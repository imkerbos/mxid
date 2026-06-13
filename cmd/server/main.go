package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/apitoken"
	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/domain/approle"
	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/consent"
	"github.com/imkerbos/mxid/internal/domain/dashboard"
	"github.com/imkerbos/mxid/internal/domain/externalidp"
	_ "github.com/imkerbos/mxid/internal/domain/externalidp/providers" // register provider factories
	"github.com/imkerbos/mxid/internal/domain/group"
	"github.com/imkerbos/mxid/internal/domain/org"
	"github.com/imkerbos/mxid/internal/domain/permission"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/domain/tenant"
	"github.com/imkerbos/mxid/internal/domain/user"
	publicpkg "github.com/imkerbos/mxid/internal/gateway/console/public"
	"github.com/imkerbos/mxid/internal/gateway/console/settings"
	"github.com/imkerbos/mxid/internal/gateway/portal"
	"github.com/imkerbos/mxid/internal/middleware"
	"github.com/imkerbos/mxid/internal/protocol/cas"
	"github.com/imkerbos/mxid/internal/protocol/oidc"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/internal/protocol/saml"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/geoip"
	"github.com/imkerbos/mxid/pkg/mailer"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/sms"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/imkerbos/mxid/pkg/urlswap"
)

func main() {
	configPath := flag.String("config", "configs", "path to config directory")
	flag.Parse()

	a, err := bootstrap.NewApp(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// Public portal group MUST be created before registerModules so the
	// password-reset / magic-link / sms-otp routes wired inside it have a
	// non-nil group to mount on.
	publicPortalGroup = a.Router.Group("/api/v1/portal-public")

	registerModules(a)

	// Public metadata endpoint — both portal and console SPAs fetch this
	// before login to learn the canonical issuer / portal / console URLs.
	bootstrap.RegisterSystemInfo(a.Router, &a.Config.Server, "")
	publicpkg.Register(a.Router, settingService, a.Config.Tenant.DefaultID)

	// File upload (app icons) + static serve. Storage dir lives outside
	// the binary so it survives rebuilds; defaults to ./data/uploads.
	if err := bootstrap.RegisterUpload(a.Router, a.ConsoleGroup, a.IDGen, "data/uploads"); err != nil {
		a.Logger.Fatal("register upload", zap.Error(err))
	}

	if err := a.Run(); err != nil {
		a.Logger.Fatal("application error", zap.Error(err))
	}
}

// settingService + mailerSvc are wired in registerModules and held here so
// the portal email-verify handler (which lives in main.go via bootstrap)
// can reuse the same instance instead of constructing a second mailer.
var (
	settingService    *setting.Service
	mailerSvc         *mailer.Mailer
	publicPortalGroup *gin.RouterGroup
)

func registerModules(a *bootstrap.App) {
	// 0a. Catch-all audit middleware. Installed on the console + portal GROUPS
	// at the very top of registerModules — before any route is registered on
	// them — so it sits in their handler chain. (Router-level .Use here would
	// NOT work: the groups were created in NewApp and already snapshotted the
	// engine's middleware slice, so a later engine.Use doesn't reach them.)
	// The recorder resolves lazily — the audit service is constructed further
	// down — so this closure is a no-op during the bootstrap window and the
	// real recorder from then on. Runs after AuthMiddleware (added later in the
	// same group chain) so the actor is already stamped into the request ctx.
	var auditRecorder func(*gin.Context)
	auditCatchAll := func(c *gin.Context) {
		c.Next()
		if auditRecorder != nil {
			auditRecorder(c)
		}
	}
	a.ConsoleGroup.Use(auditCatchAll)
	a.PortalGroup.Use(auditCatchAll)

	// 0. Settings module — runtime tunable config (SMTP, password policy,
	// branding, etc). Initialized first so other modules can read defaults.
	settingRepo := setting.NewRepositoryWithIDGen(a.DB, a.IDGen)
	settingService = setting.NewService(settingRepo, a.MasterKey)
	settingService.SetEventBus(a.EventBus)
	mailerSvc = mailer.New(settingService)

	// Build the handler now; its ROUTES are mounted later (after AuthMiddleware
	// + authz are on the console group) so settings endpoints aren't reachable
	// unauthenticated. The service above is constructed early because other
	// modules read config defaults from it during bootstrap.
	settingsHandler := settings.NewHandler(settingService, mailerSvc, a.Config.Tenant.DefaultID)

	// 1. Session manager
	sessionMgr := session.NewManager(
		a.Redis,
		a.Config.Session.IdleTimeout,
		a.Config.Session.AbsoluteTimeout,
	)
	// Runtime session policy — admin can change idle / absolute via settings
	// UI. Default tenant scope (auth runs pre-tenant-resolve). Zero values
	// in DB fall back to the YAML-driven static config.
	sessionMgr.SetPolicyProvider(func(ctx context.Context) (time.Duration, time.Duration) {
		pol, err := settingService.SecurityPolicy(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return 0, 0
		}
		return time.Duration(pol.Session.IdleMinutes) * time.Minute,
			time.Duration(pol.Session.AbsoluteHours) * time.Hour
	})

	// 2. User module (needed by authn adapter and protocol resolvers)
	userModule := user.Register(a)

	// 3. Authentication module — bridge user repo via adapters
	authQuerier := authn.BuildAuthQuerier(func(ctx context.Context, tenantID int64, username string) (*authn.UserAuth, error) {
		u, err := userModule.Repo.GetByUsername(ctx, tenantID, username)
		if err != nil {
			return nil, err
		}
		displayName := ""
		if u.DisplayName != nil {
			displayName = *u.DisplayName
		}
		return &authn.UserAuth{
			ID:                u.ID,
			Username:          u.Username,
			DisplayName:       displayName,
			PasswordHash:      u.PasswordHash,
			Status:            int(u.Status),
			PasswordChangedAt: u.PasswordChangedAt,
		}, nil
	})

	userQuerier := authn.BuildUserQuerier(
		func(ctx context.Context, id int64) (*authn.UserInfo, error) {
			u, err := userModule.Repo.GetByID(ctx, id)
			if err != nil {
				return nil, err
			}
			displayName := ""
			if u.DisplayName != nil {
				displayName = *u.DisplayName
			}
			return &authn.UserInfo{
				ID:          u.ID,
				Username:    u.Username,
				DisplayName: displayName,
				Status:      int(u.Status),
			}, nil
		},
		func(ctx context.Context, id int64, ip string) error {
			return userModule.Repo.UpdateLastLogin(ctx, id, ip)
		},
		func(ctx context.Context, id int64, status int) error {
			return userModule.Repo.UpdateStatus(ctx, id, status)
		},
	)

	mfaVerifier := newUserMFAVerifierAdapter(userModule)
	authnModule := authn.Register(a, sessionMgr, authQuerier, userQuerier, mfaVerifier)
	authnModule.Engine.SetLoginRecorder(newUserLoginRecorderAdapter(userModule, a.Logger))

	// Brute-force limiter for the password login path (per-IP + per-user).
	// Replaces the old permanent mxid_user.status auto-lock with an
	// auto-expiring Redis lock; admin LockUser stays the only permanent lock.
	// Window/lockout mirror the YAML login defaults; MaxAttempts uses the
	// configured threshold (fallback 5). Fail-closed: a Redis outage on this
	// high-value path conservatively blocks rather than admitting unlimited
	// guesses.
	loginMaxAttempts := a.Config.Security.Login.MaxFailedAttempts
	if loginMaxAttempts <= 0 {
		loginMaxAttempts = 5
	}
	loginLockout := a.Config.Security.Login.LockoutDuration
	if loginLockout <= 0 {
		loginLockout = 15 * time.Minute
	}
	if loginLimiter, err := ratelimit.New(a.Redis, ratelimit.Config{
		Purpose:     "login",
		MaxAttempts: loginMaxAttempts,
		Window:      loginLockout,
		Lockout:     loginLockout,
	}); err != nil {
		a.Logger.Error("login rate limiter init failed: " + err.Error())
	} else {
		authnModule.Engine.SetLoginLimiter(loginLimiter)
	}

	// Live security policy — read setting DB on every check (cached by
	// setting.Service itself) so admins can tighten without a restart.
	// YAML LoginConfig remains the fallback when DB rows are absent.
	userModule.Service.SetPasswordPolicyProvider(func(ctx context.Context, tenantID int64) user.PasswordPolicy {
		pol, err := settingService.SecurityPolicy(ctx, tenantID)
		if err != nil {
			pol = setting.DefaultSecurityPolicy()
		}
		return user.PasswordPolicy{
			MinLength:        pol.Password.MinLength,
			RequireUppercase: pol.Password.RequireUppercase,
			RequireLowercase: pol.Password.RequireLowercase,
			RequireNumber:    pol.Password.RequireNumber,
			RequireSpecial:   pol.Password.RequireSpecial,
			HistoryCount:     pol.Password.HistoryCount,
		}
	})
	authnModule.Engine.SetLoginPolicyProvider(func(ctx context.Context, tenantID int64) (int, time.Duration) {
		pol, err := settingService.SecurityPolicy(ctx, tenantID)
		if err != nil {
			pol = setting.DefaultSecurityPolicy()
		}
		return pol.Login.MaxFailedAttempts, time.Duration(pol.Login.LockoutMinutes) * time.Minute
	})
	// CaptchaAfterFailures: captcha is demanded only once the client IP has
	// crossed this many login failures. Returning 0 keeps captcha mandatory
	// on every attempt (the stricter pre-existing behaviour).
	authnModule.Handler.SetCaptchaThresholdProvider(func(ctx context.Context, tenantID int64) int {
		pol, err := settingService.SecurityPolicy(ctx, tenantID)
		if err != nil {
			return 0
		}
		return pol.Login.CaptchaAfterFailures
	})
	// License quota — block user creation when MaxUsers is set and the
	// global user count already meets the cap. Zero MaxUsers = unlimited
	// (OSS / no license).
	userModule.Service.SetLicenseQuotaCheck(func(ctx context.Context, tenantID int64) error {
		// The global license + cross-tenant user count are deliberately
		// platform-wide, not scoped to the creating tenant. Run them under an
		// explicit cross-tenant escape so the isolation plugin does not narrow
		// the count to the current tenant.
		ctx = tenantscope.WithCrossTenant(ctx)
		lic, err := settingService.License(ctx, a.Config.Tenant.DefaultID)
		if err != nil || lic.MaxUsers <= 0 {
			return nil
		}
		n, err := userModule.Repo.CountAll(ctx)
		if err != nil {
			return nil
		}
		if n >= int64(lic.MaxUsers) {
			return user.ErrLicenseQuotaExceeded
		}
		return nil
	})

	// Welcome email — soft-fail subscriber on user.created. Logs on send
	// failures (missing SMTP, missing email, template error) but never
	// blocks creation; mail is a courtesy, not a flow requirement.
	a.EventBus.Subscribe(event.UserCreated, func(ctx context.Context, evt event.Event) {
		p, ok := evt.Payload.(map[string]any)
		if !ok {
			return
		}
		email, _ := p["email"].(string)
		if email == "" {
			return
		}
		tid, _ := p["tenant_id"].(int64)
		username, _ := p["username"].(string)
		displayName, _ := p["display_name"].(string)
		if displayName == "" {
			displayName = username
		}
		if err := mailerSvc.SendWelcomeEmail(ctx, tid, email, displayName, username, a.Config.Server.PortalURL); err != nil {
			a.Logger.Warn("welcome email send failed",
				zap.String("username", username),
				zap.String("email", email),
				zap.Error(err))
		}
	})

	// Remember-me cookie TTL — admin can change via security/session policy.
	authnModule.Handler.SetRememberMeProvider(func(ctx context.Context) int {
		pol, err := settingService.SecurityPolicy(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return 0
		}
		return pol.Session.RememberMeHours * 3600
	})

	// Login-method gate: reject auth_type when admin disabled it in
	// settings. Default tenant scoping because auth runs pre-tenant-
	// resolution; cross-tenant gating could come later.
	authnModule.Handler.SetLoginMethodGate(func(ctx context.Context, authType string) error {
		m, err := settingService.LoginMethods(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return nil
		}
		switch authType {
		case "local", "password", "":
			if !m.Password {
				return fmt.Errorf("密码登录已被管理员关闭")
			}
		case "sms":
			if !m.SMSOTP {
				return fmt.Errorf("短信登录已被管理员关闭")
			}
		case "magic_link":
			if !m.EmailMagicLink {
				return fmt.Errorf("邮件链接登录已被管理员关闭")
			}
		}
		return nil
	})

	// 4. Apply auth middleware to protected route groups
	a.ConsoleGroup.Use(authn.AuthMiddleware(authnModule.SessionMgr, session.NamespaceConsole))
	a.PortalGroup.Use(authn.AuthMiddleware(authnModule.SessionMgr, session.NamespacePortal))

	// 4a. Mandatory-MFA-enrollment gate — a session flagged at login (policy
	// requires MFA but the user has none) is blocked from everything except the
	// MFA enrollment surface until they bind a factor. Runs right after auth so
	// it gates before any business handler. Self-heals once a factor exists.
	enrollGate := func(ns string) gin.HandlerFunc {
		return authn.EnrollGateMiddleware(authn.EnrollGateDeps{
			Namespace:  ns,
			SessionMgr: authnModule.SessionMgr,
			HasMFA:     authnModule.Engine.HasMFA,
		})
	}
	a.ConsoleGroup.Use(enrollGate(session.NamespaceConsole))
	a.PortalGroup.Use(enrollGate(session.NamespacePortal))

	// 4b. Install authz middleware lazily — domain modules below need to be
	// constructed first to build the binding provider, but they also need
	// the middleware to be in place when they register their routes. The
	// lazy provider closes over `authzSvc` so it resolves nil during this
	// short bootstrap window and the real service from then on.
	var authzSvc *authz.Service
	authz.InstallLazy(a.ConsoleGroup, func() *authz.Service { return authzSvc })

	// 4c. Now that auth + authz middleware are on the console group, mount
	// the deferred user routes. (user.Register was called above to build
	// the module so other constructors could depend on the user service.)
	// TenantContext sits between authz and routes so super_admin can scope
	// requests to a target tenant via X-Tenant-ID header (used by the
	// console tenant switcher).
	a.ConsoleGroup.Use(middleware.TenantContext())

	// 4d. Step-up MFA on high-risk console operations (deletes + security-
	// critical writes). Deps resolve lazily at request time: authzSvc is
	// assigned later in this bootstrap but always before the first request.
	// No dedicated Audit hook — every high-risk operation already emits its
	// own domain audit event downstream, so the action is on the trail
	// regardless of whether step-up was enforced or skipped (MFA off).
	a.ConsoleGroup.Use(authn.StepUpMiddleware(authn.StepUpDeps{
		SessionMgr: sessionMgr,
		Policy: func(ctx context.Context, tenantID int64) (string, time.Duration) {
			p, err := settingService.MFAPolicy(ctx, tenantID)
			if err != nil {
				p = setting.DefaultMFAPolicy()
			}
			return p.Mode, time.Duration(p.StepUpWindowSeconds) * time.Second
		},
		IsAdmin: func(ctx context.Context, tenantID, userID int64) bool {
			if authzSvc == nil {
				return false
			}
			perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
			return err == nil && len(perms) > 0
		},
		HasMFA: func(ctx context.Context, userID int64) (bool, error) {
			return authnModule.Engine.HasMFA(ctx, userID)
		},
	}))

	// 4e. Deny-by-default authz gateway. Mounted AFTER AuthMiddleware + authz
	// install (so c has user/tenant + the Service) and BEFORE the module routes,
	// so it sits on every console request post-routing. A matched console route
	// that declared NO permission (no authz.Require / authz.Protect) and is not
	// on the public allow-list is flagged — root-cause guard against shipping an
	// open admin endpoint. Runs in AUDIT-ONLY mode for now: it LOGS the offending
	// route loudly but does not 403, so the portal-on-console self-service
	// surfaces (profile / security / MFA / uploads / SSE) that carry their own
	// session auth keep working until they are AllowPublic'd and the app/idp/
	// audit modules grow their authz.Require + authz.Protect (sibling backfill).
	// Flip AuditOnly to false once those land and the allow-list is vetted to
	// turn on hard deny-by-default (hard mode needs mount-time authz.Protect for
	// gated routes, since the gateway runs before each route's own Require).
	a.ConsoleGroup.Use(authz.Gateway(authz.GatewayConfig{
		Logger:    a.Logger,
		AuditOnly: true,
	}))

	userModule.RegisterRoutes(a)

	// Settings routes mounted here — AFTER AuthMiddleware + authz + tenant
	// context are on the console group — so config read/write requires an
	// authenticated admin session (previously these registered pre-auth and
	// were reachable unauthenticated).
	settingsHandler.Register(a.ConsoleGroup)

	// 5. Register domain modules
	orgModule := org.Register(a)
	groupModule := group.Register(a)
	permissionModule := permission.Register(a)
	tenantModule := tenant.Register(a)
	// Tenant license quota — blocks Create when MaxTenants set and reached.
	tenantModule.Service.SetLicenseQuotaCheck(func(ctx context.Context) error {
		lic, err := settingService.License(ctx, a.Config.Tenant.DefaultID)
		if err != nil || lic.MaxTenants <= 0 {
			return nil
		}
		ts, err := tenantModule.Repo.List(ctx)
		if err != nil {
			return nil
		}
		if len(ts) >= lic.MaxTenants {
			return tenant.ErrLicenseQuotaExceeded
		}
		return nil
	})
	// Portal login can resolve `tenant` field on the request to a tenant_id
	// via the tenant service. Hooked up here so authn's NewHandler stays
	// decoupled from the tenant domain package.
	authnModule.Handler.SetTenantResolver(func(ctx context.Context, code string) int64 {
		t, err := tenantModule.Service.GetByCode(ctx, code)
		if err != nil || t == nil {
			return 0
		}
		return t.ID
	})
	appModule := app.Register(a)
	// Protocol defaults — admin can set per-protocol TTL + subject strategy
	// via settings UI; applied at Create time when the request leaves the
	// corresponding field blank. Zero values fall through to per-protocol
	// Defaults() funcs at read time.
	appModule.Service.SetProtocolDefaultsProvider(func(ctx context.Context, tenantID int64) app.ProtocolDefaults {
		pd, err := settingService.ProtocolDefaults(ctx, tenantID)
		if err != nil {
			return app.ProtocolDefaults{}
		}
		return app.ProtocolDefaults{
			OIDCAccessTokenTTL:  pd.OIDCAccessTokenTTLSeconds,
			OIDCRefreshTokenTTL: pd.OIDCRefreshTokenTTLSeconds,
			OIDCIDTokenTTL:      pd.OIDCIDTokenTTLSeconds,
			SAMLAssertionTTL:    pd.SAMLAssertionTTLSeconds,
			CASTicketTTL:        pd.CASTicketTTLSeconds,
			DefaultSubject:      pd.DefaultSubjectStrategy,
		}
	})
	auditModule := audit.Register(a)
	// Activate the catch-all recorder installed at the top of registerModules.
	auditRecorder = auditModule.Service.RecordAPIRequest
	// Denormalize ActorName for events that publish only a user_id (app.launched
	// fires from the portal middleware context, which carries no username).
	// Best-effort: a lookup miss leaves ActorName blank but keeps actor_id.
	auditModule.Service.SetUserNameResolver(func(ctx context.Context, userID int64) string {
		u, err := userModule.Repo.GetByID(ctx, userID)
		if err != nil || u == nil {
			return ""
		}
		return u.Username
	})
	// GeoIP enrichment for audit IP. Operator points config geoip.database_path
	// at a MaxMind GeoLite2-City .mmdb; missing / unreadable falls back to
	// noop so a missing licence doesn't break audit. Shared with conditional
	// access (geo-based risk signals) below.
	var geoResolver geoip.Resolver = geoip.NoopResolver{}
	if path := a.Config.GeoIP.DatabasePath; path != "" {
		if geo, err := geoip.NewMaxMindResolver(path); err == nil {
			geoResolver = geoip.PrivateAwareResolver{Inner: geo}
			auditModule.Service.SetGeoResolver(geoResolver)
			a.Logger.Info("geoip resolver loaded", zap.String("path", path))
		} else {
			a.Logger.Warn("geoip mmdb unavailable, audit geo columns will be empty",
				zap.String("path", path), zap.Error(err))
		}
	}

	// Conditional access (adaptive auth): assess login risk + recognise devices.
	// Disabled by default (policy.Enabled=false) so this is inert until an admin
	// turns it on; device history still accumulates so the new-device signal is
	// meaningful once enabled.
	authnModule.Handler.SetConditionalAccess(buildConditionalAccess(a, settingService, geoResolver))
	// Retention cron — purges audit_log rows older than AuditPolicy.RetentionDays
	// every 6h. Hourly would be wasteful (no SLA on prompt deletion); daily
	// risks losing the window during long maintenance. Default-tenant scope
	// because retention is a global compliance knob.
	go runAuditRetention(a, settingService, auditModule.Repo)

	// Console dashboard aggregation. Live-session gauge sums the interactive
	// (console + portal) namespaces; the protocol SSO session is internal and
	// not a "logged-in user" in the dashboard sense.
	dashboardModule := dashboard.Register(a)
	dashboardModule.Service.SetSessionCounter(func(ctx context.Context) int64 {
		var total int64
		for _, ns := range []string{session.NamespaceConsole, session.NamespacePortal} {
			if n, err := sessionMgr.CountActive(ctx, ns); err == nil {
				total += n
			}
		}
		return total
	})

	consentModule := consent.Register(a)

	// Cross-domain: effective roles for a user resolve THREE binding paths
	// — direct user, group-inherited, and org-inherited (incl. ancestors).
	// Adapters keep permission/ decoupled from group/ and org/.
	permission.RegisterEffectiveRolesRoute(
		a,
		permissionModule.Service,
		newPermissionGroupLookupAdapter(groupModule),
		newPermissionOrgLookupAdapter(orgModule),
		a.Config.Tenant.DefaultID,
	)

	// Now that all module pieces exist, build and publish the authz service
	// for the lazy installer above. The binding provider is wrapped by the
	// two-level cache so per-request Check() pays L1 (sync.Map) at best,
	// L2 (Redis) on cold pods, and the underlying DB join only on a true
	// miss. Cache invalidation is driven by event-bus subscriptions on
	// permission / role mutations (see wireAuthzCacheInvalidation below);
	// callers don't need to remember to call Invalidate manually.
	authzBindings := authz.NewCachedBindingProvider(
		context.Background(),
		newAuthzBindingProvider(a, permissionModule, groupModule, orgModule),
		a.Redis,
		authz.CacheOptions{},
	)
	authzSvc = authz.NewService(authzBindings, newAuthzOrgAncestry(orgModule))
	wireAuthzCacheInvalidation(a, authzBindings)

	// Hybrid engine: Casbin owns role→permission (+ super_admin wildcard) and
	// is the authority consulted by Service.Check; the Go scopeCovers above
	// still decides instance scope (org ltree / group / kind). The enforcer
	// persists to the existing casbin_rule table and rebuilds from the
	// mxid_role* source of truth on boot + on role/permission/super-admin
	// mutations (wireCasbinSync). On any setup error we fall back to the
	// legacy in-binding permission set so a Casbin hiccup never takes down
	// the whole authz path.
	if casbinEngine, err := authz.NewCasbinEngineWithDB(a.DB); err != nil {
		a.Logger.Error("casbin engine init failed, using legacy perm matching: " + err.Error())
	} else {
		loader := newCasbinPolicyLoader(a)
		if err := casbinEngine.Sync(context.Background(), loader); err != nil {
			a.Logger.Error("casbin initial sync failed, using legacy perm matching: " + err.Error())
		} else {
			authzSvc = authzSvc.WithCasbin(casbinEngine)
			wireCasbinSync(a, casbinEngine, loader)
		}
	}
	// Tell authn /auth/me whether the caller is admin-eligible so the
	// portal SPA renders the "switch to console" entry only for users
	// who can actually use it.
	authnModule.Handler.SetAdminChecker(func(ctx context.Context, tenantID, userID int64) bool {
		perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
		if err != nil {
			return false
		}
		return len(perms) > 0
	})

	// Mandatory-MFA-enrollment gate predicate: does the MFA policy require THIS
	// user to hold a factor? all → everyone; admin_only → console-eligible
	// admins; off → no one. Pairs with the EnrollGate middleware mounted above.
	authnModule.Handler.SetMFAEnrollGate(func(ctx context.Context, tenantID, userID int64) bool {
		pol, err := settingService.MFAPolicy(ctx, tenantID)
		if err != nil {
			return false
		}
		switch pol.Mode {
		case setting.MFAModeAll:
			return true
		case setting.MFAModeAdminOnly:
			if authzSvc == nil {
				return false
			}
			perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
			return err == nil && len(perms) > 0
		default:
			return false
		}
	})

	// External IdP module — admin CRUD lives under console (authz-gated);
	// the OAuth redirect dance lives on the public portal namespace because
	// the user is not yet authenticated when they click "Login with Lark".
	extIDPModule := externalidp.Register(a)
	extIDPModule.MountAdminRoutes(a, a.Config.Tenant.DefaultID)
	extIDPModule.MountPortalRoutes(a, externalidp.PortalHandlerOpts{
		Resolver:   newUserExternalResolver(userModule),
		SessionMgr: sessionMgr,
		TenantID:   a.Config.Tenant.DefaultID,
		// Multi-tenant: portal accepts ?tenant=<code> on the login + IdP-list
		// endpoints. Resolves to the matching tenant_id; falls back to default.
		TenantByCode: func(ctx context.Context, code string) int64 {
			t, err := tenantModule.Service.GetByCode(ctx, code)
			if err != nil || t == nil {
				return 0
			}
			return t.ID
		},
		// BaseURL: where Lark/Teams should redirect back to (the BACKEND
		// callback endpoint). PortalURL: where the FRONTEND is served.
		// Configurable via env MXID_EXTERNAL_BACKEND_URL / MXID_EXTERNAL_PORTAL_URL,
		// falls back to dev defaults.
		BaseURL:      envDefault("MXID_EXTERNAL_BACKEND_URL", fmt.Sprintf("http://localhost:%d", a.Config.Server.Port)),
		PortalURL:    envDefault("MXID_EXTERNAL_PORTAL_URL", "http://localhost:3500"),
		LoginURL:     "/",
		FailureURL:   "/login?err=external",
		CookieName:   authn.CookiePortal,
		CookieDomain: a.Config.Session.CookieDomain,
		CookieSecure: a.Config.Session.CookieSecure,
	})
	// Console external-IdP login. Same OAuth dance, but gated: only an
	// admin-authorized, non-built-in user gets a console session. The gate is
	// the security boundary — a Lark user with no console permission, or the
	// break-glass `admin`, is bounced back to the login page with a reason.
	extIDPModule.MountConsolePublicRoutes(a, externalidp.ConsoleHandlerOpts{
		Resolver:   newUserExternalResolver(userModule),
		SessionMgr: sessionMgr,
		TenantID:   a.Config.Tenant.DefaultID,
		Gate: func(ctx context.Context, tenantID, userID int64) error {
			// Break-glass guard: seeded built-in accounts never federate.
			if u, err := userModule.Repo.GetByID(ctx, userID); err == nil && u != nil && u.IsBuiltin {
				return fmt.Errorf("builtin account must use local login")
			}
			// Admin authorization: must hold at least one console permission.
			perms, err := authzSvc.PermissionsForUser(ctx, tenantID, userID)
			if err != nil || len(perms) == 0 {
				return fmt.Errorf("not authorized for console")
			}
			return nil
		},
		TenantByCode: func(ctx context.Context, code string) int64 {
			t, err := tenantModule.Service.GetByCode(ctx, code)
			if err != nil || t == nil {
				return 0
			}
			return t.ID
		},
		BaseURL:      envDefault("MXID_EXTERNAL_BACKEND_URL", fmt.Sprintf("http://localhost:%d", a.Config.Server.Port)),
		ConsoleURL:   envDefault("MXID_EXTERNAL_CONSOLE_URL", "http://localhost:3500"),
		LoginURL:     "/admin/",
		FailureURL:   "/admin/login?err=external",
		CookieName:   authn.CookieConsole,
		CookieDomain: a.Config.Session.CookieDomain,
		CookieSecure: a.Config.Session.CookieSecure,
	})

	// 6. Protocol resolvers — bridge app/user repos to protocol layer.
	//
	// Issuer is the externally-reachable base URL (nginx :3500 in dev) where
	// SPs collect /protocol/saml/.../metadata and similar. NOT the backend
	// listen port. ExternalURLs setting (admin-configurable) wins at runtime
	// via urlswap.Provider; this is the fallback when no override exists.
	//
	// Dev default: nginx fronts the API on :3500. Override via env if a
	// different host/port is canonical.
	issuer := "http://localhost:3500"
	if v := os.Getenv("MXID_ISSUER"); v != "" {
		issuer = v
	}

	appResolver := buildAppResolver(appModule, a.Config.Tenant.DefaultID, a.MasterKey, a.Logger)
	idResolver := buildIdentityResolver(userModule, a)
	sessResolver := resolver.NewSessionResolver(a.Redis)
	tenantResolver := newDBTenantResolver(a)

	// 6.5. App access policy module (authorization layer).
	//
	// Wired before protocol modules because OIDC /authorize calls into
	// the AccessChecker adapter to gate code issuance.
	accessRepo := appaccess.NewRepository(a.DB)
	accessSvc := appaccess.NewService(accessRepo, a.IDGen, a.EventBus)
	appaccess.SetMatcher(newAccessMatcher(a))
	accessHandler := appaccess.NewHandler(accessSvc, newAccessSubjectResolver(a), a.Config.Tenant.DefaultID)
	accessHandler.Register(a.ConsoleGroup)
	accessAdapter := &oidcAccessAdapter{svc: accessSvc}

	// 6.6. App role module — IdP-side role mapping. SPs receive
	// `app_roles` claim instead of writing JMESPath against `groups`.
	approleRepo := approle.NewRepository(a.DB)
	approleSvc := approle.NewService(approleRepo, a.IDGen, a.EventBus)
	approleHandler := approle.NewHandler(approleSvc, newAccessSubjectResolver(a), newAppLabelResolver(a), a.Config.Tenant.DefaultID)
	approleHandler.Register(a.ConsoleGroup)
	appRolesAdapter := &oidcAppRolesAdapter{svc: approleSvc}

	// 6.7. Referenced-entity tenant validators (Phase 2.6).
	//
	// Association handlers accept a referenced entity id (user/group/org/role/
	// app) from the request body and link it to a tenant-owned parent. The
	// parent is tenant-guarded, but the referent was not validated — letting an
	// admin plant a FOREIGN-tenant entity into their own org/group/role/app and
	// inherit its scoped access. Inject tenant-scoped existence checks (backed
	// by each referent's GetByID; the tenantscope plugin appends tenant_id=?, so
	// a cross-tenant id 404s) so every site rejects a foreign referent.
	userValidator := validateUserInTenant(userModule)
	groupValidator := validateGroupInTenant(groupModule)
	orgValidator := validateOrgInTenant(orgModule)
	roleValidator := validateRoleInTenant(permissionModule)
	appValidator := validateAppInTenant(appModule)
	appGroupValidator := validateAppGroupInTenant(appModule)

	orgModule.Service.SetUserValidator(userValidator)
	groupModule.Service.SetUserValidator(userValidator)
	permissionModule.Service.SetRefValidators(permission.RefValidators{
		User:  userValidator,
		Group: groupValidator,
		Org:   orgValidator,
	})
	appModule.Service.SetAccessSubjectValidators(app.AccessSubjectValidators{
		User:  userValidator,
		Group: groupValidator,
		Org:   orgValidator,
		Role:  roleValidator,
	})
	accessSvc.SetRefValidators(appaccess.RefValidators{
		App:      appValidator,
		AppGroup: appGroupValidator,
		User:     userValidator,
		Group:    groupValidator,
		Org:      orgValidator,
		Role:     roleValidator,
	})
	approleSvc.SetRefValidators(approle.RefValidators{
		App:      appValidator,
		AppGroup: appGroupValidator,
		User:     userValidator,
		Group:    groupValidator,
		Org:      orgValidator,
		Role:     roleValidator,
	})

	// 7. Register protocol modules
	//
	// OIDC engine select: MXID_OIDC_ENGINE=zitadel mounts the zitadel/oidc-based
	// provider (internal/protocol/oidcop); anything else keeps the hand-rolled
	// engine. Both occupy /protocol/oidc, so exactly one is mounted.
	var oidcModule *oidc.Module
	if os.Getenv("MXID_OIDC_ENGINE") == "zitadel" {
		if err := wireOIDCOP(a, issuer, appResolver, idResolver, sessResolver, consentModule.Service); err != nil {
			a.Logger.Fatal("wire zitadel OIDC engine: " + err.Error())
		}
	} else {
		oidcModule = oidc.Register(a.ProtocolGroup, issuer, a.Config.Server.PortalURL, a.Redis, appResolver, idResolver, sessResolver, tenantResolver, consentModule.Service, accessAdapter, appRolesAdapter, sessionMgr, a.EventBus)
	}
	samlModule := saml.Register(a.ProtocolGroup, issuer, a.Config.Server.PortalURL, appResolver, idResolver, sessResolver, tenantResolver)
	casModule := cas.Register(a.ProtocolGroup, issuer, a.Config.Server.PortalURL, a.Redis, appResolver, idResolver, sessResolver, tenantResolver)

	// Runtime URL provider — admin-configurable external URLs. Empty
	// fields fall through to the bootstrap config (i.e. the static
	// defaults compiled in). The provider is invoked per-request so admin
	// changes take effect immediately (settings layer caches for 60s).
	urlProvider := func(ctx context.Context) urlswap.URLs {
		v, err := settingService.ExternalURLs(ctx, a.Config.Tenant.DefaultID)
		if err != nil {
			return urlswap.URLs{}
		}
		return urlswap.URLs{Issuer: v.IssuerURL, Portal: v.PortalURL, Console: v.ConsoleURL}
	}
	if oidcModule != nil { // nil when the zitadel engine is active
		oidcModule.Handler.SetURLProvider(urlProvider)
	}
	samlModule.Handler.SetURLProvider(urlProvider)
	casModule.Handler.SetURLProvider(urlProvider)

	// 8. Register portal gateway (user-facing API)
	portalUserQ := buildPortalUserQuerier(userModule)
	portalAppQ := buildPortalAppQuerier(a, appModule, issuer, accessSvc)
	portalSessQ := buildPortalSessionQuerier(sessionMgr)
	portalMFAQ := buildPortalMFAQuerier(userModule)
	portalIDQ := buildPortalIdentityQuerier(userModule)
	portalConsentQ := buildPortalConsentQuerier(appModule)
	portal.Register(a.PortalGroup, portalUserQ, portalAppQ, portalSessQ, portalMFAQ, portalIDQ,
		consentModule.Service, portalConsentQ, a.Config.Tenant.DefaultID,
		a.Redis, a.Logger, a.Config.Server.PortalURL, mailerSvc, a.EventBus)

	// Public portal password-reset routes (no auth). Lives on
	// /api/v1/portal-public so the AuthMiddleware on /api/v1/portal can't
	// reject the pre-login caller.
	tenantByCodeResolver := func(ctx context.Context, code string) int64 {
		t, err := tenantModule.Service.GetByCode(ctx, code)
		if err != nil || t == nil {
			return 0
		}
		return t.ID
	}
	// Brute-force / abuse limiters for the public pre-auth flows. Each is
	// fail-closed (a Redis outage blocks rather than admits) and keyed by the
	// flow's natural identifier (phone / email). buildLimiter logs + returns
	// nil on a config error so wiring degrades gracefully.
	smsLoginLimiter := buildLimiter(a, ratelimit.Config{
		Purpose: "sms_login", MaxAttempts: 5,
		Window: 5 * time.Minute, Lockout: 15 * time.Minute,
	})
	magicLinkLimiter := buildLimiter(a, ratelimit.Config{
		Purpose: "magic_link_send", MaxAttempts: 5,
		Window: 15 * time.Minute, Lockout: 15 * time.Minute,
	})
	pwdResetLimiter := buildLimiter(a, ratelimit.Config{
		Purpose: "pwd_reset_send", MaxAttempts: 5,
		Window: 15 * time.Minute, Lockout: 15 * time.Minute,
	})

	// devFallback gates the dev_link/dev_code response + log exposure on
	// non-release mode. In release we never leak the out-of-band reset/magic
	// /OTP secret even when the mail/SMS provider is misconfigured or fails.
	devFallback := !a.Config.Server.IsRelease()
	pwdResetHandler := portal.NewPasswordResetHandler(
		a.Redis, portalUserQ, a.Logger, a.Config.Server.PortalURL,
		mailerSvc, a.Config.Tenant.DefaultID, tenantByCodeResolver,
	)
	pwdResetHandler.SetLimiter(pwdResetLimiter)
	pwdResetHandler.SetDevFallback(devFallback)
	portal.RegisterPasswordResetRoutes(publicPortalGroup, pwdResetHandler)
	// Public SMS OTP routes. Gated by LoginMethods.SMSOTP. Provider config
	// (Aliyun / Tencent / Twilio) is per-tenant via setting.SMS; secret is
	// AES-decrypted by setting.Service.SMS at send time.
	smsSvc := sms.New(settingService)
	portal.RegisterSMSOTPRoutes(publicPortalGroup, portal.NewSMSOTPHandler(portal.SMSOTPHandlerOpts{
		Redis:      a.Redis,
		Users:      portalUserQ,
		Logger:     a.Logger,
		SMS:        smsSvc,
		SessionMgr: sessionMgr,
		Enabled: func(ctx context.Context) bool {
			m, err := settingService.LoginMethods(ctx, a.Config.Tenant.DefaultID)
			if err != nil {
				return false
			}
			return m.SMSOTP
		},
		DefaultTID:   a.Config.Tenant.DefaultID,
		TenantByCode: tenantByCodeResolver,
		CookieDomain: a.Config.Session.CookieDomain,
		CookieSecure: a.Config.Session.CookieSecure,
		DevFallback:  devFallback,
		Limiter:      smsLoginLimiter,
	}))

	// Public magic-link routes. Gated by LoginMethods.EmailMagicLink — the
	// send endpoint returns 403 when admin disabled it. Callback always
	// honors live tokens regardless of the flag.
	portal.RegisterMagicLinkRoutes(publicPortalGroup, portal.NewMagicLinkHandler(portal.MagicLinkHandlerOpts{
		Redis:      a.Redis,
		Users:      portalUserQ,
		Logger:     a.Logger,
		PortalURL:  a.Config.Server.PortalURL,
		Mailer:     mailerSvc,
		SessionMgr: sessionMgr,
		Enabled: func(ctx context.Context) bool {
			m, err := settingService.LoginMethods(ctx, a.Config.Tenant.DefaultID)
			if err != nil {
				return false
			}
			return m.EmailMagicLink
		},
		DefaultTID:   a.Config.Tenant.DefaultID,
		TenantByCode: tenantByCodeResolver,
		CookieDomain: a.Config.Session.CookieDomain,
		CookieSecure: a.Config.Session.CookieSecure,
		DevFallback:  devFallback,
		Limiter:      magicLinkLimiter,
	}))

	// 9. Mount /security on BOTH portal and console groups so the rate
	//    limiter (shared via authnModule.Engine.MFARateLimiter()) is
	//    threaded into both copies of the handler. portal.Register no
	//    longer mounts /security itself — keeping the wiring in one place
	//    avoids a "two sources of truth" footgun when the handler signature
	//    grows.
	mfaLimiter := authnModule.Engine.MFARateLimiter()
	// Wire admin "clear MFA lockout" → reset Redis counters via the same
	// limiter the login + enroll paths use.
	userModule.Service.SetMFALockoutClearer(func(ctx context.Context, uid int64) {
		mfaLimiter.Reset(ctx, uid, "")
	})
	// TOTP single-use (replay) protection. Every VerifyTOTP call site (login
	// MFA challenge, step-up, enroll/re-verify) routes through
	// user.Service.VerifyTOTP, so this one wiring covers them all.
	userModule.Service.SetTOTPReplayGuard(a.Redis)
	portalLoginHistoryQ := buildPortalLoginHistoryQuerier(auditModule)
	apiTokenModule := apitoken.Register(a)
	portalAPITokenQ := buildPortalAPITokenQuerier(apiTokenModule.Service)
	tenantDefault := a.Config.Tenant.DefaultID
	portal.RegisterSecurityRoutes(a.PortalGroup, portal.NewSecurityHandler(
		session.NamespacePortal, portalUserQ, portalSessQ, portalMFAQ, portalIDQ,
		portalLoginHistoryQ, portalAPITokenQ, tenantDefault, mfaLimiter, a.EventBus,
	))
	portal.RegisterSecurityRoutes(a.ConsoleGroup, portal.NewSecurityHandler(
		session.NamespaceConsole, portalUserQ, portalSessQ, portalMFAQ, portalIDQ,
		portalLoginHistoryQ, portalAPITokenQ, tenantDefault, mfaLimiter, a.EventBus,
	))

	// Mount the bearer middleware on /openapi/v1 so every script-facing
	// route requires a valid PAT. Per-route scope guards (apitoken.RequireScope)
	// can be added when concrete routes ship.
	a.OpenAPIGroup.Use(apitoken.AuthMiddleware(apiTokenModule.Service))

	// Minimal /me probe — proves the bearer middleware fires AND lets
	// scripts discover their own identity/scopes before making real
	// calls. Lives here (not in a domain package) because it's pure
	// glue: read context, echo back.
	a.OpenAPIGroup.GET("/me", func(c *gin.Context) {
		userID, _ := c.Get(apitoken.CtxUserID)
		tenantID, _ := c.Get(apitoken.CtxTenantID)
		scopes, _ := c.Get(apitoken.CtxScopes)
		c.JSON(200, gin.H{
			"code": 0, "message": "ok",
			"data": gin.H{"user_id": userID, "tenant_id": tenantID, "scopes": scopes},
		})
	})

	// 10. Mirror /profile + /profile/email/* onto console so admin users
	//     can edit their own display name / avatar / email and trigger
	//     email verification from the console SPA. Verification click-back
	//     redirect still points at the portal URL — admins clicking the
	//     dev_link land in the portal, which is fine (single account state).
	portal.RegisterProfileRoutes(a.ConsoleGroup, portal.NewProfileHandler(portalUserQ, a.EventBus))
	emailVerifyHandler := portal.NewEmailVerifyHandler(
		a.Redis, portalUserQ, a.Logger, a.Config.Server.PortalURL, mailerSvc, tenantDefault,
	)
	emailVerifyHandler.SetDevFallback(devFallback)
	portal.RegisterEmailVerifyRoutes(a.ConsoleGroup, emailVerifyHandler)
}

// buildPortalConsentQuerier surfaces a thin app-domain projection to the
// consent handler so it can render app metadata on the consent screen
// without coupling the portal handler to the app domain types.
func buildPortalConsentQuerier(appModule *app.Module) portal.ConsentQuerier {
	return portalConsentQuerierAdapter{appModule: appModule}
}

type portalConsentQuerierAdapter struct {
	appModule *app.Module
}

func (a portalConsentQuerierAdapter) GetApp(ctx context.Context, appID int64) (*portal.ConsentApp, error) {
	ap, err := a.appModule.Repo.GetByID(ctx, appID)
	if err != nil {
		return nil, err
	}
	out := &portal.ConsentApp{ID: ap.ID, Name: ap.Name}
	if ap.Description != nil {
		out.Description = *ap.Description
	}
	if ap.Icon != nil {
		out.LogoURL = *ap.Icon
	}
	if ap.HomeURL != nil {
		out.HomeURL = *ap.HomeURL
	}
	return out, nil
}

// buildLimiter constructs a fail-closed ratelimit.Limiter from the app's
// shared redis client, logging and returning nil on a config error so the
// caller's wiring degrades to "no limiter" rather than panicking at boot.
func buildLimiter(a *bootstrap.App, cfg ratelimit.Config) *ratelimit.Limiter {
	l, err := ratelimit.New(a.Redis, cfg)
	if err != nil {
		a.Logger.Error("rate limiter init failed for " + cfg.Purpose + ": " + err.Error())
		return nil
	}
	return l
}

// buildAppResolver creates an AppResolver that bridges the app domain repo.
//
// Cert adapters decrypt the at-rest private_key via the bootstrap master key
// before handing it to the protocol layer. The protocol layer never sees
// the ciphertext.
func buildAppResolver(appModule *app.Module, _ int64, masterKey *crypto.MasterKey, logger *zap.Logger) resolver.AppResolver {
	convertCert := func(c *app.AppCert) (*resolver.CertConfig, error) {
		cfg := &resolver.CertConfig{
			ID:         c.ID,
			AppID:      c.AppID,
			CertType:   c.CertType,
			Algorithm:  c.Algorithm,
			PublicKey:  c.PublicKey,
			PrivateKey: c.PrivateKey,
			NotBefore:  &c.NotBefore,
			ExpiresAt:  c.ExpiresAt,
			Status:     c.Status,
		}
		if c.KID != nil {
			cfg.KID = *c.KID
		}
		if c.Encrypted {
			plain, err := masterKey.Decrypt(c.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt app cert %d: %w", c.ID, err)
			}
			cfg.PrivateKey = string(plain)
		}
		return cfg, nil
	}

	return resolver.NewAppResolver(
		// GetByCode
		func(ctx context.Context, tenantID int64, code string) (*resolver.AppConfig, error) {
			// The protocol layer is the cross-tenant entry point: it discovers
			// the tenant FROM the app (by globally-unique client_id / code /
			// app_id), so app/cert resolution runs as an explicit cross-tenant
			// read. The resolved AppConfig carries its TenantID, which the
			// protocol handlers then use to scope downstream user/consent reads.
			ctx = tenantscope.WithCrossTenant(ctx)
			a, err := appModule.Repo.GetByCode(ctx, tenantID, code)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetByID
		func(ctx context.Context, appID int64) (*resolver.AppConfig, error) {
			ctx = tenantscope.WithCrossTenant(ctx)
			a, err := appModule.Repo.GetByID(ctx, appID)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetByClientID
		func(ctx context.Context, clientID string) (*resolver.AppConfig, error) {
			ctx = tenantscope.WithCrossTenant(ctx)
			a, err := appModule.Repo.GetByClientID(ctx, clientID)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetCert — return the currently-active cert of the requested type.
		func(ctx context.Context, appID int64, certType string) (*resolver.CertConfig, error) {
			ctx = tenantscope.WithCrossTenant(ctx)
			certs, err := appModule.Repo.ListCertsByApp(ctx, appID)
			if err != nil {
				return nil, err
			}
			for _, c := range certs {
				if c.CertType == certType && c.Status == app.CertStatusActive {
					return convertCert(c)
				}
			}
			return nil, fmt.Errorf("no active cert of type %s for app %d", certType, appID)
		},
		// ListCerts — used by per-app cert listing; returns active + rotating.
		func(ctx context.Context, appID int64) ([]*resolver.CertConfig, error) {
			certs, err := appModule.Repo.ListCertsByApp(ctx, appID)
			if err != nil {
				return nil, err
			}
			result := make([]*resolver.CertConfig, 0, len(certs))
			for _, c := range certs {
				if c.Status != app.CertStatusActive && c.Status != app.CertStatusRotating {
					continue
				}
				converted, err := convertCert(c)
				if err != nil {
					return nil, err
				}
				result = append(result, converted)
			}
			return result, nil
		},
		// ListAllActiveSigningCerts — IdP-level JWKS aggregation.
		func(ctx context.Context) ([]*resolver.CertConfig, error) {
			certs, err := appModule.KeyService.ListActiveSigningCerts(ctx)
			if err != nil {
				return nil, err
			}
			result := make([]*resolver.CertConfig, 0, len(certs))
			for _, c := range certs {
				converted, err := convertCert(c)
				if err != nil {
					// One unusable cert (e.g. orphaned by a KEK rotation) must
					// not take down the whole IdP JWKS for every other app.
					// Skip it — a key we can't load is a key we can't sign with,
					// so it has no business being advertised — and log loudly so
					// the operator knows to rotate that app's signing key.
					logger.Warn("skipping unusable signing cert in JWKS aggregation",
						zap.Int64("cert_id", c.ID), zap.Int64("app_id", c.AppID), zap.Error(err))
					continue
				}
				result = append(result, converted)
			}
			return result, nil
		},
		// MintSigningCert — lazy bootstrap for SAML/CAS apps created before
		// auto-mint existed. Called from the SAML metadata handler when no
		// signing cert is present, so /metadata never returns 500.
		func(ctx context.Context, appID int64) (*resolver.CertConfig, error) {
			cert, err := appModule.KeyService.RotateForApp(ctx, appID)
			if err != nil {
				return nil, err
			}
			return convertCert(cert)
		},
	)
}

func appToConfig(a *app.App) *resolver.AppConfig {
	// Shared apps (Scope=2) have NULL tenant_id; the protocol resolver
	// needs a concrete int — fall back to 0 to signal "no tenant scope".
	var tid int64
	if a.TenantID != nil {
		tid = *a.TenantID
	}
	cfg := &resolver.AppConfig{
		ID:              a.ID,
		TenantID:        tid,
		Scope:           a.Scope,
		SubjectStrategy: a.SubjectStrategy,
		Name:            a.Name,
		Code:            a.Code,
		Protocol:        a.Protocol,
		ClientType:      a.ClientType,
		Status:          a.Status,
		FirstParty:      a.IsFirstParty,
		RequireConsent:  a.RequireConsent,
		ProtocolConfig:  a.ProtocolConfig,
		RedirectURIs:    resolver.ParseRedirectURIs(a.RedirectURIs),
		AccessPolicy:    a.AccessPolicy,
	}
	if a.ClientID != nil {
		cfg.ClientID = *a.ClientID
	}
	if a.ClientSecret != nil {
		cfg.ClientSecret = *a.ClientSecret
	}
	if a.HomeURL != nil {
		cfg.HomeURL = *a.HomeURL
	}
	if a.LoginURL != nil {
		cfg.LoginURL = *a.LoginURL
	}
	if a.LogoutURL != nil {
		cfg.LogoutURL = *a.LogoutURL
	}
	return cfg
}

// certToConfig is kept for tests / future migrations that need a no-decrypt
// projection. Production code paths go through buildAppResolver's adapter
// which decrypts at-rest ciphertext.
var _ = (*resolver.CertConfig)(nil)

// buildIdentityResolver bridges the user domain repo to the protocol
// IdentityResolver so claim mappers can read user attributes without
// importing the user package.
func buildIdentityResolver(userModule *user.Module, a *bootstrap.App) resolver.IdentityResolver {
	return resolver.NewIdentityResolver(
		func(ctx context.Context, userID int64) (*resolver.IdentityInfo, error) {
			u, err := userModule.Repo.GetByID(ctx, userID)
			if err != nil {
				return nil, err
			}
			info := &resolver.IdentityInfo{
				ID:            u.ID,
				TenantID:      u.TenantID,
				Username:      u.Username,
				Status:        u.Status,
				UpdatedAt:     u.UpdatedAt.Unix(),
				EmailVerified: u.EmailVerified,
			}
			if u.DisplayName != nil {
				info.DisplayName = *u.DisplayName
			}
			if u.Email != nil {
				info.Email = *u.Email
			}
			if u.Phone != nil {
				info.Phone = *u.Phone
			}
			if u.Avatar != nil {
				info.Avatar = *u.Avatar
			}

			// OIDC `groups` claim emits machine-readable group codes (e.g.
			// "grafana-admins"), not display names. Downstream apps
			// (Grafana role_attribute_path, Harbor admin group, etc) all
			// match on identifiers, not localized names.
			var codes []string
			_ = a.DB.WithContext(ctx).
				Table("mxid_user_group_member m").
				Joins("INNER JOIN mxid_user_group g ON g.id = m.group_id AND g.deleted_at IS NULL").
				Where("m.user_id = ?", userID).
				Pluck("g.code", &codes).Error
			if codes == nil {
				codes = []string{}
			}
			info.Groups = codes

			// Pull user_detail (sparse) for claim-mapper access.
			var detail struct {
				Gender     *int    `gorm:"column:gender"`
				Birthday   *string `gorm:"column:birthday"`
				Address    *string `gorm:"column:address"`
				EmployeeNo *string `gorm:"column:employee_no"`
				JobTitle   *string `gorm:"column:job_title"`
				Department *string `gorm:"column:department"`
			}
			if err := a.DB.WithContext(ctx).
				Table("mxid_user_detail").
				Where("user_id = ?", userID).
				Take(&detail).Error; err == nil {
				m := map[string]any{}
				if detail.Gender != nil {
					m["gender"] = *detail.Gender
				}
				if detail.Birthday != nil {
					m["birthday"] = *detail.Birthday
				}
				if detail.Address != nil {
					m["address"] = *detail.Address
				}
				if detail.EmployeeNo != nil {
					m["employee_no"] = *detail.EmployeeNo
				}
				if detail.JobTitle != nil {
					m["job_title"] = *detail.JobTitle
				}
				if detail.Department != nil {
					m["department"] = *detail.Department
				}
				info.Detail = m
			}

			return info, nil
		},
	)
}

// OIDC adapters moved to adapters_oidc.go.

// runAuditRetention runs forever, purging audit_log rows older than
// AuditPolicy.RetentionDays every 6 hours. A zero RetentionDays disables
// the purge for that tick (admin can opt out by setting 0). Cron lives in
// the binary process, not a separate worker, so OSS deployments don't have
// to wire a job scheduler.
func runAuditRetention(a *bootstrap.App, ss *setting.Service, repo audit.Repository) {
	const tickEvery = 6 * time.Hour
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	// One immediate tick so a freshly-restarted server reflects the policy
	// without a 6h delay; later ticks ride the ticker.
	for {
		// Background cron with no request context. The purge is a deliberate
		// GLOBAL cross-tenant delete of old rows, so it must use an EXPLICIT
		// system escape — otherwise the tenant-isolation plugin fails closed
		// (or, worse, scopes the purge to tenant 0). SystemContext is the
		// sanctioned, auditable bypass for background jobs.
		ctx := tenantscope.SystemContext()
		pol, err := ss.AuditPolicy(ctx, a.Config.Tenant.DefaultID)
		if err == nil && pol.RetentionDays > 0 {
			cutoff := time.Now().AddDate(0, 0, -pol.RetentionDays)
			deleted, err := repo.PurgeOlderThan(ctx, cutoff)
			if err != nil {
				a.Logger.Warn("audit retention purge failed",
					zap.Int("retention_days", pol.RetentionDays),
					zap.Error(err))
			} else if deleted > 0 {
				a.Logger.Info("audit retention purge",
					zap.Int("retention_days", pol.RetentionDays),
					zap.Int64("deleted", deleted))
			}
		}
		<-ticker.C
	}
}
