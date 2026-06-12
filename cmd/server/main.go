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
	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/domain/approle"
	"github.com/imkerbos/mxid/internal/domain/apitoken"
	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/internal/domain/consent"
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
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/sms"
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
	// 0. Settings module — runtime tunable config (SMTP, password policy,
	// branding, etc). Initialized first so other modules can read defaults.
	settingRepo := setting.NewRepositoryWithIDGen(a.DB, a.IDGen)
	settingService = setting.NewService(settingRepo, a.MasterKey)
	mailerSvc = mailer.New(settingService)

	settingsHandler := settings.NewHandler(settingService, mailerSvc, a.Config.Tenant.DefaultID)
	settingsHandler.Register(a.ConsoleGroup)

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
	// License quota — block user creation when MaxUsers is set and the
	// global user count already meets the cap. Zero MaxUsers = unlimited
	// (OSS / no license).
	userModule.Service.SetLicenseQuotaCheck(func(ctx context.Context, tenantID int64) error {
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

	userModule.RegisterRoutes(a)

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

	// 7. Register protocol modules
	oidcModule := oidc.Register(a.ProtocolGroup, issuer, a.Config.Server.PortalURL, a.Redis, appResolver, idResolver, sessResolver, tenantResolver, consentModule.Service, accessAdapter, appRolesAdapter, sessionMgr, a.EventBus)
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
	oidcModule.Handler.SetURLProvider(urlProvider)
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
	portal.RegisterPasswordResetRoutes(publicPortalGroup, portal.NewPasswordResetHandler(
		a.Redis, portalUserQ, a.Logger, a.Config.Server.PortalURL,
		mailerSvc, a.Config.Tenant.DefaultID, tenantByCodeResolver,
	))
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
	portalLoginHistoryQ := buildPortalLoginHistoryQuerier(auditModule)
	apiTokenModule := apitoken.Register(a)
	portalAPITokenQ := buildPortalAPITokenQuerier(apiTokenModule.Service)
	tenantDefault := a.Config.Tenant.DefaultID
	portal.RegisterSecurityRoutes(a.PortalGroup, portal.NewSecurityHandler(
		session.NamespacePortal, portalUserQ, portalSessQ, portalMFAQ, portalIDQ,
		portalLoginHistoryQ, portalAPITokenQ, tenantDefault, mfaLimiter,
	))
	portal.RegisterSecurityRoutes(a.ConsoleGroup, portal.NewSecurityHandler(
		session.NamespaceConsole, portalUserQ, portalSessQ, portalMFAQ, portalIDQ,
		portalLoginHistoryQ, portalAPITokenQ, tenantDefault, mfaLimiter,
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
	portal.RegisterProfileRoutes(a.ConsoleGroup, portal.NewProfileHandler(portalUserQ))
	portal.RegisterEmailVerifyRoutes(a.ConsoleGroup, portal.NewEmailVerifyHandler(
		a.Redis, portalUserQ, a.Logger, a.Config.Server.PortalURL, mailerSvc, tenantDefault,
	))
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
			a, err := appModule.Repo.GetByCode(ctx, tenantID, code)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetByID
		func(ctx context.Context, appID int64) (*resolver.AppConfig, error) {
			a, err := appModule.Repo.GetByID(ctx, appID)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetByClientID
		func(ctx context.Context, clientID string) (*resolver.AppConfig, error) {
			a, err := appModule.Repo.GetByClientID(ctx, clientID)
			if err != nil {
				return nil, err
			}
			return appToConfig(a), nil
		},
		// GetCert — return the currently-active cert of the requested type.
		func(ctx context.Context, appID int64, certType string) (*resolver.CertConfig, error) {
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
		ProtocolConfig: a.ProtocolConfig,
		RedirectURIs:   resolver.ParseRedirectURIs(a.RedirectURIs),
		AccessPolicy:   a.AccessPolicy,
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
		ctx := context.Background()
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
