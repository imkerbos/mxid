package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/mfaerr"
	"github.com/imkerbos/mxid/pkg/ratelimit"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/redis/go-redis/v9"
)

// Engine errors.
var (
	ErrUnknownProvider = errors.New("unknown authentication provider")
	ErrAuthFailed      = errors.New("authentication failed")
	ErrAccountLocked   = errors.New("account is locked")
	ErrAccountDisabled = errors.New("account is disabled")
	ErrMFARequired     = errors.New("mfa verification required")
	ErrSessionNotFound = errors.New("session not found")
	// ErrMFACodeReused — the TOTP code was CORRECT but already spent this
	// window (the single-use replay guard). Kept apart from ErrMFAVerifyFailed
	// because the advice is the opposite: not "check your code" but "wait for
	// the next one". Flattening the two told a user who had typed the right
	// digits that they were wrong, in the most common sequence there is —
	// two prompts landing inside the same 30-second step.
	// Aliased to pkg/mfaerr so the EE module — a separate Go module that
	// cannot import internal/... — can branch on it across the seam.
	ErrMFACodeReused = mfaerr.ErrCodeReused
)

// LoginResponse is returned by Engine.Login.
//
// Two terminal shapes:
//
//   - Success: SessionID populated; MFARequired=false. Caller sets session cookie.
//   - MFA required: SessionID empty; MFARequired=true with Challenge + MFAMethods.
//     Caller surfaces Challenge to the client; client POSTs it back to
//     /auth/mfa/verify together with the TOTP code.
type LoginResponse struct {
	UserID      int64    `json:"user_id,string,omitempty"`
	TenantID    int64    `json:"tenant_id,string,omitempty"`
	Username    string   `json:"username,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	MFARequired bool     `json:"mfa_required,omitempty"`
	MFAMethods  []string `json:"mfa_methods,omitempty"`
	Challenge   string   `json:"challenge,omitempty"`
}

// LoginRecorder persists each login attempt for audit. Implementations live
// outside the authn package (user domain) — the engine only depends on the
// minimal interface to avoid an import cycle.
type LoginRecorder interface {
	RecordAttempt(ctx context.Context, attempt LoginAttempt)
}

// LoginAttempt is the data engine hands to LoginRecorder for each attempt.
type LoginAttempt struct {
	TenantID  int64
	UserID    int64
	Username  string
	Success   bool
	Stage     string // "password" or "mfa"
	AuthType  string
	Reason    string
	IP        string
	UserAgent string
}

// Engine orchestrates authentication across multiple providers.
// LoginPolicyProvider returns the runtime login policy for a tenant
// (max_failed_attempts / lockout_duration). Implementations read from
// setting.Service and fall back to the YAML LoginConfig defaults; nil
// keeps the engine on YAML.
type LoginPolicyProvider func(ctx context.Context, tenantID int64) (maxFailedAttempts int, lockoutDuration time.Duration)

type Engine struct {
	providers      map[string]Provider
	sessionMgr     *session.Manager
	eventBus       *event.Bus
	idGen          *snowflake.Generator
	loginConfig    *bootstrap.LoginConfig
	loginPolicy    LoginPolicyProvider
	userRepo       UserQuerier
	rdb            *redis.Client
	mfaVerifier    MFAVerifier
	mfaRateLimiter *MFARateLimiter
	loginRecorder  LoginRecorder
	loginLimiter   *ratelimit.Limiter
	// dummyCompare burns the constant-cost password compare on a branch that
	// refuses a login without evaluating the credential. nil = the real
	// burnDummyCompare; tests swap it to observe that the refusal keeps paying
	// the enumeration equalizer.
	dummyCompare func(password string)
	// accountThrottleArmed, when set (tests), is notified of every refusal
	// window the account dimension arms, so the escalation can be asserted
	// without reading Redis keys.
	accountThrottleArmed func(userID int64, window time.Duration)
}

// SetLoginLimiter wires the brute-force limiter that backs the password
// login path (per-IP + per-user). When nil the engine falls back to its
// legacy per-user Redis counter (tests without redis). Called by main.go.
func (e *Engine) SetLoginLimiter(l *ratelimit.Limiter) { e.loginLimiter = l }

// SetLoginPolicyProvider injects the runtime policy lookup. Called by
// main.go after the setting service is built; nil keeps engine on YAML.
func (e *Engine) SetLoginPolicyProvider(p LoginPolicyProvider) { e.loginPolicy = p }

// NewEngine creates a new authentication engine.
func NewEngine(
	sessionMgr *session.Manager,
	eventBus *event.Bus,
	idGen *snowflake.Generator,
	loginConfig *bootstrap.LoginConfig,
	userRepo UserQuerier,
	rdb *redis.Client,
) *Engine {
	return &Engine{
		providers:      make(map[string]Provider),
		sessionMgr:     sessionMgr,
		eventBus:       eventBus,
		idGen:          idGen,
		loginConfig:    loginConfig,
		userRepo:       userRepo,
		rdb:            rdb,
		mfaRateLimiter: NewMFARateLimiter(rdb),
	}
}

// MFARateLimiter exposes the shared rate limiter so handlers (security
// enrollment verify) can plug into the same counters the login challenge
// uses. Nil when redis isn't wired (tests).
func (e *Engine) MFARateLimiter() *MFARateLimiter { return e.mfaRateLimiter }

// SetMFAVerifier wires the MFA factor verifier. Called by Register after the
// user module is built; nil mfaVerifier disables the second-factor step
// (used in tests; production must always set it).
func (e *Engine) SetMFAVerifier(v MFAVerifier) {
	e.mfaVerifier = v
}

// SetLoginRecorder wires the audit recorder. Nil disables login-record
// persistence (event bus events still fire). Called by Register after the
// user module is built.
func (e *Engine) SetLoginRecorder(r LoginRecorder) {
	e.loginRecorder = r
}

// RegisterProvider adds an authentication provider.
func (e *Engine) RegisterProvider(p Provider) {
	e.providers[p.Type()] = p
}

// Login performs authentication and creates a session on success.
func (e *Engine) Login(ctx context.Context, req *AuthRequest, namespace string) (*LoginResponse, error) {
	provider, ok := e.providers[req.AuthType]
	if !ok {
		return nil, ErrUnknownProvider
	}

	// Login runs BEFORE any session exists, so the request context carries no
	// tenant scope. The target tenant is resolved explicitly upstream
	// (effectiveTenant -> req.TenantID); pin it onto the context so the gorm
	// tenant-isolation plugin can scope the user lookups (GetByUsername/Email/
	// Phone) instead of failing closed.
	if req.TenantID > 0 {
		ctx = tenantscope.WithTenant(ctx, req.TenantID)
	}

	// Brute-force gate (pre-auth, IP-scoped): if this client IP has already
	// tripped the limiter, reject before spending a bcrypt compare. This is the
	// only dimension that hard-locks; see accountIdentifier for why the account
	// dimension must not.
	if err := e.checkLoginLock(ctx, req.ClientIP); err != nil {
		return nil, err
	}

	// Per-account throttle (pre-auth): an account that just failed repeatedly
	// has its next attempts REFUSED for a short, growing window.
	if userID, username, throttled := e.accountThrottled(ctx, req); throttled {
		// The IP dimension must keep counting — it is what stops a scan that
		// never gets as far as a compare. The ACCOUNT tally is deliberately not
		// bumped: nothing was evaluated, so a refused attempt is no evidence
		// about the credential, and counting it would let an attacker ratchet a
		// victim's own window straight to the cap by hammering it.
		e.trackFailure(ctx, 0, req)
		e.publishLoginEvent(ctx, &AuthResult{
			UserID:   userID,
			Username: username,
			Status:   AuthFailed,
		}, req, false)
		return nil, ErrAuthFailed
	}

	result, err := provider.Authenticate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	switch result.Status {
	case AuthFailed:
		// Tracked even when the username matched nobody (UserID 0). Skipping
		// those skipped the per-IP dimension too, so a scripted scan over
		// invented usernames never incremented anything: no captcha was ever
		// demanded and no IP lock ever tripped, however many attempts it made.
		// The per-user dimension is simply absent for an unknown account —
		// trackFailure skips it when there is no userID.
		e.trackFailure(ctx, result.UserID, req)
		e.publishLoginEvent(ctx, result, req, false)
		// Arms from the tally trackFailure just wrote, so it must run after it.
		e.armAccountThrottle(ctx, result.UserID)
		return nil, ErrAuthFailed

	case AuthLocked:
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrAccountLocked

	case AuthDisabled:
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrAccountDisabled

	case AuthMFARequired:
		// Return without creating a session; MFA step needed
		return nil, ErrMFARequired

	case AuthSuccess:
		// Clear failure count (both per-user and per-IP) so a legitimate
		// login relieves the brute-force budget it may have nudged via typos.
		if result.UserID > 0 {
			e.clearFailureCountIP(ctx, result.UserID, req.ClientIP)
		}

		// MFA gate: if the user has a verified TOTP factor, password-success
		// does NOT yet grant a session. Mint a single-use challenge token,
		// hand it to the client, and wait for /auth/mfa/verify to call
		// VerifyMFAChallenge with the second factor.
		if e.mfaVerifier != nil {
			hasTOTP, mfaErr := e.mfaVerifier.HasVerifiedTOTP(ctx, result.UserID)
			if mfaErr != nil {
				return nil, fmt.Errorf("check mfa: %w", mfaErr)
			}
			if hasTOTP {
				challenge, err := e.issueMFAChallenge(ctx, &mfaChallengePayload{
					UserID:      result.UserID,
					TenantID:    req.TenantID,
					Username:    result.Username,
					DisplayName: result.DisplayName,
					AuthType:    req.AuthType,
					Namespace:   namespace,
					ClientIP:    req.ClientIP,
					UserAgent:   req.UserAgent,
				})
				if err != nil {
					return nil, fmt.Errorf("issue mfa challenge: %w", err)
				}
				return &LoginResponse{
					UserID:      result.UserID,
					TenantID:    req.TenantID,
					Username:    result.Username,
					DisplayName: result.DisplayName,
					MFARequired: true,
					MFAMethods:  []string{"totp"},
					Challenge:   challenge,
				}, nil
			}
		}

		return e.completeLogin(ctx, namespace, req, result, "password")

	default:
		return nil, ErrAuthFailed
	}
}

// completeLogin issues the session that ends a successful login (first factor
// only, or both factors when MFA is in play). Updates last-login, mints the
// session row, publishes the success event, and returns the response shape
// the handler expects.
//
// stage records which step finalised the login ("password" for no-MFA users,
// "mfa" for users who went through the challenge).
func (e *Engine) completeLogin(ctx context.Context, namespace string, req *AuthRequest, result *AuthResult, stage string) (*LoginResponse, error) {
	_ = e.userRepo.UpdateLastLogin(ctx, result.UserID, req.ClientIP)

	sess, err := e.sessionMgr.Create(
		ctx, namespace,
		result.UserID, req.TenantID,
		req.ClientIP, req.UserAgent, req.AuthType,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// A login that cleared an MFA challenge is a fresh proof of possession — start
	// the step-up (sudo) window at login. Without this, MFA-at-login never counted
	// as a step-up, so portal actions that require a fresh step-up (the form-fill
	// extension's pair / credential reveal) were effectively unsatisfiable: the
	// only other portal path that sets it is TOTP re-enrollment, and /auth/step-up
	// refreshes the console session, not the portal one.
	if stage == "mfa" {
		_ = e.sessionMgr.MarkMFAVerified(ctx, namespace, sess.ID)
	}

	e.publishLoginEvent(ctx, result, req, true, stage)

	return &LoginResponse{
		UserID:      result.UserID,
		TenantID:    req.TenantID,
		Username:    result.Username,
		DisplayName: result.DisplayName,
		SessionID:   sess.ID,
	}, nil
}

// VerifyMFAChallenge validates the TOTP code submitted against a pending
// challenge token. On success, consumes the token (single-use) and creates
// the namespace session that Login deferred. The returned LoginResponse
// mirrors the password-only success shape so the caller can finalize cookies
// the same way.
//
// The original client IP/User-Agent captured at password verification are
// reused for the session record, NOT the values from the MFA-verify request.
// Rationale: the session belongs to the device that started the login —
// consistent audit signals matter more here than the transport endpoint.
// HasMFA reports whether the user has a verified MFA factor enrolled. Used by
// step-up enforcement to choose between challenging an enrolled user and
// demanding enrollment from one who has none.
func (e *Engine) HasMFA(ctx context.Context, userID int64) (bool, error) {
	if e.mfaVerifier == nil {
		return false, nil
	}
	return e.mfaVerifier.HasVerifiedTOTP(ctx, userID)
}

// VerifyStepUp validates a TOTP (or backup) code for an ALREADY-authenticated
// user performing a high-risk operation. Unlike VerifyMFAChallenge there is no
// login challenge token — the caller already holds a live session. Rate-limited
// per user+IP. Returns nil on success, ErrMFAVerifyFailed on a bad code,
// ErrMFANotConfigured / ErrMFARateLimited otherwise.
func (e *Engine) VerifyStepUp(ctx context.Context, userID int64, clientIP, code string) error {
	if e.mfaVerifier == nil {
		return ErrMFANotConfigured
	}
	if err := e.mfaRateLimiter.Check(ctx, userID, clientIP); err != nil {
		return err
	}
	verifyErr := e.mfaVerifier.VerifyTOTP(ctx, userID, code)
	if verifyErr != nil && looksLikeBackupCode(code) {
		if err := e.mfaVerifier.ConsumeBackupCode(ctx, userID, code); err == nil {
			verifyErr = nil
		}
	}
	if verifyErr != nil {
		// A spent-but-correct code keeps its own sentinel: the caller renders
		// "wait for the next code", not "that code is wrong". It also does NOT
		// count toward the lockout — replaying a code means the digits were
		// already right, so it is evidence of a double-submit (the portal
		// auto-submits on the sixth digit), not of guessing. An attacker who
		// can replay a valid code did not brute-force it.
		if errors.Is(verifyErr, ErrMFACodeReused) {
			return ErrMFACodeReused
		}
		e.mfaRateLimiter.RecordFailure(ctx, userID, clientIP)
		return ErrMFAVerifyFailed
	}
	e.mfaRateLimiter.Reset(ctx, userID, clientIP)
	return nil
}

// Step-up methods. A step-up ("sudo") challenge proves the person at the
// keyboard is still the account owner. Which proof we can demand depends on
// what the account actually has:
//
//   - StepUpMethodTOTP     — a verified second factor is enrolled. Always
//     preferred: it is the strongest proof and the only one that satisfies an
//     MFA-enforcing policy.
//   - StepUpMethodPassword — no factor enrolled, but the account has a usable
//     local password. Re-typing it is a real barrier to someone who only stole
//     the session cookie (the GitHub / Google "sudo mode" model), and without
//     it every step-up-gated feature is permanently unreachable for accounts
//     that never enrolled MFA.
//   - StepUpMethodNone     — neither (an external-IdP account with no password
//     and no factor). The caller must enroll a factor first; there is nothing
//     to challenge against.
const (
	StepUpMethodTOTP     = "totp"
	StepUpMethodPassword = "password"
	StepUpMethodNone     = "none"
)

// StepUpMethod reports which proof this user can be challenged for. See the
// StepUpMethod* constants for the ordering rationale.
func (e *Engine) StepUpMethod(ctx context.Context, tenantID, userID int64) string {
	if ok, err := e.HasMFA(ctx, userID); err == nil && ok {
		return StepUpMethodTOTP
	}
	if e.HasLocalPassword(ctx, tenantID, userID) {
		return StepUpMethodPassword
	}
	return StepUpMethodNone
}

// HasLocalPassword reports whether the user can authenticate with a local
// password. False for external-IdP (e.g. Lark) accounts that never set one,
// and whenever the local provider isn't wired.
func (e *Engine) HasLocalPassword(ctx context.Context, tenantID, userID int64) bool {
	lp, ok := e.providers[LocalProviderType].(*LocalProvider)
	if !ok {
		return false
	}
	u, err := e.userRepo.GetByID(ctx, userID)
	if err != nil || u == nil {
		return false
	}
	ua, err := lp.userRepo.GetByUsername(ctx, tenantID, u.Username)
	if err != nil || ua == nil {
		return false
	}
	return crypto.HasUsablePassword(ua.PasswordHash)
}

// VerifyPasswordStepUp re-checks the password of an ALREADY-authenticated user
// as a step-up proof. Only for accounts with no MFA factor — an enrolled user
// must answer the TOTP challenge, or the second factor would be downgradeable
// to something the phisher already has.
//
// Rate-limited on the same per-user+IP counters as the MFA step-up, so this
// path is not a lower-friction password oracle than the login form.
func (e *Engine) VerifyPasswordStepUp(ctx context.Context, tenantID, userID int64, clientIP, password string) error {
	lp, ok := e.providers[LocalProviderType].(*LocalProvider)
	if !ok {
		return ErrUnknownProvider
	}
	u, err := e.userRepo.GetByID(ctx, userID)
	if err != nil || u == nil {
		return ErrAuthFailed
	}
	if err := e.mfaRateLimiter.Check(ctx, userID, clientIP); err != nil {
		return err
	}
	result, err := lp.Authenticate(ctx, &AuthRequest{
		TenantID:    tenantID,
		AuthType:    LocalProviderType,
		Credentials: map[string]string{"username": u.Username, "password": password},
		ClientIP:    clientIP,
		UserAgent:   "",
	})
	// Only an outright success counts. AuthDisabled /
	// AuthLocked all mean the account may not act right now, and AuthFailed is a
	// wrong password — none of them is a valid proof of presence.
	if err != nil || result == nil || result.Status != AuthSuccess || result.UserID != userID {
		e.mfaRateLimiter.RecordFailure(ctx, userID, clientIP)
		return ErrAuthFailed
	}
	e.mfaRateLimiter.Reset(ctx, userID, clientIP)
	return nil
}

func (e *Engine) VerifyMFAChallenge(ctx context.Context, challenge, code string) (*LoginResponse, error) {
	if e.mfaVerifier == nil {
		return nil, ErrMFANotConfigured
	}
	payload, err := e.consumeMFAChallenge(ctx, challenge)
	if err != nil {
		return nil, err
	}

	// Second-factor verification also runs pre-session; pin the challenge's
	// tenant so downstream user/MFA repo reads are tenant-scoped.
	if payload.TenantID > 0 {
		ctx = tenantscope.WithTenant(ctx, payload.TenantID)
	}

	if err := e.mfaRateLimiter.Check(ctx, payload.UserID, payload.ClientIP); err != nil {
		return nil, err
	}

	// Accept TOTP code OR backup code. We check TOTP first because it's
	// the dominant case; only fall through to backup-code consumption when
	// the format unambiguously rules TOTP out (contains a hyphen or has
	// alpha chars). This keeps the fast path fast and avoids burning a
	// backup code on a typo'd TOTP digit.
	verifyErr := e.mfaVerifier.VerifyTOTP(ctx, payload.UserID, code)
	if verifyErr != nil && looksLikeBackupCode(code) {
		if err := e.mfaVerifier.ConsumeBackupCode(ctx, payload.UserID, code); err == nil {
			verifyErr = nil
		}
	}
	if verifyErr != nil {
		// A replayed code does not count toward the lockout — see VerifyStepUp.
		// The attempt is still audited: a failed second factor is a failed
		// second factor, whatever the reason.
		if !errors.Is(verifyErr, ErrMFACodeReused) {
			e.mfaRateLimiter.RecordFailure(ctx, payload.UserID, payload.ClientIP)
		}
		err := verifyErr
		// Token already consumed; client must restart login. We do NOT
		// fold MFA failures into the password lockout counter — the
		// password was already valid and the challenge TTL caps brute
		// force. A dedicated MFA-attempt counter is a future hardening step.
		e.eventBus.Publish(ctx, event.Event{
			Type: event.LoginFailed,
			Payload: map[string]any{
				"user_id":    payload.UserID,
				"username":   payload.Username,
				"auth_type":  payload.AuthType,
				"ip":         payload.ClientIP,
				"user_agent": payload.UserAgent,
				"tenant_id":  payload.TenantID,
				"stage":      "mfa",
				"reason":     err.Error(),
				"success":    false,
			},
		})
		if e.loginRecorder != nil {
			e.loginRecorder.RecordAttempt(ctx, LoginAttempt{
				TenantID:  payload.TenantID,
				UserID:    payload.UserID,
				Username:  payload.Username,
				Success:   false,
				Stage:     "mfa",
				AuthType:  payload.AuthType,
				Reason:    err.Error(),
				IP:        payload.ClientIP,
				UserAgent: payload.UserAgent,
			})
		}
		return nil, ErrMFAVerifyFailed
	}

	// Code accepted — wipe both per-user and per-IP fail counters so the
	// user isn't penalised for a typo earlier in the session.
	e.mfaRateLimiter.Reset(ctx, payload.UserID, payload.ClientIP)

	authReq := &AuthRequest{
		TenantID:  payload.TenantID,
		AuthType:  payload.AuthType,
		ClientIP:  payload.ClientIP,
		UserAgent: payload.UserAgent,
	}
	result := &AuthResult{
		UserID:      payload.UserID,
		Username:    payload.Username,
		DisplayName: payload.DisplayName,
		Status:      AuthSuccess,
	}
	return e.completeLogin(ctx, payload.Namespace, authReq, result, "mfa")
}

// Logout deletes a session. meta carries the request context (ip, user agent,
// tenant) so the audit row is complete — without it the logout event records
// only a user_id and the console shows blank actor / IP columns.
func (e *Engine) Logout(ctx context.Context, namespace, sessionID string, userID int64, meta LogoutMeta) error {
	if err := e.sessionMgr.Delete(ctx, namespace, sessionID); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	e.eventBus.Publish(ctx, event.Event{
		Type: event.Logout,
		Payload: map[string]any{
			"user_id":    userID,
			"session_id": sessionID,
			"tenant_id":  meta.TenantID,
			"ip":         meta.IP,
			"user_agent": meta.UserAgent,
		},
	})

	return nil
}

// LogoutMeta carries request-scoped context for the logout audit row.
type LogoutMeta struct {
	TenantID  int64
	IP        string
	UserAgent string
}

// GetSession retrieves and validates a session.
func (e *Engine) GetSession(ctx context.Context, namespace, sessionID string) (*session.Session, error) {
	sess, err := e.sessionMgr.Get(ctx, namespace, sessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	if sess == nil {
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

// GetCurrentUser returns user info for a session.
func (e *Engine) GetCurrentUser(ctx context.Context, userID int64) (*UserInfo, error) {
	return e.userRepo.GetByID(ctx, userID)
}

// failCountKey returns the legacy Redis key for tracking login failures.
// Retained for the fallback path when no loginLimiter is wired (tests).
func (e *Engine) failCountKey(userID int64) string {
	return "mxid:login_fail:" + strconv.FormatInt(userID, 10)
}

// accountIdentifier is the limiter identifier for the per-account dimension.
// Single definition so the writer (trackFailure) and the readers
// (accountThrottled, armAccountThrottle) can never drift onto different keys.
//
// This dimension is COUNTED ONLY — trackFailure records it through
// RecordFailureCount, which never writes a ":locked" key. A binary lock keyed
// on the account hands a denial of service to anyone who knows a username, and
// the limiter's lock also answers 429 with a distinct business code, i.e. an
// account-enumeration oracle. The throttle below replaces it.
func accountIdentifier(userID int64) string {
	return "u:" + strconv.FormatInt(userID, 10)
}

// ipIdentifier is the limiter identifier for the per-IP dimension — the only
// login dimension that hard-locks.
func ipIdentifier(clientIP string) string {
	return "ip:" + clientIP
}

// loginIdentifiers builds every identifier a login failure touches, for the
// reset path. Empty parts are omitted so a missing IP (test) or an unknown
// account simply narrows the scope rather than poisoning a shared key.
func loginIdentifiers(userID int64, clientIP string) []string {
	ids := make([]string, 0, 2)
	if userID > 0 {
		ids = append(ids, accountIdentifier(userID))
	}
	if clientIP != "" {
		ids = append(ids, ipIdentifier(clientIP))
	}
	return ids
}

// checkLoginLock reports whether the client IP is currently locked by the
// brute-force limiter, returning ErrAccountLocked (with the limiter's
// RateLimitError as cause, so the handler can surface Retry-After). nil
// limiter = no lock (legacy path).
//
// It takes NO userID on purpose: the account dimension must never be checked
// here. Doing so would resurrect the binary account lock — and its 429 +
// too-many-attempts code — that accountIdentifier explains away, and it would
// do it silently, because the lock key would simply start existing. With the
// parameter gone that cannot be reintroduced by passing a value.
func (e *Engine) checkLoginLock(ctx context.Context, clientIP string) error {
	if e.loginLimiter == nil || clientIP == "" {
		return nil
	}
	if err := e.loginLimiter.Check(ctx, ipIdentifier(clientIP)); err != nil {
		return fmt.Errorf("%w: %w", ErrAccountLocked, err)
	}
	return nil
}

// Per-account login throttle. The account dimension deliberately does NOT hard
// lock: a binary lock keyed on the account hands a DoS switch to anyone who
// knows a username. Instead, an account that keeps failing has its next
// attempts REFUSED for a window that grows with the tally, while a real user
// who mistyped a couple of times pays nothing at all.
//
// Why a refusal and not a delay. A delay is paid by US: it runs after the
// provider has already spent the bcrypt compare, it parks a goroutine for the
// whole wait, and an attacker that does not read the response keeps its full
// guess rate regardless. It also reopens the enumeration oracle
// burnDummyCompare exists to close, pointing the other way — slow answer =
// throttled account = this account exists. A refusal costs us one indexed
// lookup plus the equalizer compare, and costs the attacker the window.
const (
	// accountThrottleFreeFailures is how many failures cost nothing. Typos live
	// here; brute force does not.
	accountThrottleFreeFailures = 3
	accountThrottleBase         = time.Second
	// accountThrottleMax caps the window. The cap is what keeps the control a
	// throttle and not a lockout: the owner is never more than this far from
	// their next real attempt.
	accountThrottleMax = 8 * time.Second
	// accountThrottleMaxShift is where base<<n already exceeds the cap; it
	// keeps a long run of failures from shifting into overflow.
	accountThrottleMaxShift = 4
)

// accountThrottleWindow maps an account's failure tally to how long its next
// attempts are refused: 0 up to accountThrottleFreeFailures, then 1s, 2s, 4s,
// capped at 8s.
func accountThrottleWindow(failures int) time.Duration {
	over := failures - accountThrottleFreeFailures
	if over <= 0 {
		return 0
	}
	if over > accountThrottleMaxShift {
		return accountThrottleMax
	}
	if d := accountThrottleBase << uint(over-1); d < accountThrottleMax {
		return d
	}
	return accountThrottleMax
}

// accountThrottled reports whether this attempt must be refused without the
// credential ever being evaluated, together with the account it was aimed at
// (for the audit row). Only the identifier is resolved — no password work.
//
// The caller answers the ordinary ErrAuthFailed, with no RateLimitError in the
// chain: a throttled attempt is the same 401 and the same business code as a
// plain wrong password. Anything distinguishable here would be an
// account-enumeration oracle. It also never revokes sessions and never flips
// account status — an attacker-triggered control that logged the victim out
// would be self-service DoS by another name.
func (e *Engine) accountThrottled(ctx context.Context, req *AuthRequest) (int64, string, bool) {
	if e.loginLimiter == nil {
		return 0, "", false
	}
	u := e.resolveLoginAccount(ctx, req)
	if u == nil {
		return 0, "", false
	}
	if !e.loginLimiter.InCooldown(ctx, accountIdentifier(u.ID)) {
		return 0, "", false
	}
	// Break-glass exemption, checked here as well as at arming time: the seeded
	// admin must not be refused even if a key was armed while a lookup was
	// failing. A past release auto-locked it and deadlocked fresh installs
	// outright, with nobody left who could log in and repair it.
	if e.isBuiltinUser(ctx, u.ID) {
		return 0, "", false
	}
	// Flat timing: the refusal has to cost what a real compare costs, or fast
	// means "throttled" and slow means "actually checking".
	e.burnEqualizer(req.Credentials["password"])
	return u.ID, u.Username, true
}

// resolveLoginAccount maps the submitted login identifier to its account
// BEFORE the credential is evaluated. Returns nil when the identifier matches
// nobody, the credentials are incomplete, or the provider cannot resolve one
// (an external IdP — that path is covered by the per-IP dimension only).
//
// Resolving pre-auth leaks nothing here: the refusal it enables is the ordinary
// ErrAuthFailed and burns the same dummy compare, so "which usernames are
// throttled" is not readable off the response. The lookup is the provider's own
// resolveUser, so a known and an unknown identifier take the same path they
// already took on every login.
func (e *Engine) resolveLoginAccount(ctx context.Context, req *AuthRequest) *UserAuth {
	resolver, ok := e.providers[req.AuthType].(accountResolver)
	if !ok {
		return nil
	}
	identifier := req.Credentials["username"]
	if identifier == "" || req.Credentials["password"] == "" {
		return nil
	}
	u, err := resolver.ResolveAccount(ctx, req.TenantID, identifier)
	if err != nil || u == nil {
		return nil
	}
	return u
}

// armAccountThrottle opens the window during which this account's next
// attempts are refused outright. Called after the failure has been counted and
// audited; the tally it reads is the per-account counter, which is why rotating
// the source IP no longer resets the guessing budget.
func (e *Engine) armAccountThrottle(ctx context.Context, userID int64) {
	if e.loginLimiter == nil || userID <= 0 {
		return
	}
	window := accountThrottleWindow(e.loginLimiter.FailureCount(ctx, accountIdentifier(userID)))
	if window <= 0 {
		return
	}
	// Break-glass exemption — see accountThrottled. is_builtin is server-side
	// DB state, never a request claim. The lookup sits behind the window check,
	// so a normal login never pays for it.
	if e.isBuiltinUser(ctx, userID) {
		return
	}
	e.loginLimiter.ArmCooldown(ctx, accountIdentifier(userID), window)
	if e.accountThrottleArmed != nil {
		e.accountThrottleArmed(userID, window)
	}
}

// burnEqualizer spends the constant-cost compare that keeps a credential-free
// refusal as slow as a real one.
func (e *Engine) burnEqualizer(password string) {
	if e.dummyCompare != nil {
		e.dummyCompare(password)
		return
	}
	burnDummyCompare(password)
}

// isBuiltinUser reports whether the account is the seeded break-glass admin.
// Fails to "not built-in" on a lookup error: the throttle is the safe side of
// that decision (it refuses for seconds, it does not lock), and claiming
// built-in on a failed read would hand an attacker an exemption.
func (e *Engine) isBuiltinUser(ctx context.Context, userID int64) bool {
	if e.userRepo == nil {
		return false
	}
	u, err := e.userRepo.GetByID(ctx, userID)
	return err == nil && u != nil && u.IsBuiltin
}

// LoginFailureCount returns the current brute-force failure count for the
// given IP (and optionally user). Used by the handler to enforce
// CaptchaAfterFailures: captcha is demanded only once an identifier has
// crossed the policy threshold. Returns 0 when no limiter is wired.
func (e *Engine) LoginFailureCount(ctx context.Context, clientIP string) int {
	if e.loginLimiter == nil {
		return 0
	}
	return e.loginLimiter.FailureCount(ctx, ipIdentifier(clientIP))
}

// trackFailure records a failed login against the brute-force limiter and
// emits UserLocked when the account crosses the threshold. It NO LONGER flips
// mxid_user.status — that permanent DB lock is reserved for admin LockUser.
//
// The two dimensions are recorded differently on purpose. The per-IP dimension
// takes the auto-expiring lock: it throttles a scripted scan and self-heals
// when its TTL elapses. The per-account dimension is COUNTED ONLY
// (RecordFailureCount never writes a lock key) — it feeds the refusal window
// in armAccountThrottle instead, because a lock keyed on the account is a DoS
// switch for anyone who knows a username.
func (e *Engine) trackFailure(ctx context.Context, userID int64, req *AuthRequest) {
	if e.loginLimiter == nil {
		// Legacy fallback (no limiter wired, e.g. tests): keep a per-user
		// counter but DO NOT flip account status — auto-lock is Redis-only now.
		e.trackFailureLegacy(ctx, userID, req)
		return
	}
	if req.ClientIP != "" {
		_ = e.loginLimiter.RecordFailure(ctx, ipIdentifier(req.ClientIP))
	}
	// userID 0 means the username matched no account: the IP counter still
	// moved, but there is nothing to count or report against an account.
	if userID <= 0 {
		return
	}
	count := e.loginLimiter.RecordFailureCount(ctx, accountIdentifier(userID))
	// Emitted on the crossing only (exact equality), so a run of failures
	// reports once. Now that the account dimension no longer rides the IP
	// lock's transition, this also fires for an attacker rotating addresses.
	if max := e.loginLimiter.Config().MaxAttempts; max > 0 && count == max {
		e.eventBus.Publish(ctx, event.Event{
			Type: event.UserLocked,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  "max_failed_attempts",
				"ip":      req.ClientIP,
			},
		})
	}
}

// trackFailureLegacy is the pre-limiter per-user counter, kept for the
// no-redis-limiter path. It records the failure and emits UserLocked at the
// threshold but never touches mxid_user.status (no permanent auto-lock).
func (e *Engine) trackFailureLegacy(ctx context.Context, userID int64, req *AuthRequest) {
	// Purely per-user, so an unknown username (userID 0) has nothing to count
	// here — it would key every failed enumeration attempt onto a single
	// bucket for a user that does not exist.
	if e.rdb == nil || userID <= 0 {
		return
	}
	key := e.failCountKey(userID)
	count, err := e.rdb.Incr(ctx, key).Result()
	if err != nil {
		return
	}
	maxAttempts := e.loginConfig.MaxFailedAttempts
	lockout := e.loginConfig.LockoutDuration
	if e.loginPolicy != nil {
		if m, d := e.loginPolicy(ctx, req.TenantID); m > 0 {
			maxAttempts = m
			lockout = d
		}
	}
	if count == 1 {
		e.rdb.Expire(ctx, key, lockout)
	}
	maxAttemptsI64 := int64(maxAttempts)
	if maxAttemptsI64 > 0 && count == maxAttemptsI64 {
		e.eventBus.Publish(ctx, event.Event{
			Type: event.UserLocked,
			Payload: map[string]any{
				"user_id": userID,
				"reason":  "max_failed_attempts",
				"ip":      req.ClientIP,
			},
		})
	}
}

// clearFailureCountIP clears the limiter keys for the user AND the supplied IP
// (so a legitimate login also relieves the per-IP budget), plus the legacy
// per-user counter.
func (e *Engine) clearFailureCountIP(ctx context.Context, userID int64, clientIP string) {
	if e.loginLimiter != nil {
		e.loginLimiter.ResetMany(ctx, loginIdentifiers(userID, clientIP)...)
	}
	if e.rdb != nil {
		e.rdb.Del(ctx, e.failCountKey(userID))
	}
}

// publishLoginEvent emits a login success or failure event AND persists a
// login record for audit. The two paths are independent — event subscribers
// can do live notifications (slack, security tooling) while the record
// table backs the per-user history view in the console.
//
// stage is "password" for first-factor attempts and "mfa" for second-factor
// verification calls. Callers default to "password" by passing "".
func (e *Engine) publishLoginEvent(ctx context.Context, result *AuthResult, req *AuthRequest, success bool, stage ...string) {
	stageStr := "password"
	if len(stage) > 0 && stage[0] != "" {
		stageStr = stage[0]
	}
	eventType := event.LoginFailed
	if success {
		eventType = event.LoginSuccess
	}

	payload := map[string]any{
		"user_id":    result.UserID,
		"username":   result.Username,
		"auth_type":  req.AuthType,
		"ip":         req.ClientIP,
		"user_agent": req.UserAgent,
		"tenant_id":  req.TenantID,
		"success":    success,
	}

	reason := ""
	if !success {
		payload["failure_status"] = int(result.Status)
		switch result.Status {
		case AuthFailed:
			reason = "invalid credentials"
		case AuthLocked:
			reason = "account locked"
		case AuthDisabled:
			reason = "account disabled"
		case AuthMFARequired:
			reason = "mfa required"
		}
		// Carry the reason into the audit detail too — previously it was only
		// fed to the login recorder, leaving every login.failed audit row with
		// a blank reason (can't tell "account disabled" from "wrong password").
		payload["reason"] = reason
	}

	e.eventBus.Publish(ctx, event.Event{
		Type:    eventType,
		Payload: payload,
	})

	if e.loginRecorder != nil {
		e.loginRecorder.RecordAttempt(ctx, LoginAttempt{
			TenantID:  req.TenantID,
			UserID:    result.UserID,
			Username:  result.Username,
			Success:   success,
			Stage:     stageStr,
			AuthType:  req.AuthType,
			Reason:    reason,
			IP:        req.ClientIP,
			UserAgent: req.UserAgent,
		})
	}
}

// SessionManager returns the underlying session manager (for middleware use).
func (e *Engine) SessionManager() *session.Manager {
	return e.sessionMgr
}
