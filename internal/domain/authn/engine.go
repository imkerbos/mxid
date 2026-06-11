package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/redis/go-redis/v9"
)

// Engine errors.
var (
	ErrUnknownProvider = errors.New("unknown authentication provider")
	ErrAuthFailed      = errors.New("authentication failed")
	ErrAccountLocked   = errors.New("account is locked")
	ErrPasswordExpired = errors.New("password has expired")
	ErrMFARequired     = errors.New("mfa verification required")
	ErrSessionNotFound = errors.New("session not found")
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
}

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

	result, err := provider.Authenticate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	switch result.Status {
	case AuthFailed:
		// Track failure count
		if result.UserID > 0 {
			e.trackFailure(ctx, result.UserID, req)
		}
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrAuthFailed

	case AuthLocked:
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrAccountLocked

	case AuthPasswordExpired:
		e.publishLoginEvent(ctx, result, req, false)
		return nil, ErrPasswordExpired

	case AuthMFARequired:
		// Return without creating a session; MFA step needed
		return nil, ErrMFARequired

	case AuthSuccess:
		// Clear failure count
		if result.UserID > 0 {
			e.clearFailureCount(ctx, result.UserID)
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

	e.publishLoginEvent(ctx, result, req, true, stage)

	return &LoginResponse{
		UserID:      result.UserID,
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
func (e *Engine) VerifyMFAChallenge(ctx context.Context, challenge, code string) (*LoginResponse, error) {
	if e.mfaVerifier == nil {
		return nil, ErrMFANotConfigured
	}
	payload, err := e.consumeMFAChallenge(ctx, challenge)
	if err != nil {
		return nil, err
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
		e.mfaRateLimiter.RecordFailure(ctx, payload.UserID, payload.ClientIP)
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

// Logout deletes a session.
func (e *Engine) Logout(ctx context.Context, namespace, sessionID string, userID int64) error {
	if err := e.sessionMgr.Delete(ctx, namespace, sessionID); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	e.eventBus.Publish(ctx, event.Event{
		Type: event.Logout,
		Payload: map[string]any{
			"user_id":    userID,
			"session_id": sessionID,
		},
	})

	return nil
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

// failCountKey returns the Redis key for tracking login failures.
func (e *Engine) failCountKey(userID int64) string {
	return "mxid:login_fail:" + strconv.FormatInt(userID, 10)
}

// trackFailure increments the failure counter and locks the account if the threshold is reached.
func (e *Engine) trackFailure(ctx context.Context, userID int64, req *AuthRequest) {
	key := e.failCountKey(userID)
	count, err := e.rdb.Incr(ctx, key).Result()
	if err != nil {
		return
	}

	// Runtime policy from DB (with YAML fallback) so admins can tune
	// these without a restart.
	maxAttempts := e.loginConfig.MaxFailedAttempts
	lockout := e.loginConfig.LockoutDuration
	if e.loginPolicy != nil {
		if m, d := e.loginPolicy(ctx, req.TenantID); m > 0 {
			maxAttempts = m
			lockout = d
		}
	}

	// Set TTL on first failure
	if count == 1 {
		e.rdb.Expire(ctx, key, lockout)
	}

	maxAttemptsI64 := int64(maxAttempts)
	if maxAttemptsI64 > 0 && count >= maxAttemptsI64 {
		// Lock the account
		_ = e.userRepo.UpdateStatus(ctx, userID, 2) // StatusLocked = 2

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

// clearFailureCount removes the failure counter after a successful login.
func (e *Engine) clearFailureCount(ctx context.Context, userID int64) {
	e.rdb.Del(ctx, e.failCountKey(userID))
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
		"user_id":   result.UserID,
		"username":  result.Username,
		"auth_type": req.AuthType,
		"ip":        req.ClientIP,
		"user_agent": req.UserAgent,
		"tenant_id": req.TenantID,
		"success":   success,
	}

	reason := ""
	if !success {
		payload["failure_status"] = int(result.Status)
		switch result.Status {
		case AuthFailed:
			reason = "invalid credentials"
		case AuthLocked:
			reason = "account locked"
		case AuthPasswordExpired:
			reason = "password expired"
		case AuthMFARequired:
			reason = "mfa required"
		}
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

