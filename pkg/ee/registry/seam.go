package registry

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/pkg/session"
)

// This file is the dependency-injection seam used by heavier EE features (e.g.
// external IdP) that need more than a console route group: they require the
// bootstrap App (DB/Redis/router/groups), plus a handful of CE-domain hooks the
// EE module cannot construct itself (account linking lives in the CE user
// domain; tenant-code resolution and console authorization live in CE too).
//
// An EE feature registers an Initializer from its init(); app/run.go calls
// RunInit once at startup with a populated InitContext. CE imports no EE feature
// package, so no Initializer is registered and RunInit is a no-op.

// ResolverInput is the neutral account-linking contract between an external IdP
// callback (EE) and the CE user domain. It mirrors user.ExternalLoginInput but
// lives here so neither side imports the other: CE's adapter and the EE handler
// both reference this type. Carries every field needed to link an existing user
// or auto-provision a new one.
type ResolverInput struct {
	TenantID     int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	Username     string
	DisplayName  string
	Email        string
	Phone        string
	Avatar       string
	Raw          map[string]any
	AutoCreate   bool
	DefaultOrgID *int64
}

// ExternalLoginFunc resolves an external identity to a local user, returning the
// user id and username. Implemented by the CE user domain.
type ExternalLoginFunc func(ctx context.Context, in *ResolverInput) (userID int64, username string, err error)

// BindIdentityInput is the neutral binding contract between an external IdP
// callback (EE) and the CE user domain. Mirrors ResolverInput but carries the
// already-authenticated local user instead of auto-provision knobs.
type BindIdentityInput struct {
	TenantID     int64
	UserID       int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	DisplayName  string
	Raw          map[string]any
	// LinkedAtLogin marks a bind that came from the login-time link flow,
	// where the caller held no session and proved ownership with a TOTP code.
	// Carried across the seam so the audit action can say which path it was.
	LinkedAtLogin bool
}

// BindIdentityFunc links an already-authenticated external identity to an
// existing local user. Implemented by the CE user domain. Account linking is a
// CE concern on purpose: the rule deciding who may take over an external
// identity is a security decision and belongs in auditable open code, not in an
// obfuscated EE build.
type BindIdentityFunc func(ctx context.Context, in *BindIdentityInput) error

// Stable identity-rebind conflict sentinels. BindIdentityFunc and
// ExternalLoginFunc implementations (CE) translate their internal
// user.ErrExternalIDTaken / ErrIdentityAlreadyBound / ErrExternalUserDeleted
// into these before returning, so an EE caller — which cannot import CE's
// internal user domain to compare against those directly — can still tell a
// known conflict apart from an arbitrary failure via errors.Is, and choose a
// fixed, URL-safe slug for it.
//
// This exists because an EE callback handler once put a bind failure's raw
// err.Error() straight into a redirect's query string: a wrapped database
// error ("create identity: %w") flowed unfiltered into the browser's address
// bar, its history, and server access logs. errors.Is against these values —
// never the error's own text — is how a caller crossing this seam picks a
// slug safely. Mirrors errcode.NumExternalIDTaken / NumIdentityAlreadyBound /
// NumExternalUserDeleted in pkg/errcode/catalog.go; these are the same three
// conflicts, just referenceable from a package that must not import CE
// internals.
var (
	ErrExternalIDTaken      = errors.New("external account already bound to a live user")
	ErrIdentityAlreadyBound = errors.New("identity binding is already active")
	ErrExternalUserDeleted  = errors.New("the account behind this external identity was deleted")
	// ErrExternalLinkAmbiguous means the identity matched more than one local
	// account, or matched one that already signs in through this same
	// provider. Both are situations where picking a side would be picking who
	// receives the identity, so the caller must refuse and point at an
	// administrator.
	ErrExternalLinkAmbiguous = errors.New("more than one local account matches this identity")
	// ErrExternalLinkRequired is the sentinel behind *ExternalLinkRequired.
	ErrExternalLinkRequired = errors.New("external identity matches an existing account and must be linked")
)

// ExternalLinkRequired reports that an external identity has no binding, but a
// local account carrying the same email does exist — the shape of a provider
// migration, where someone's second IdP meets the account their first one
// created.
//
// It is NOT an authorization to bind. The caller must make the user prove they
// hold the candidate account (a fresh MFA factor, or its password) before any
// binding is written; without that step, matching on an attribute the IdP
// reports would let anyone who can set that attribute claim the account.
//
// Carries identifiers because the caller has to park the pending identity
// against the candidate and name the account in a prompt. Mask them before
// they reach a browser: unmasked, the prompt answers "does this person have an
// account here" for anyone who can reach the login page.
type ExternalLinkRequired struct {
	UserID   int64
	Username string
	Email    string
}

func (e *ExternalLinkRequired) Error() string {
	// Deliberately carries no identifiers: this string reaches logs.
	return "external identity matches an existing local account; linking required"
}

// Unwrap lets errors.Is(err, ErrExternalLinkRequired) succeed.
func (e *ExternalLinkRequired) Unwrap() error { return ErrExternalLinkRequired }

// TenantByCodeFunc maps a tenant code to its id (0 when unknown). Implemented by
// the CE tenant domain.
type TenantByCodeFunc func(ctx context.Context, code string) int64

// UpdateLastLoginFunc stamps last_login_at / last_login_ip after a successful
// login. The CE password engine does this in completeLogin; external-IdP logins
// run outside that engine (and the CE resolver seam has no client IP), so the EE
// handler must call this after minting the session or the user's "last login"
// never reflects a federated sign-in. Implemented by the CE user domain.
type UpdateLastLoginFunc func(ctx context.Context, userID int64, ip string) error

// ConsoleGateFunc authorizes an external identity for console login: it must
// reject break-glass built-in accounts and users without any console
// permission. Implemented in CE (authz + user repo).
type ConsoleGateFunc func(ctx context.Context, tenantID, userID int64) error

// AdminCheckFunc reports whether a user is an administrator (holds at least one
// console permission). Unlike ConsoleGateFunc it does NOT reject built-in
// accounts — it answers "may this user perform admin-level actions", not "may
// this external identity federate into console". Use it to gate admin writes
// reached over the portal (e.g. the form-fill extension pushing app descriptors).
type AdminCheckFunc func(ctx context.Context, tenantID, userID int64) bool

// ExternalURLsFunc returns the externally-reachable issuer (the OAuth callback
// target), portal, and console URLs for a tenant — read at REQUEST time from the
// CE settings store so external-IdP callbacks use the admin-configured URLs
// rather than a boot-time env default. Any empty return value means "fall back
// to the boot-time env value". Implemented in CE over settings.ExternalURLs (it
// injects the tenant scope itself, since external-IdP start runs pre-login
// without one). Unifies external URL config across CE protocols and EE IdP.
type ExternalURLsFunc func(ctx context.Context, tenantID int64) (issuer, portal, console string)

// OutboxHandler processes a durable outbox message. payload is the raw JSON the
// producer enqueued. Returning an error reschedules the message with backoff
// (dead-lettered after max attempts); nil marks it delivered. Must be
// idempotent — at-least-once delivery means a message can be retried after a
// crash mid-processing. Neutral ([]byte) so the EE module needs no CE internal
// type.
type OutboxHandler func(ctx context.Context, payload []byte) error

// OutboxRegisterFunc binds an EE handler to an outbox message kind. Implemented
// in CE over the outbox worker. The CE binary registers no EE handler and never
// enqueues an EE-only kind, so the kind simply has no consumer there.
type OutboxRegisterFunc func(kind string, h OutboxHandler)

// StepUpFreshFunc reports whether the caller's session has a fresh step-up (sudo)
// authentication within the configured window. EE credential-reveal gates on it —
// a honeypot vault must never hand out plaintext without a recent MFA. Implemented
// in CE over authn.StepUpChecker.Fresh.
type StepUpFreshFunc func(c *gin.Context, tenantID int64) bool

// OptionalSessionMiddlewareFunc builds gin middleware that resolves the given
// session namespace's cookie when one is present and valid, and does nothing
// otherwise — it never rejects. The external-IdP callback is the motivating
// caller: the same URL serves both an anonymous visitor signing in and a
// signed-in user attaching an external account to their profile (identity
// rebind), and only the second needs to know who is calling. Implemented in
// CE over authn.OptionalAuthMiddleware, which mxid-ee cannot import directly
// (internal package, separate module) — hence the seam.
type OptionalSessionMiddlewareFunc func(namespace string) gin.HandlerFunc

// MFAChallengeRequiredFunc reports whether an already-first-factor-authenticated
// user must clear an interactive MFA (TOTP) challenge before a session is issued:
// the MFA policy applies to them (all → everyone, admin_only → admins) AND they
// hold a verified factor. Used by external-IdP login to enforce MFA on federated
// sign-ins (a Lark login otherwise bypasses the second factor). A user with NO
// factor is handled separately by the mandatory-enrollment gate at session
// creation, not here.
type MFAChallengeRequiredFunc func(ctx context.Context, tenantID, userID int64) bool

// VerifyStepUpTOTPFunc validates a TOTP (or backup) code for a user mid-login,
// rate-limited per user+IP. Returns nil on success. Reused by external-IdP MFA
// so the federated challenge shares the same verifier + limiter as local login.
type VerifyStepUpTOTPFunc func(ctx context.Context, userID int64, clientIP, code string) error

// AppAccessFunc reports whether a user is authorized to launch an app (passes the
// app's access policy). EE form-fill gates credential access on it so a user can
// only reach a credential for an app they may actually use — and, for shared
// credentials, so only authorized users see the shared secret. Implemented in CE
// over appaccess.Service.CanAccess.
type AppAccessFunc func(ctx context.Context, userID, appID int64) (bool, error)

// ProvisioningConfigFunc returns an app's live, decrypted outbound-provisioning
// config. enabled=false means no downstream deprovision should run. Implemented
// in CE over the provisioning domain so the EE SCIM connector never touches the
// config table or the master key.
type ProvisioningConfigFunc func(ctx context.Context, appID int64) (enabled bool, connector, baseURL, token string, err error)

// InitContext carries everything an EE feature needs from CE at startup. App
// exposes DB/Redis/router/route-groups/config; the func hooks bridge to CE
// domains the EE module must not import.
type InitContext struct {
	App           *bootstrap.App
	SessionMgr    *session.Manager
	ExternalLogin ExternalLoginFunc
	// BindIdentity links an already-authenticated external identity to an
	// existing local user (account-linking, as opposed to ExternalLogin's
	// resolve-or-auto-provision). Implemented by the CE user domain.
	BindIdentity BindIdentityFunc
	TenantByCode TenantByCodeFunc
	ConsoleGate  ConsoleGateFunc
	// IsAdmin reports whether a user holds admin (console) permissions, without
	// the built-in-account rejection ConsoleGate applies. Gates admin writes made
	// over the portal (form-fill descriptor push).
	IsAdmin      AdminCheckFunc
	ExternalURLs ExternalURLsFunc
	// UpdateLastLogin stamps last-login after a federated sign-in (external IdP
	// runs outside the CE password engine that normally owns the stamp).
	UpdateLastLogin UpdateLastLoginFunc
	// OutboxRegister binds an EE outbox handler (e.g. SCIM deprovision delivery).
	OutboxRegister OutboxRegisterFunc
	// ProvisioningConfig reads an app's outbound-provisioning credentials at
	// delivery time (the EE SCIM connector uses it).
	ProvisioningConfig ProvisioningConfigFunc
	// StepUpFresh gates EE credential reveal on a fresh step-up (sudo) window.
	StepUpFresh StepUpFreshFunc
	// OptionalSessionMiddleware resolves a session without requiring one — used
	// to mount an optional-auth check on a single route (the external-IdP
	// callback) rather than a whole route group.
	OptionalSessionMiddleware OptionalSessionMiddlewareFunc
	// CanLaunchApp reports whether a user passes an app's access policy — EE
	// form-fill only reveals a credential for an app the user may launch.
	CanLaunchApp AppAccessFunc
	// MFAChallengeRequired gates external-IdP login on an interactive MFA
	// challenge when policy applies and the user holds a factor.
	MFAChallengeRequired MFAChallengeRequiredFunc
	// VerifyStepUpTOTP validates the TOTP code the external-IdP MFA challenge
	// collects, sharing the local-login verifier + rate limiter.
	VerifyStepUpTOTP VerifyStepUpTOTPFunc
}

// Initializer wires one EE feature. Returning an error aborts startup.
type Initializer func(*InitContext) error

var initializers []Initializer

// RegisterInit adds an EE feature initializer. Called from an EE package init().
func RegisterInit(i Initializer) {
	if i != nil {
		initializers = append(initializers, i)
	}
}

// RunInit invokes every registered EE initializer with the given context. No EE
// module imported (CE) → no initializers → no-op.
func RunInit(ic *InitContext) error {
	for _, i := range initializers {
		if err := i(ic); err != nil {
			return err
		}
	}
	return nil
}
