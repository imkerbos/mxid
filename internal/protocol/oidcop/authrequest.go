// Package oidcop adapts MXID's stores and identity into the zitadel/oidc
// OpenID Provider (op) library, which owns the OIDC/OAuth2 spec surface
// (authorize/token/userinfo/jwks/introspect/revoke/end_session, PKCE, hashes,
// signing). This replaces the hand-rolled internal/protocol/oidc package.
//
// Multi-tenancy: one issuer, many clients — op.Storage.GetClientByClientID
// resolves each app as a client; tokens are scoped per-client by `aud`. Signing
// is provider-level (internal/domain/oidckey), NOT per-app.
package oidcop

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// authRequest is MXID's persisted authorization request. It implements
// op.AuthRequest and is stored in Redis between the authorize call and the
// login/consent completion (the BFF bridge sets UserID + IsDone, then op issues
// the code). Fields are exported for JSON (Redis) serialization.
type authRequest struct {
	ID            string            `json:"id"`
	CreationDate  time.Time         `json:"creation_date"`
	ClientID      string            `json:"client_id"`
	CallbackURI   string            `json:"callback_uri"`
	TransferState string            `json:"transfer_state"`
	Prompt        []string          `json:"prompt,omitempty"`
	LoginHint     string            `json:"login_hint,omitempty"`
	MaxAuthAgeSec *uint             `json:"max_auth_age_sec,omitempty"`
	UserID        string            `json:"user_id,omitempty"`
	Scopes        []string          `json:"scopes,omitempty"`
	Audience      []string          `json:"audience,omitempty"`
	ResponseType  oidc.ResponseType `json:"response_type"`
	ResponseMode  oidc.ResponseMode `json:"response_mode,omitempty"`
	Nonce         string            `json:"nonce,omitempty"`
	CodeChallenge *codeChallenge    `json:"code_challenge,omitempty"`
	AMR           []string          `json:"amr,omitempty"`
	ACR           string            `json:"acr,omitempty"`

	// IsDone flips to true once the user has authenticated (and consented) via
	// the BFF login bridge. op refuses to issue a code until Done() is true.
	IsDone bool      `json:"is_done"`
	AuthAt time.Time `json:"auth_at,omitempty"`

	// SessionID is the shared protocol-namespace session id (session.Manager,
	// NamespaceProtocol — same value as the mxid_proto_sid cookie), set by the
	// login bridge alongside UserID/IsDone once the user authenticates. It is
	// emitted as the id_token `sid` claim (claims.go) so OIDC back-channel
	// logout (WS2) can correlate the id_token with the logout_token minted for
	// the same session.
	SessionID string `json:"session_id,omitempty"`

	// IdpInitiated records that this authorize request carried idp_initiated=1
	// (a portal app-list launch, set by app/adapters_portal.go's launch-URL
	// builder). op's schema decoder drops the unknown query param, so it is
	// captured off the raw request into the request context by the
	// withIdpInitiated wrapper (provider.go) and persisted here in
	// Storage.CreateAuthRequest. The login bridge reads it to keep IdP-initiated
	// launches seamless (no SSO login-confirmation), mirroring the hand-rolled
	// engine (internal/protocol/oidc/handler.go:397).
	IdpInitiated bool `json:"idp_initiated,omitempty"`
}

type codeChallenge struct {
	Challenge string `json:"challenge"`
	Method    string `json:"method"`
}

func (a *authRequest) GetID() string          { return a.ID }
func (a *authRequest) GetACR() string         { return a.ACR }
func (a *authRequest) GetAMR() []string       { return a.AMR }
func (a *authRequest) GetAudience() []string  { return a.Audience }
func (a *authRequest) GetAuthTime() time.Time { return a.AuthAt }
func (a *authRequest) GetClientID() string    { return a.ClientID }
func (a *authRequest) GetNonce() string       { return a.Nonce }
func (a *authRequest) GetRedirectURI() string { return a.CallbackURI }
func (a *authRequest) GetState() string       { return a.TransferState }
func (a *authRequest) GetSubject() string     { return a.UserID }
func (a *authRequest) Done() bool             { return a.IsDone }
func (a *authRequest) GetSessionID() string   { return a.SessionID }

func (a *authRequest) GetResponseType() oidc.ResponseType { return a.ResponseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.ResponseMode }
func (a *authRequest) GetScopes() []string                { return a.Scopes }

func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == nil {
		return nil
	}
	method := oidc.CodeChallengeMethodPlain
	if a.CodeChallenge.Method == "S256" {
		method = oidc.CodeChallengeMethodS256
	}
	return &oidc.CodeChallenge{Challenge: a.CodeChallenge.Challenge, Method: method}
}

// authRequestFromOIDC builds the persisted request from the parsed op request.
// UserID is empty at this point — the login bridge fills it before completion.
func authRequestFromOIDC(req *oidc.AuthRequest, id, userID string) *authRequest {
	var cc *codeChallenge
	if req.CodeChallenge != "" {
		cc = &codeChallenge{Challenge: req.CodeChallenge, Method: string(req.CodeChallengeMethod)}
	}
	return &authRequest{
		ID:            id,
		CreationDate:  time.Now(),
		ClientID:      req.ClientID,
		CallbackURI:   req.RedirectURI,
		TransferState: req.State,
		Prompt:        promptToInternal(req.Prompt),
		LoginHint:     req.LoginHint,
		MaxAuthAgeSec: req.MaxAge,
		UserID:        userID,
		Scopes:        req.Scopes,
		Audience:      []string{req.ClientID}, // aud = client_id; per-client scoping
		ResponseType:  req.ResponseType,
		ResponseMode:  req.ResponseMode,
		Nonce:         req.Nonce,
		CodeChallenge: cc,
	}
}

func promptToInternal(prompts oidc.SpaceDelimitedArray) []string {
	out := make([]string, 0, len(prompts))
	for _, p := range prompts {
		switch p {
		case oidc.PromptNone, oidc.PromptLogin, oidc.PromptConsent, oidc.PromptSelectAccount:
			out = append(out, p)
		}
	}
	return out
}
