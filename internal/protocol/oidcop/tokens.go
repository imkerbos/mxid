package oidcop

import "time"

// accessToken is a persisted access token record. Stored keyed by ID so the
// userinfo/introspection/revocation endpoints can look it up regardless of
// whether the wire format is opaque or JWT.
type accessToken struct {
	ID             string    `json:"id"`
	ClientID       string    `json:"client_id"`
	Subject        string    `json:"subject"`
	RefreshTokenID string    `json:"refresh_token_id,omitempty"`
	Audience       []string  `json:"audience,omitempty"`
	Scopes         []string  `json:"scopes,omitempty"`
	Expiration     time.Time `json:"expiration"`
}

// refreshToken is a persisted refresh token record. Its Token string IS its ID
// (an opaque uuid); rotation deletes the old record and writes a new one keyed
// by the new string.
type refreshToken struct {
	ID            string    `json:"id"`
	Token         string    `json:"token"`
	AuthTime      time.Time `json:"auth_time"`
	AMR           []string  `json:"amr,omitempty"`
	Audience      []string  `json:"audience,omitempty"`
	UserID        string    `json:"user_id"`
	ClientID      string    `json:"client_id"`
	Scopes        []string  `json:"scopes,omitempty"`
	AccessTokenID string    `json:"access_token_id,omitempty"`
	// SessionID is the shared protocol-namespace session id (see
	// authRequest.SessionID), carried here so id_tokens reissued via the
	// refresh_token grant keep the same `sid` the first login emitted. It
	// survives rotation because renewRefreshToken reloads the whole record.
	SessionID string `json:"session_id,omitempty"`
	// FamilyID links every refresh token derived from the same initial
	// token-exchange (the code-flow issuance plus every rotation child
	// after it). Reuse detection revokes the whole family — not just the
	// presented token — so a stolen-and-replayed link kills the legitimate
	// client's current live token too. It survives rotation for the same
	// reason SessionID does.
	FamilyID   string    `json:"family_id,omitempty"`
	Expiration time.Time `json:"expiration"`
}

// consumedMarker is left behind at kRefreshConsumed(token) when a refresh
// token is rotated away (see Storage.renewRefreshToken). Its presence for a
// token that is no longer live is the reuse/theft signal: the token was
// already spent, yet someone just presented it again (RFC 6819 §5.2.2.3).
type consumedMarker struct {
	FamilyID string `json:"family_id"`
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
}

// refreshTokenRequest wraps a refreshToken to implement op.RefreshTokenRequest.
type refreshTokenRequest struct {
	*refreshToken
}

func (r *refreshTokenRequest) GetAMR() []string            { return r.AMR }
func (r *refreshTokenRequest) GetAudience() []string       { return r.Audience }
func (r *refreshTokenRequest) GetAuthTime() time.Time      { return r.AuthTime }
func (r *refreshTokenRequest) GetClientID() string         { return r.ClientID }
func (r *refreshTokenRequest) GetScopes() []string         { return r.Scopes }
func (r *refreshTokenRequest) GetSubject() string          { return r.UserID }
func (r *refreshTokenRequest) SetCurrentScopes(s []string) { r.Scopes = s }

// GetSessionID satisfies the sessionCarrier interface (claims.go) so id_tokens
// reissued via the refresh_token grant carry the same `sid` as the original.
func (r *refreshTokenRequest) GetSessionID() string { return r.SessionID }

// clientCredentialsRequest implements op.TokenRequest for the
// client_credentials (machine-to-machine) grant: there is no end user, so the
// subject is the client itself — mirrors the hand-rolled engine's
// tokenClientCredentials (internal/protocol/oidc/handler.go:928), which also
// carries no user context and issues a token scoped to the client's own
// audience.
type clientCredentialsRequest struct {
	clientID string
	scopes   []string
}

func (r *clientCredentialsRequest) GetSubject() string    { return r.clientID }
func (r *clientCredentialsRequest) GetAudience() []string { return []string{r.clientID} }
func (r *clientCredentialsRequest) GetScopes() []string   { return r.scopes }
func (r *clientCredentialsRequest) GetClientID() string   { return r.clientID }
