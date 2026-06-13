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
	Expiration    time.Time `json:"expiration"`
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
