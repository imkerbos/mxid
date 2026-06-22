package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/redis/go-redis/v9"
)

const (
	authCodePrefix       = "mxid:oidc:code:"
	refreshTokenPrefix   = "mxid:oidc:refresh:"
	refreshFamilyPrefix  = "mxid:oidc:refresh:family:"
	refreshConsumePrefix = "mxid:oidc:refresh:consumed:"
	// ssoAppsPrefix tracks the set of OIDC apps that authenticated against
	// a given protocol SSO session. End-session uses this to enumerate RPs
	// for back-channel logout fan-out.
	ssoAppsPrefix      = "mxid:sso:apps:"
	defaultAuthCodeTTL = 5 * time.Minute
	defaultRefreshTTL  = 7 * 24 * time.Hour
)

// TrackSSOApp records that the given OIDC app authenticated a user via the
// given protocol SSO session. Idempotent SADD — duplicate authorize calls
// for the same session/app pair leave the set untouched.
//
// Expiry mirrors the SSO session's absolute window so the set self-cleans
// after the session is gone.
func (s *Store) TrackSSOApp(ctx context.Context, ssoSID string, appID int64, ttl time.Duration) error {
	if ssoSID == "" {
		return nil
	}
	key := ssoAppsPrefix + ssoSID
	pipe := s.rdb.Pipeline()
	pipe.SAdd(ctx, key, appID)
	if ttl > 0 {
		pipe.Expire(ctx, key, ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// PeekSSOApps returns the app IDs an SSO session authenticated against WITHOUT
// removing the tracking set. Use this for per-app JIT logout paths that must
// inspect the set but leave it intact so a subsequent full logout
// (LogoutUserBackchannel / endSession) can still fan out to all participating
// RPs. Contrast with ListSSOApps which is destructive (consume-once).
func (s *Store) PeekSSOApps(ctx context.Context, ssoSID string) ([]int64, error) {
	if ssoSID == "" {
		return nil, nil
	}
	key := ssoAppsPrefix + ssoSID
	members, err := s.rdb.SMembers(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	ids := make([]int64, 0, len(members))
	for _, m := range members {
		var id int64
		_, _ = fmt.Sscanf(m, "%d", &id)
		if id != 0 {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// ListSSOApps returns the app IDs an SSO session authenticated against, then
// removes the tracking set. DESTRUCTIVE: the Redis key is deleted after the
// read. Called by end-session / offboarding (LogoutUserBackchannel) to drive
// back-channel logout fan-out — those paths do not need the set to survive
// because the session itself is being torn down. For non-terminal per-app
// JIT logout, use PeekSSOApps instead.
func (s *Store) ListSSOApps(ctx context.Context, ssoSID string) ([]int64, error) {
	if ssoSID == "" {
		return nil, nil
	}
	key := ssoAppsPrefix + ssoSID
	members, err := s.rdb.SMembers(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	s.rdb.Del(ctx, key)
	ids := make([]int64, 0, len(members))
	for _, m := range members {
		var id int64
		_, _ = fmt.Sscanf(m, "%d", &id)
		if id != 0 {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// AuthorizationCode represents a stored auth code.
//
// AuthTime is the epoch second at which the user was authenticated in the
// originating SSO session — carried through so the eventual id_token can
// emit the OIDC `auth_time` claim with the correct value (NOT the code
// issuance time, which would be misleading when the same session reissues
// codes across multiple RP interactions).
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              int64     `json:"user_id"`
	TenantID            int64     `json:"tenant_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	Nonce               string    `json:"nonce"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	AuthTime            int64     `json:"auth_time,omitempty"`
	AuthMethod          string    `json:"auth_method,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}

// RefreshToken represents a stored refresh token.
//
// FamilyID links every refresh_token derived from the same initial token-exchange.
// On rotation, the new token inherits the family_id; on reuse detection (i.e.
// presenting a token whose hash already appears in the consumed-marker set),
// the entire family is revoked — a stolen + replayed refresh token gets
// caught even if the attacker rotates it once before the legitimate client
// does.
//
// AuthTime / AuthMethod / Nonce are carried through the chain so refreshed
// id_tokens emit the ORIGINAL login time (per OIDC Core §12.1).
type RefreshToken struct {
	Token      string    `json:"token"`
	FamilyID   string    `json:"family_id"`
	ClientID   string    `json:"client_id"`
	UserID     int64     `json:"user_id"`
	TenantID   int64     `json:"tenant_id"`
	Scopes     []string  `json:"scopes"`
	AuthTime   int64     `json:"auth_time,omitempty"`
	AuthMethod string    `json:"auth_method,omitempty"`
	Nonce      string    `json:"nonce,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Store manages OIDC authorization codes and refresh tokens in Redis.
type Store struct {
	rdb *redis.Client
}

// NewStore creates an OIDC token store.
func NewStore(rdb *redis.Client) *Store {
	return &Store{rdb: rdb}
}

// Redis exposes the underlying client so peer helpers (client assertion
// verification, jti replay tracking) can share the same connection pool
// without re-wiring through bootstrap.
func (s *Store) Redis() *redis.Client { return s.rdb }

// CreateAuthCode generates and stores an authorization code.
func (s *Store) CreateAuthCode(ctx context.Context, req *AuthCodeRequest) (*AuthorizationCode, error) {
	code, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("generate auth code: %w", err)
	}

	ttl := defaultAuthCodeTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}

	ac := &AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              req.UserID,
		TenantID:            req.TenantID,
		RedirectURI:         req.RedirectURI,
		Scopes:              req.Scopes,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		AuthTime:            req.AuthTime,
		AuthMethod:          req.AuthMethod,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(ttl),
	}

	data, err := json.Marshal(ac)
	if err != nil {
		return nil, fmt.Errorf("marshal auth code: %w", err)
	}

	key := authCodePrefix + code
	if err := s.rdb.Set(ctx, key, data, ttl).Err(); err != nil {
		return nil, fmt.Errorf("store auth code: %w", err)
	}

	return ac, nil
}

// ConsumeAuthCode retrieves and deletes an authorization code (single-use).
func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	key := authCodePrefix + code
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("authorization code not found or expired")
		}
		return nil, fmt.Errorf("get auth code: %w", err)
	}

	// Delete immediately (single-use)
	s.rdb.Del(ctx, key)

	var ac AuthorizationCode
	if err := json.Unmarshal(data, &ac); err != nil {
		return nil, fmt.Errorf("unmarshal auth code: %w", err)
	}

	if time.Now().After(ac.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	return &ac, nil
}

// CreateRefreshTokenRequest gathers everything needed to mint a fresh refresh
// token. A zero FamilyID means "start a new family" (initial token exchange);
// passing the parent's family ID chains the new token into the existing family.
type CreateRefreshTokenRequest struct {
	ClientID   string
	UserID     int64
	TenantID   int64
	Scopes     []string
	AuthTime   int64
	AuthMethod string
	Nonce      string
	FamilyID   string // empty → new family
	TTL        time.Duration
}

// CreateRefreshToken generates and stores a refresh token, registering it
// against the (possibly new) family bucket so subsequent rotations and
// reuse-detection can find every sibling.
func (s *Store) CreateRefreshToken(ctx context.Context, req *CreateRefreshTokenRequest) (*RefreshToken, error) {
	token := uuid.New().String()
	familyID := req.FamilyID
	if familyID == "" {
		familyID = uuid.New().String()
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = defaultRefreshTTL
	}

	rt := &RefreshToken{
		Token:      token,
		FamilyID:   familyID,
		ClientID:   req.ClientID,
		UserID:     req.UserID,
		TenantID:   req.TenantID,
		Scopes:     req.Scopes,
		AuthTime:   req.AuthTime,
		AuthMethod: req.AuthMethod,
		Nonce:      req.Nonce,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}

	data, err := json.Marshal(rt)
	if err != nil {
		return nil, fmt.Errorf("marshal refresh token: %w", err)
	}

	hash := hashRefreshToken(token)
	key := refreshTokenPrefix + hash
	if err := s.rdb.Set(ctx, key, data, ttl).Err(); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	// Family membership — used for cascade revoke on reuse detection.
	familyKey := refreshFamilyPrefix + familyID
	pipe := s.rdb.Pipeline()
	pipe.SAdd(ctx, familyKey, hash)
	pipe.Expire(ctx, familyKey, ttl)
	_, _ = pipe.Exec(ctx)

	return rt, nil
}

// ConsumeRefreshToken atomically retrieves and deletes a refresh token.
//
// If the token's hash already exists in the consumed-marker set, this is a
// replay attempt: the function revokes the entire token family and returns
// an error so the caller can deny the refresh AND alert audit.
func (s *Store) ConsumeRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	hash := hashRefreshToken(token)

	// Reuse detection — a hash present in the consumed-marker set means this
	// exact token has already been spent. The legitimate client should never
	// present an old token after rotation; if it shows up, treat as theft.
	consumedKey := refreshConsumePrefix + hash
	if exists, _ := s.rdb.Exists(ctx, consumedKey).Result(); exists > 0 {
		// Best-effort: load family ID from the consumed marker, revoke all members.
		fid, _ := s.rdb.Get(ctx, consumedKey).Result()
		if fid != "" {
			s.revokeFamily(ctx, fid)
		}
		return nil, fmt.Errorf("refresh token reuse detected; family revoked")
	}

	key := refreshTokenPrefix + hash
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("refresh token not found or expired")
		}
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	var rt RefreshToken
	if err := json.Unmarshal(data, &rt); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token: %w", err)
	}

	// Mark consumed + delete. Keep the marker for the original TTL so a
	// late-arriving replay can still be caught.
	remaining := time.Until(rt.ExpiresAt)
	if remaining < time.Minute {
		remaining = time.Minute
	}
	pipe := s.rdb.Pipeline()
	pipe.Del(ctx, key)
	pipe.Set(ctx, consumedKey, rt.FamilyID, remaining)
	_, _ = pipe.Exec(ctx)

	return &rt, nil
}

// RevokeRefreshToken deletes a single refresh token without touching its family.
func (s *Store) RevokeRefreshToken(ctx context.Context, token string) error {
	hash := hashRefreshToken(token)
	return s.rdb.Del(ctx, refreshTokenPrefix+hash).Err()
}

// revokeFamily deletes every refresh_token in a family plus the family bucket.
// Called when reuse detection trips so a compromised refresh chain cannot
// continue rotating into fresh tokens.
func (s *Store) revokeFamily(ctx context.Context, familyID string) {
	familyKey := refreshFamilyPrefix + familyID
	hashes, err := s.rdb.SMembers(ctx, familyKey).Result()
	if err != nil {
		return
	}
	if len(hashes) > 0 {
		keys := make([]string, 0, len(hashes)+1)
		for _, h := range hashes {
			keys = append(keys, refreshTokenPrefix+h)
		}
		keys = append(keys, familyKey)
		_ = s.rdb.Del(ctx, keys...).Err()
	}
}

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthCodeRequest holds parameters for creating an authorization code.
type AuthCodeRequest struct {
	ClientID            string
	UserID              int64
	TenantID            int64
	RedirectURI         string
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            int64  // epoch seconds when user authenticated
	AuthMethod          string // primary auth method, used to build amr (e.g. "local" → ["pwd"])
	TTL                 int    // seconds
}

// VerifyPKCE verifies the code_verifier against the stored challenge.
func VerifyPKCE(codeVerifier, codeChallenge, method string) bool {
	if method == "" || method == "plain" {
		return codeVerifier == codeChallenge
	}
	// S256: BASE64URL(SHA256(code_verifier))
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return computed == codeChallenge
}
