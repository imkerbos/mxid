package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenIssuer creates signed JWTs for OIDC.
type TokenIssuer struct {
	issuer string
}

// NewTokenIssuer creates a token issuer with the given issuer URL.
func NewTokenIssuer(issuer string) *TokenIssuer {
	return &TokenIssuer{issuer: issuer}
}

// IDTokenClaims holds the claims for an OIDC ID token.
//
// AuthTime is the epoch second at which the user was authenticated; sourced
// from the protocol SSO session's CreatedAt. Required by OIDC Core §2 when
// max_age is requested or when issuing for high-assurance flows.
//
// AccessToken (when set) drives at_hash computation per OIDC Core §3.1.3.6.
// AuthorizationCode (when set) drives c_hash computation per OIDC Core
// §3.3.2.11 — required in hybrid flow (response_type includes id_token).
// AMR / ACR are populated to advertise how the user authenticated.
type IDTokenClaims struct {
	UserID            int64
	ClientID          string
	Nonce             string
	Scopes            []string
	Extra             map[string]any
	ExpiresIn         time.Duration
	AuthTime          int64
	AMR               []string // authentication methods, e.g. ["pwd"]
	ACR               string   // authentication context class
	AccessToken       string   // raw access_token used to derive at_hash
	AuthorizationCode string   // raw authorization code used to derive c_hash
	// Subject overrides the default "<UserID>" sub generation. When non-empty
	// the issuer uses this value verbatim — used to honour the app's
	// subject_strategy (pairwise / username_suffixed / persistent_id / email).
	Subject string
}

// AccessTokenClaims holds the claims for an access token.
type AccessTokenClaims struct {
	UserID    int64
	TenantID  int64
	ClientID  string
	Scopes    []string
	ExpiresIn time.Duration
	// Subject overrides default "<UserID>" — see IDTokenClaims.Subject.
	Subject string
}

// TokenPair holds the generated tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IssueIDToken creates a signed ID token per OIDC Core 1.0 §2.
//
// Claim policy:
//   - iss / sub / aud / exp / iat — always present (RFC mandatory)
//   - azp — always set to client_id (matches aud in single-audience case)
//   - jti — fresh ULID-equivalent for replay defence
//   - auth_time — set when AuthTime is non-zero
//   - nonce — echoed verbatim from request when provided
//   - amr / acr — set when populated by caller
//   - at_hash — computed from AccessToken when present; OMITTED when empty
//     (OIDC Core §3.1.3.6 — empty string is non-conforming)
func (t *TokenIssuer) IssueIDToken(claims *IDTokenClaims, key *rsa.PrivateKey, kid string) (string, error) {
	now := time.Now()
	exp := now.Add(claims.ExpiresIn)

	sub := claims.Subject
	if sub == "" {
		// Back-compat default — bare snowflake string. Callers that want
		// strategy-driven sub MUST populate claims.Subject upstream.
		sub = fmt.Sprintf("%d", claims.UserID)
	}
	mapClaims := jwt.MapClaims{
		"iss": t.issuer,
		"sub": sub,
		"aud": claims.ClientID,
		"azp": claims.ClientID,
		"exp": exp.Unix(),
		"iat": now.Unix(),
		"jti": uuid.New().String(),
	}

	if claims.AuthTime > 0 {
		mapClaims["auth_time"] = claims.AuthTime
	}
	if claims.Nonce != "" {
		mapClaims["nonce"] = claims.Nonce
	}
	if len(claims.AMR) > 0 {
		mapClaims["amr"] = claims.AMR
	}
	if claims.ACR != "" {
		mapClaims["acr"] = claims.ACR
	}
	if claims.AccessToken != "" {
		mapClaims["at_hash"] = computeHash(claims.AccessToken)
	}
	if claims.AuthorizationCode != "" {
		mapClaims["c_hash"] = computeHash(claims.AuthorizationCode)
	}

	// Merge extra claims (profile, email, phone, groups from scopes).
	// Done last so explicit values above are not silently overwritten.
	for k, v := range claims.Extra {
		if _, conflict := mapClaims[k]; conflict {
			continue
		}
		mapClaims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}
	return signed, nil
}

// computeHash implements the at_hash / c_hash algorithm shared by OIDC Core
// §3.1.3.6 (at_hash) and §3.3.2.11 (c_hash):
//
//  1. Hash the ASCII bytes with the signing algorithm's hash function
//     (SHA-256 for RS256).
//  2. Take the left-most half (16 bytes for SHA-256).
//  3. base64url-encode without padding.
func computeHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// IssueAccessToken creates a signed access token (JWT).
//
// Claims kept minimal per RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens):
// iss, sub, aud, exp, iat, jti, client_id, scope, token_type. The tenant_id
// claim is intentionally NOT included — internal multi-tenancy is a server
// concern, not part of the public token contract. Resource servers that need
// tenant resolution should call /introspect or lookup by sub.
func (t *TokenIssuer) IssueAccessToken(claims *AccessTokenClaims, key *rsa.PrivateKey, kid string) (string, error) {
	now := time.Now()
	exp := now.Add(claims.ExpiresIn)

	sub := claims.Subject
	if sub == "" {
		sub = fmt.Sprintf("%d", claims.UserID)
	}
	mapClaims := jwt.MapClaims{
		"iss":        t.issuer,
		"sub":        sub,
		"aud":        claims.ClientID,
		"exp":        exp.Unix(),
		"iat":        now.Unix(),
		"jti":        uuid.New().String(),
		"client_id":  claims.ClientID,
		"scope":      claims.Scopes,
		"token_type": "Bearer",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "at+jwt" // RFC 9068 — identifies as access token

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign access_token: %w", err)
	}
	return signed, nil
}

// ValidateAccessToken parses and validates a JWT access token.
func (t *TokenIssuer) ValidateAccessToken(tokenStr string, key *rsa.PublicKey) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// ParseRSAPrivateKey parses a PEM-encoded RSA private key.
func ParseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 first, then PKCS1
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		rsaKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return rsaKey, nil
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rsaKey, nil
}

// ParseRSAPublicKey parses a PEM-encoded RSA public key.
func ParseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaKey, nil
}

// JWK represents a JSON Web Key for the JWKS endpoint.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// RSAPublicKeyToJWK converts an RSA public key to a JWK.
func RSAPublicKeyToJWK(pub *rsa.PublicKey, kid string) *JWK {
	return &JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64URLEncodeBigInt(pub.N),
		E:   base64URLEncodeBigInt(big.NewInt(int64(pub.E))),
	}
}

func base64URLEncodeBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}
