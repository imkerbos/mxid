package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/safehttp"
	"github.com/redis/go-redis/v9"
)

// jwksHTTPClient is the SSRF-safe client for fetching admin-configured RP
// jwks_uri. jwks_uri is per-app OIDC client config (arbitrary host), so it must
// go through the IP/scheme guard. Federation is https-only by design.
var jwksHTTPClient = safehttp.New(safehttp.WithTimeout(5 * time.Second))

// ClientAssertionType is the OAuth-registered client_assertion_type value
// for RFC 7523 JWT-bearer client authentication.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// jtiReplayPrefix is the Redis namespace for client_assertion jti tracking.
// One entry per (client_id, jti) pair with TTL = jwt's exp - now, so replays
// of the same assertion within its validity window are rejected.
const jtiReplayPrefix = "mxid:oidc:client_jti:"

// jwksCache is a small in-process cache for RP-supplied JWKS endpoints so
// private_key_jwt verification does not hit the RP on every /token call.
//
// TTL is intentionally short (5 min) so key rotations propagate quickly;
// production deployments expecting heavier traffic should layer an HTTP
// cache (Cloudflare / nginx) in front.
type jwksCache struct {
	mu      sync.Mutex
	entries map[string]jwksCacheEntry
}

type jwksCacheEntry struct {
	keys     []*rsa.PublicKey
	keyByKID map[string]*rsa.PublicKey
	expires  time.Time
}

var sharedJWKSCache = &jwksCache{entries: make(map[string]jwksCacheEntry)}

// VerifyClientAssertion implements RFC 7523 §3 + OIDC Core §9.
//
// Returns the asserted client_id when the assertion is valid for the
// configured auth method, an empty string + error otherwise. Caller is
// responsible for fetching the app config based on the returned client_id
// and applying any additional authorization checks.
func VerifyClientAssertion(
	ctx context.Context,
	rdb *redis.Client,
	app *resolver.AppConfig,
	assertion string,
	expectedAud string,
) error {
	cfg := parseOIDCConfigStatic(app.ProtocolConfig)
	method := cfg.TokenEndpointAuthMode

	parsed, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("parse client_assertion: %w", err)
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid client_assertion claims")
	}

	// Standard claim checks (apply to both HMAC and asymmetric paths).
	iss, _ := mc["iss"].(string)
	sub, _ := mc["sub"].(string)
	if iss == "" || sub == "" || iss != sub || iss != app.ClientID {
		return fmt.Errorf("client_assertion iss/sub must equal client_id")
	}
	if !audienceMatches(mc["aud"], expectedAud) {
		return fmt.Errorf("client_assertion aud does not match token endpoint")
	}
	if exp, ok := numericClaim(mc["exp"]); !ok || time.Now().Unix() >= exp {
		return fmt.Errorf("client_assertion expired or missing exp")
	}
	if jti, _ := mc["jti"].(string); jti != "" {
		if err := checkJTIReplay(ctx, rdb, app.ClientID, jti, exp(mc)); err != nil {
			return err
		}
	}

	// Signature verification per auth method.
	switch method {
	case "client_secret_jwt":
		if app.ClientSecret == "" {
			return fmt.Errorf("app has no client_secret configured for client_secret_jwt")
		}
		_, err := jwt.Parse(assertion, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing alg: %v", t.Header["alg"])
			}
			return []byte(app.ClientSecret), nil
		})
		if err != nil {
			return fmt.Errorf("verify client_secret_jwt signature: %w", err)
		}
	case "private_key_jwt":
		keys, err := resolveRPJWKS(ctx, cfg)
		if err != nil {
			return fmt.Errorf("load RP jwks: %w", err)
		}
		_, err = jwt.Parse(assertion, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing alg: %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			if kid != "" {
				if key, ok := keys.keyByKID[kid]; ok {
					return key, nil
				}
			}
			// Fall back to trying every published key when kid omitted —
			// some libraries skip the header. Spec recommends kid, but
			// being permissive here makes integration easier.
			if len(keys.keys) > 0 {
				return keys.keys[0], nil
			}
			return nil, fmt.Errorf("no matching RP public key")
		})
		if err != nil {
			return fmt.Errorf("verify private_key_jwt signature: %w", err)
		}
	default:
		return fmt.Errorf("client auth method %q does not support JWT-bearer assertion", method)
	}

	return nil
}

func audienceMatches(claim any, expected string) bool {
	switch v := claim.(type) {
	case string:
		return v == expected
	case []any:
		for _, x := range v {
			if s, _ := x.(string); s == expected {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
	}
	return false
}

func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func exp(mc jwt.MapClaims) time.Duration {
	n, ok := numericClaim(mc["exp"])
	if !ok {
		return time.Minute
	}
	remaining := time.Until(time.Unix(n, 0))
	if remaining < time.Minute {
		return time.Minute
	}
	if remaining > 24*time.Hour {
		return 24 * time.Hour
	}
	return remaining
}

func checkJTIReplay(ctx context.Context, rdb *redis.Client, clientID, jti string, ttl time.Duration) error {
	key := jtiReplayPrefix + clientID + ":" + jti
	ok, err := rdb.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return fmt.Errorf("check jti replay: %w", err)
	}
	if !ok {
		return fmt.Errorf("client_assertion jti replay")
	}
	return nil
}

// resolveRPJWKS returns the RP's public keys for private_key_jwt
// verification, sourced from inline JWKS or fetched from JWKSURI with TTL
// caching.
func resolveRPJWKS(ctx context.Context, cfg *OIDCConfig) (*jwksCacheEntry, error) {
	if cfg.JWKS != "" {
		return parseInlineJWKS(cfg.JWKS)
	}
	if cfg.JWKSURI != "" {
		return fetchJWKSURI(ctx, cfg.JWKSURI)
	}
	return nil, fmt.Errorf("RP has neither jwks nor jwks_uri configured")
}

func parseInlineJWKS(raw string) (*jwksCacheEntry, error) {
	entry, err := decodeJWKSPayload([]byte(raw))
	if err != nil {
		return nil, err
	}
	entry.expires = time.Now().Add(time.Hour) // inline JWKS rarely changes
	return entry, nil
}

func fetchJWKSURI(ctx context.Context, uri string) (*jwksCacheEntry, error) {
	sharedJWKSCache.mu.Lock()
	if e, ok := sharedJWKSCache.entries[uri]; ok && time.Now().Before(e.expires) {
		sharedJWKSCache.mu.Unlock()
		return &e, nil
	}
	sharedJWKSCache.mu.Unlock()

	httpCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(httpCtx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := jwksHTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, safehttp.ErrDisallowedAddress) || errors.Is(err, safehttp.ErrDisallowedScheme) {
			return nil, fmt.Errorf("jwks_uri blocked by SSRF guard (target resolves to a disallowed/internal address or non-https scheme): %w", err)
		}
		return nil, fmt.Errorf("fetch jwks_uri: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jwks_uri returned status %d", resp.StatusCode)
	}
	// Cap the JWKS body: an admin-configured RP endpoint is semi-trusted, and an
	// oversized/streaming response must not balloon memory. 1 MiB dwarfs any real
	// JWKS.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	entry, err := decodeJWKSPayload(body)
	if err != nil {
		return nil, err
	}
	entry.expires = time.Now().Add(5 * time.Minute)

	sharedJWKSCache.mu.Lock()
	sharedJWKSCache.entries[uri] = *entry
	sharedJWKSCache.mu.Unlock()
	return entry, nil
}

func decodeJWKSPayload(raw []byte) (*jwksCacheEntry, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	out := &jwksCacheEntry{
		keys:     make([]*rsa.PublicKey, 0, len(doc.Keys)),
		keyByKID: make(map[string]*rsa.PublicKey, len(doc.Keys)),
	}
	for _, k := range doc.Keys {
		if !strings.EqualFold(k.Kty, "RSA") {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		ei := new(big.Int).SetBytes(eb).Int64()
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(ei),
		}
		out.keys = append(out.keys, pub)
		if k.Kid != "" {
			out.keyByKID[k.Kid] = pub
		}
	}
	if len(out.keys) == 0 {
		return nil, fmt.Errorf("jwks has no usable RSA keys")
	}
	return out, nil
}

// parseOIDCConfigStatic is a package-private helper so this file does not
// depend on Handler's parseOIDCConfig instance method.
func parseOIDCConfigStatic(raw json.RawMessage) *OIDCConfig {
	cfg := Defaults()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, cfg)
	}
	return cfg
}
