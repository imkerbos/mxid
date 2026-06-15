// Package license verifies Ed25519-signed MXID enterprise licenses and answers
// edition / feature questions. The vendor holds the private signing key; the
// app embeds only the public key (pubkey.go), so an operator cannot forge or
// edit a license to unlock EE features — the old admin-editable
// setting.License.EnableEnterprise boolean is replaced by this.
//
// Token format (compact, JWT-like, no header):
//
//	base64url(payload_json) "." base64url(ed25519_signature)
//
// CE is the default: an empty, malformed, signature-invalid, or expired token
// yields a CE Manager with no features.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Edition is the resolved product edition.
type Edition string

const (
	EditionCE Edition = "ce"
	EditionEE Edition = "ee"
)

// Product is this product's identifier. A license is bound to a product: the
// shared license-authority signs with a per-product key AND stamps this field,
// so a license issued for another product fails here even if a key leaked. When
// this verify code is later extracted into a shared licensekit, Product becomes
// a parameter; for now it's fixed to mxid.
const Product = "mxid"

// Payload is the signed license body. Format is shared with the
// license-authority signer (which imports this package), so changes here are
// the single source of truth for the token shape.
type Payload struct {
	Product    string    `json:"product"` // must equal Product ("mxid")
	Customer   string    `json:"customer"`
	Features   []Feature `json:"features"`
	IssuedAt   int64     `json:"iat"`
	ExpiresAt  int64     `json:"exp"` // unix seconds; 0 = perpetual
	MaxTenants int       `json:"max_tenants,omitempty"`
	MaxUsers   int       `json:"max_users,omitempty"`
	// InstallID, when set, binds the license to one installation fingerprint
	// (see Fingerprint). Empty = portable (runs on any install).
	InstallID string `json:"install_id,omitempty"`
}

var (
	ErrEmpty     = errors.New("license: empty token")
	ErrMalformed = errors.New("license: malformed token")
	ErrSignature = errors.New("license: bad signature")
	ErrExpired   = errors.New("license: expired")
	ErrProduct   = errors.New("license: wrong product")
	ErrInstall   = errors.New("license: bound to a different installation")
)

// Manager answers edition/feature questions for the loaded license. The zero
// value (and a CE Manager) safely report CE with no features.
type Manager struct {
	payload  *Payload
	features map[Feature]bool
	valid    bool
	// loadErr records why a non-empty token failed (for ops display); nil for
	// a clean CE (no token) or a valid EE license.
	loadErr error
}

// CE returns a community-edition Manager (no features).
func CE() *Manager { return &Manager{} }

// Load verifies a token against the embedded public key at time `now` and
// returns a Manager. A nil/empty token returns a CE Manager with no error.
// Any verification failure also returns a CE Manager, with LoadErr set so the
// caller can surface "license invalid → running as CE".
func Load(token string, now time.Time) *Manager {
	token = strings.TrimSpace(token)
	if token == "" {
		return &Manager{}
	}
	p, err := verify(token, now)
	if err != nil {
		return &Manager{loadErr: err}
	}
	feats := make(map[Feature]bool, len(p.Features))
	for _, f := range p.Features {
		feats[f] = true
	}
	return &Manager{payload: p, features: feats, valid: true}
}

func verify(token string, now time.Time) (*Payload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, ErrMalformed
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	pub, err := publicKey()
	if err != nil {
		return nil, err
	}
	// Signature is over the exact base64url payload segment (parts[0]) so we
	// never depend on canonical JSON re-encoding.
	if !ed25519.Verify(pub, []byte(parts[0]), sig) {
		return nil, ErrSignature
	}
	var p Payload
	if err := json.Unmarshal(payloadRaw, &p); err != nil {
		return nil, ErrMalformed
	}
	if p.Product != Product {
		return nil, ErrProduct
	}
	// Install binding: a bound license only verifies on its installation.
	if p.InstallID != "" && p.InstallID != InstallFingerprint() {
		return nil, ErrInstall
	}
	if p.ExpiresAt != 0 && now.Unix() > p.ExpiresAt {
		return nil, ErrExpired
	}
	return &p, nil
}

// Sign produces a signed license token for the given payload. Used by the
// license-authority signer (it imports this package so the format never drifts
// from verification). Stamps Product automatically.
func Sign(priv ed25519.PrivateKey, p Payload) (string, error) {
	p.Product = Product
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	seg := base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(priv, []byte(seg))
	return seg + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Edition reports CE or EE.
func (m *Manager) Edition() Edition {
	if m != nil && m.valid {
		return EditionEE
	}
	return EditionCE
}

// IsEE reports whether a valid enterprise license is loaded.
func (m *Manager) IsEE() bool { return m != nil && m.valid }

// State reports the precise license state for UI:
//   - "ee"      valid enterprise license
//   - "expired" a token is present but past its expiry (running as CE)
//   - "invalid" a token is present but malformed / bad signature / wrong product
//   - "ce"      no token (Community Edition)
func (m *Manager) State() string {
	switch {
	case m == nil:
		return "ce"
	case m.valid:
		return "ee"
	case m.loadErr == ErrExpired:
		return "expired"
	case m.loadErr == ErrInstall:
		return "mismatch"
	case m.loadErr != nil:
		return "invalid"
	default:
		return "ce"
	}
}

// Has reports whether the given EE feature is unlocked. CE → always false.
func (m *Manager) Has(f Feature) bool {
	if m == nil || !m.valid {
		return false
	}
	return m.features[f]
}

// EnabledFeatures returns the unlocked feature keys (nil for CE). Used by the
// bootstrap endpoint so the frontend can gate EE UI.
func (m *Manager) EnabledFeatures() []Feature {
	if m == nil || !m.valid {
		return nil
	}
	out := make([]Feature, 0, len(m.payload.Features))
	out = append(out, m.payload.Features...)
	return out
}

// Customer returns the licensed customer name (empty for CE).
func (m *Manager) Customer() string {
	if m == nil || m.payload == nil {
		return ""
	}
	return m.payload.Customer
}

// ExpiresAt returns the license expiry (zero time for CE / perpetual).
func (m *Manager) ExpiresAt() time.Time {
	if m == nil || m.payload == nil || m.payload.ExpiresAt == 0 {
		return time.Time{}
	}
	return time.Unix(m.payload.ExpiresAt, 0)
}

// MaxTenants / MaxUsers expose signed limits (0 = unlimited / unset).
func (m *Manager) MaxTenants() int {
	if m == nil || m.payload == nil {
		return 0
	}
	return m.payload.MaxTenants
}
func (m *Manager) MaxUsers() int {
	if m == nil || m.payload == nil {
		return 0
	}
	return m.payload.MaxUsers
}

// LoadErr returns why a supplied token failed verification (nil if CE-by-
// default or a valid license).
func (m *Manager) LoadErr() error {
	if m == nil {
		return nil
	}
	return m.loadErr
}
