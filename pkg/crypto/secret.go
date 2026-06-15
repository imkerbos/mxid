package crypto

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// MaskedSecret is the sentinel returned when a populated Secret is serialized
// to JSON. The plaintext is never emitted, so secret fields cannot leak through
// API responses.
const MaskedSecret = "********"

// secretMasterKey is the process-wide MasterKey used by Secret.Value /
// Secret.Scan, which have no context through which a key could be passed.
// It is configured once at startup via SetSecretMasterKey.
var (
	secretMasterKeyMu sync.RWMutex
	secretMasterKey   *MasterKey
)

// ErrSecretMasterKeyUnset is returned by Secret.Value / Secret.Scan when no
// process MasterKey has been configured via SetSecretMasterKey.
var ErrSecretMasterKeyUnset = errors.New("crypto: secret master key not configured; call SetSecretMasterKey at startup")

// SetSecretMasterKey configures the process-wide MasterKey used to
// encrypt/decrypt Secret values at the database boundary.
//
// Callers MUST invoke this exactly once during startup, before any Secret is
// persisted or loaded (e.g. in bootstrap, right after the MasterKey is
// constructed). Because Secret implements driver.Valuer / sql.Scanner — which
// receive no context — there is no other way to thread the key through GORM.
func SetSecretMasterKey(mk *MasterKey) {
	secretMasterKeyMu.Lock()
	defer secretMasterKeyMu.Unlock()
	secretMasterKey = mk
}

func loadSecretMasterKey() (*MasterKey, error) {
	secretMasterKeyMu.RLock()
	defer secretMasterKeyMu.RUnlock()
	if secretMasterKey == nil {
		return nil, ErrSecretMasterKeyUnset
	}
	return secretMasterKey, nil
}

// Secret is an encrypted-at-rest, never-serialized secret string.
//
// At the database boundary the plaintext is encrypted with the process
// MasterKey (AES-256-GCM) and stored as base64 ciphertext, so it cannot leak
// through DB dumps. At the JSON boundary it serializes to a masked sentinel, so
// it cannot leak through API responses. The plaintext is held only in memory
// and is readable solely via Reveal(), which callers use at explicit, audited
// code paths (e.g. signing, outbound auth).
//
// The zero value is an empty secret. Empty secrets persist as NULL and
// serialize to "".
type Secret struct {
	plaintext string
	set       bool
}

// NewSecret constructs a Secret from a plaintext value. An empty string yields
// an empty (unset) Secret.
func NewSecret(plaintext string) Secret {
	if plaintext == "" {
		return Secret{}
	}
	return Secret{plaintext: plaintext, set: true}
}

// IsZero reports whether the Secret holds no value.
func (s Secret) IsZero() bool {
	return !s.set || s.plaintext == ""
}

// Reveal returns the plaintext secret. This is the ONLY way to read the
// underlying value; use it only on code paths that genuinely need the secret
// (e.g. signing, establishing an outbound connection). Never log the result.
func (s Secret) Reveal() string {
	return s.plaintext
}

// String masks the secret so it cannot leak through fmt / logging. Use Reveal()
// to obtain the plaintext.
func (s Secret) String() string {
	if s.IsZero() {
		return ""
	}
	return MaskedSecret
}

// GoString masks the secret under the %#v verb. Without this, fmt's Go-syntax
// formatting (used by panic dumps and reflexive debug logging) would dump the
// unexported plaintext field verbatim. Mirrors pkg/secure.Secret.GoString.
func (s Secret) GoString() string {
	if s.IsZero() {
		return "crypto.Secret{}"
	}
	return "crypto.Secret{" + MaskedSecret + "}"
}

// Value implements driver.Valuer. It encrypts the plaintext with the process
// MasterKey and returns base64 ciphertext. An empty secret stores as NULL.
func (s Secret) Value() (driver.Value, error) {
	if s.IsZero() {
		return nil, nil
	}
	mk, err := loadSecretMasterKey()
	if err != nil {
		return nil, err
	}
	ciphertext, err := mk.Encrypt([]byte(s.plaintext))
	if err != nil {
		return nil, fmt.Errorf("crypto: encrypt secret: %w", err)
	}
	return ciphertext, nil
}

// Scan implements sql.Scanner. It decrypts base64 ciphertext from the database
// back into the in-memory plaintext. NULL / empty yields an empty secret.
func (s *Secret) Scan(src any) error {
	if src == nil {
		*s = Secret{}
		return nil
	}

	var ciphertext string
	switch v := src.(type) {
	case string:
		ciphertext = v
	case []byte:
		ciphertext = string(v)
	default:
		return fmt.Errorf("crypto: cannot scan %T into Secret", src)
	}

	if ciphertext == "" {
		*s = Secret{}
		return nil
	}

	mk, err := loadSecretMasterKey()
	if err != nil {
		return err
	}
	plaintext, err := mk.Decrypt(ciphertext)
	if err != nil {
		return fmt.Errorf("crypto: decrypt secret: %w", err)
	}
	*s = Secret{plaintext: string(plaintext), set: true}
	return nil
}

// MarshalJSON returns a masked value so the plaintext can never be serialized
// into an API response. An empty secret marshals to "".
func (s Secret) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return json.Marshal("")
	}
	return json.Marshal(MaskedSecret)
}

// UnmarshalJSON accepts an incoming plaintext string, so request DTOs can bind a
// new secret value. The masked sentinel is treated as "no change": it leaves the
// Secret empty rather than storing the sentinel as plaintext, so echoing a
// masked value back never persists garbage.
func (s *Secret) UnmarshalJSON(data []byte) error {
	var plaintext string
	if err := json.Unmarshal(data, &plaintext); err != nil {
		return err
	}
	if plaintext == "" || plaintext == MaskedSecret {
		*s = Secret{}
		return nil
	}
	*s = Secret{plaintext: plaintext, set: true}
	return nil
}
