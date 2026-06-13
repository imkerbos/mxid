package externalidp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/imkerbos/mxid/pkg/crypto"
	"gorm.io/datatypes"
)

// testMasterKey returns a deterministic 32-byte AES-256 key for tests.
func testMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	// 32 zero bytes, base64-encoded.
	mk, err := crypto.NewMasterKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatalf("new master key: %v", err)
	}
	return mk
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	return &Service{masterKey: testMasterKey(t), registry: NewRegistry()}
}

// fakeProvider lets the build/login test assert the provider received the
// decrypted plaintext secret.
type fakeProvider struct{ secret string }

func (fakeProvider) Type() string { return "fake" }
func (fakeProvider) Authorize(context.Context, *AuthorizeRequest) (*AuthorizeResponse, error) {
	return &AuthorizeResponse{URL: "https://example.test/auth"}, nil
}
func (fakeProvider) Exchange(context.Context, *CallbackRequest) (*ExternalIdentity, error) {
	return &ExternalIdentity{}, nil
}

// TestEncryptDecryptRoundTrip: encrypt → store → decrypt yields the original.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	s := newTestService(t)
	raw := []byte(`{"client_id":"abc","client_secret":"s3cr3t","scopes":["read"]}`)

	enc, err := s.encryptConfig(TypeGitHub, raw)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	// At rest the secret must NOT be the plaintext and must carry the enc prefix.
	if strings.Contains(string(enc), "s3cr3t") {
		t.Fatalf("plaintext secret leaked into encrypted config: %s", enc)
	}
	var m map[string]any
	_ = json.Unmarshal(enc, &m)
	if v, _ := m["client_secret"].(string); !strings.HasPrefix(v, encPrefix) {
		t.Fatalf("client_secret not encrypted: %q", v)
	}
	// Non-secret fields untouched.
	if v, _ := m["client_id"].(string); v != "abc" {
		t.Fatalf("client_id mutated: %q", v)
	}

	dec, err := s.decryptConfig(TypeGitHub, enc)
	if err != nil {
		t.Fatalf("decryptConfig: %v", err)
	}
	var dm map[string]any
	_ = json.Unmarshal(dec, &dm)
	if v, _ := dm["client_secret"].(string); v != "s3cr3t" {
		t.Fatalf("round-trip mismatch: got %q want s3cr3t", v)
	}
}

// TestTolerantReadLegacyPlaintext: a legacy plaintext secret (no enc prefix)
// still decrypts (passes through) so existing rows never break login.
func TestTolerantReadLegacyPlaintext(t *testing.T) {
	s := newTestService(t)
	legacy := []byte(`{"app_id":"cli","app_secret":"legacyPlain"}`)

	dec, err := s.decryptConfig(TypeLark, legacy)
	if err != nil {
		t.Fatalf("decryptConfig legacy: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(dec, &m)
	if v, _ := m["app_secret"].(string); v != "legacyPlain" {
		t.Fatalf("tolerant read failed: got %q", v)
	}

	// Re-encrypting a legacy row now produces ciphertext (opportunistic migration).
	enc, err := s.encryptConfig(TypeLark, legacy)
	if err != nil {
		t.Fatalf("encryptConfig legacy: %v", err)
	}
	if strings.Contains(string(enc), "legacyPlain") {
		t.Fatalf("legacy plaintext not encrypted on re-save: %s", enc)
	}
}

// TestMaskedResponseNoPlaintextOrCiphertext: a populated config marshaled to a
// response contains NO plaintext secret AND no ciphertext, only a *_set sentinel.
func TestMaskedResponseNoPlaintextOrCiphertext(t *testing.T) {
	s := newTestService(t)
	raw := []byte(`{"client_id":"abc","client_secret":"s3cr3t"}`)
	enc, err := s.encryptConfig(TypeTeams, raw)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	idp := &ExternalIDP{Type: TypeTeams, Config: datatypes.JSON(enc)}

	out, err := json.Marshal(Mask(idp))
	if err != nil {
		t.Fatalf("marshal masked: %v", err)
	}
	body := string(out)
	if strings.Contains(body, "s3cr3t") {
		t.Fatalf("plaintext secret leaked in response: %s", body)
	}
	if strings.Contains(body, encPrefix) {
		t.Fatalf("ciphertext leaked in response: %s", body)
	}
	if !strings.Contains(body, `"secret_set"`) {
		t.Fatalf("missing secret_set sentinel: %s", body)
	}
	// The secret key must be absent from the masked config; client_id stays.
	var resp struct {
		Config    map[string]any  `json:"config"`
		SecretSet map[string]bool `json:"secret_set"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if _, present := resp.Config["client_secret"]; present {
		t.Fatalf("client_secret present in masked config")
	}
	if resp.Config["client_id"] != "abc" {
		t.Fatalf("client_id missing/altered in masked config")
	}
	if !resp.SecretSet["client_secret"] {
		t.Fatalf("secret_set[client_secret] should be true")
	}
}

// TestBuildDecryptedProviderGetsPlaintext: a provider can still be built/login
// with the decrypted secret (the login path uses buildDecrypted, not the raw
// encrypted row).
func TestBuildDecryptedProviderGetsPlaintext(t *testing.T) {
	s := newTestService(t)
	const want = "s3cr3t"

	var seen string
	s.registry.Register(TypeGitHub, func(idp *ExternalIDP) (Provider, error) {
		var cfg struct {
			ClientSecret string `json:"client_secret"`
		}
		if err := json.Unmarshal(idp.Config, &cfg); err != nil {
			return nil, err
		}
		seen = cfg.ClientSecret
		return fakeProvider{secret: cfg.ClientSecret}, nil
	})

	raw := []byte(`{"client_id":"abc","client_secret":"` + want + `"}`)
	enc, err := s.encryptConfig(TypeGitHub, raw)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	idp := &ExternalIDP{Type: TypeGitHub, Config: datatypes.JSON(enc)}

	if _, err := s.buildDecrypted(idp); err != nil {
		t.Fatalf("buildDecrypted: %v", err)
	}
	if seen != want {
		t.Fatalf("provider got %q, want decrypted %q", seen, want)
	}
	// buildDecrypted must NOT mutate the stored row's ciphertext.
	if strings.Contains(string(idp.Config), want) {
		t.Fatalf("stored row config was decrypted in place: %s", idp.Config)
	}
}

// TestPreserveSecretsKeepsStoredOnEmpty: an Update with an empty/masked secret
// preserves the stored ciphertext; a fresh value replaces it.
func TestPreserveSecretsKeepsStoredOnEmpty(t *testing.T) {
	s := newTestService(t)
	stored, err := s.encryptConfig(TypeGitHub, []byte(`{"client_id":"abc","client_secret":"old"}`))
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}

	// Empty secret → preserve stored ciphertext.
	merged, err := s.preserveSecrets(TypeGitHub, stored, map[string]any{"client_id": "abc", "client_secret": ""})
	if err != nil {
		t.Fatalf("preserveSecrets empty: %v", err)
	}
	mv, _ := merged["client_secret"].(string)
	if !strings.HasPrefix(mv, encPrefix) {
		t.Fatalf("empty secret did not preserve stored ciphertext: %q", mv)
	}
	dec, _ := s.decryptConfig(TypeGitHub, mustJSON(t, merged))
	var dm map[string]any
	_ = json.Unmarshal(dec, &dm)
	if dm["client_secret"] != "old" {
		t.Fatalf("preserved value wrong: %v", dm["client_secret"])
	}

	// Masked sentinel → also preserve.
	merged, err = s.preserveSecrets(TypeGitHub, stored, map[string]any{"client_secret": crypto.MaskedSecret})
	if err != nil {
		t.Fatalf("preserveSecrets masked: %v", err)
	}
	if mv, _ := merged["client_secret"].(string); !strings.HasPrefix(mv, encPrefix) {
		t.Fatalf("masked sentinel did not preserve stored ciphertext: %q", mv)
	}

	// Fresh value → replace.
	merged, err = s.preserveSecrets(TypeGitHub, stored, map[string]any{"client_secret": "new"})
	if err != nil {
		t.Fatalf("preserveSecrets fresh: %v", err)
	}
	if merged["client_secret"] != "new" {
		t.Fatalf("fresh secret not kept: %v", merged["client_secret"])
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
