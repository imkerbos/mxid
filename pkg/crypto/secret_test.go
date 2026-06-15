package crypto

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// newTestMasterKey builds a valid 32-byte AES-256 MasterKey for tests.
func newTestMasterKey(t *testing.T) *MasterKey {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("read random key: %v", err)
	}
	mk, err := NewMasterKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("new master key: %v", err)
	}
	return mk
}

// configureTestMasterKey installs a process master key and restores the prior
// one when the test finishes, so tests do not leak global state.
func configureTestMasterKey(t *testing.T, mk *MasterKey) {
	t.Helper()
	secretMasterKeyMu.RLock()
	prev := secretMasterKey
	secretMasterKeyMu.RUnlock()
	SetSecretMasterKey(mk)
	t.Cleanup(func() { SetSecretMasterKey(prev) })
}

func TestSecretValueScanRoundTrip(t *testing.T) {
	configureTestMasterKey(t, newTestMasterKey(t))

	tests := []struct {
		name      string
		plaintext string
	}{
		{name: "simple", plaintext: "s3cr3t"},
		{name: "client secret style", plaintext: "AbCdEf_-1234567890ZZZ"},
		{name: "unicode", plaintext: "пароль-密码-🔐"},
		{name: "long", plaintext: strings.Repeat("x", 4096)},
		{name: "whitespace preserved", plaintext: "  leading and trailing  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := NewSecret(tt.plaintext)

			v, err := orig.Value()
			if err != nil {
				t.Fatalf("Value: %v", err)
			}
			ciphertext, ok := v.(string)
			if !ok {
				t.Fatalf("Value returned %T, want string", v)
			}
			if ciphertext == "" {
				t.Fatal("Value returned empty ciphertext for non-empty secret")
			}
			if strings.Contains(ciphertext, tt.plaintext) {
				t.Fatalf("ciphertext leaks plaintext: %q", ciphertext)
			}

			var got Secret
			if err := got.Scan(ciphertext); err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got.Reveal() != tt.plaintext {
				t.Fatalf("round-trip mismatch: got %q want %q", got.Reveal(), tt.plaintext)
			}
		})
	}
}

func TestSecretScanByteSlice(t *testing.T) {
	configureTestMasterKey(t, newTestMasterKey(t))

	orig := NewSecret("from-bytes")
	v, err := orig.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	ciphertext := v.(string)

	var got Secret
	if err := got.Scan([]byte(ciphertext)); err != nil {
		t.Fatalf("Scan []byte: %v", err)
	}
	if got.Reveal() != "from-bytes" {
		t.Fatalf("got %q want %q", got.Reveal(), "from-bytes")
	}
}

func TestSecretMarshalJSONNeverLeaksPlaintext(t *testing.T) {
	configureTestMasterKey(t, newTestMasterKey(t))

	const plaintext = "super-secret-signing-key-DO-NOT-LEAK"
	s := NewSecret(plaintext)

	// Marshal the Secret directly and inside a struct (the realistic DTO case).
	direct, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal direct: %v", err)
	}
	type dto struct {
		Name   string `json:"name"`
		Secret Secret `json:"secret"`
	}
	nested, err := json.Marshal(dto{Name: "app", Secret: s})
	if err != nil {
		t.Fatalf("marshal nested: %v", err)
	}

	for _, out := range []string{string(direct), string(nested)} {
		if strings.Contains(out, plaintext) {
			t.Fatalf("JSON output leaks plaintext: %s", out)
		}
		if !strings.Contains(out, MaskedSecret) {
			t.Fatalf("JSON output missing mask sentinel: %s", out)
		}
	}
}

func TestSecretStringMasks(t *testing.T) {
	const plaintext = "do-not-print-me"
	s := NewSecret(plaintext)
	if got := s.String(); got != MaskedSecret {
		t.Fatalf("String() = %q, want mask", got)
	}
	if strings.Contains(s.String(), plaintext) {
		t.Fatalf("String() leaks plaintext: %q", s.String())
	}
	if got := NewSecret("").String(); got != "" {
		t.Fatalf("empty String() = %q, want \"\"", got)
	}
}

func TestSecretGoStringMasks(t *testing.T) {
	const plaintext = "GOSTRING-LEAK-CANARY"
	s := NewSecret(plaintext)
	// %#v (Go-syntax) must not dump the unexported plaintext field.
	for _, v := range []string{
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%#v", &s),
		fmt.Sprintf("%#v", struct{ S Secret }{s}),
	} {
		if strings.Contains(v, plaintext) {
			t.Fatalf("%%#v leaks plaintext: %q", v)
		}
	}
	if got := NewSecret("").GoString(); got != "crypto.Secret{}" {
		t.Fatalf("empty GoString() = %q", got)
	}
}

func TestSecretUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantVal string
		wantZero bool
	}{
		{name: "plaintext", input: `"new-secret-value"`, wantVal: "new-secret-value"},
		{name: "empty string", input: `""`, wantZero: true},
		{name: "masked sentinel is no-op", input: `"` + MaskedSecret + `"`, wantZero: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s Secret
			if err := json.Unmarshal([]byte(tt.input), &s); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if tt.wantZero {
				if !s.IsZero() {
					t.Fatalf("expected zero secret, got reveal=%q", s.Reveal())
				}
				return
			}
			if s.IsZero() {
				t.Fatal("expected populated secret, got zero")
			}
			if s.Reveal() != tt.wantVal {
				t.Fatalf("Reveal() = %q, want %q", s.Reveal(), tt.wantVal)
			}
		})
	}
}

func TestSecretUnmarshalRoundTripThroughDTO(t *testing.T) {
	configureTestMasterKey(t, newTestMasterKey(t))

	type dto struct {
		Secret Secret `json:"secret"`
	}
	var d dto
	if err := json.Unmarshal([]byte(`{"secret":"bound-from-request"}`), &d); err != nil {
		t.Fatalf("unmarshal dto: %v", err)
	}
	if d.Secret.Reveal() != "bound-from-request" {
		t.Fatalf("Reveal() = %q", d.Secret.Reveal())
	}
	// The bound secret must still persist/round-trip correctly.
	v, err := d.Secret.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	var back Secret
	if err := back.Scan(v); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if back.Reveal() != "bound-from-request" {
		t.Fatalf("round-trip Reveal() = %q", back.Reveal())
	}
}

func TestSecretEmptyHandling(t *testing.T) {
	configureTestMasterKey(t, newTestMasterKey(t))

	t.Run("zero value Value is NULL", func(t *testing.T) {
		var s Secret
		v, err := s.Value()
		if err != nil {
			t.Fatalf("Value: %v", err)
		}
		if v != nil {
			t.Fatalf("Value = %v, want nil for empty secret", v)
		}
	})

	t.Run("NewSecret empty is NULL", func(t *testing.T) {
		v, err := NewSecret("").Value()
		if err != nil {
			t.Fatalf("Value: %v", err)
		}
		if v != nil {
			t.Fatalf("Value = %v, want nil", v)
		}
	})

	t.Run("Scan nil yields empty", func(t *testing.T) {
		s := NewSecret("had-a-value")
		if err := s.Scan(nil); err != nil {
			t.Fatalf("Scan nil: %v", err)
		}
		if !s.IsZero() {
			t.Fatal("expected zero after Scan(nil)")
		}
	})

	t.Run("Scan empty string yields empty", func(t *testing.T) {
		var s Secret
		if err := s.Scan(""); err != nil {
			t.Fatalf("Scan empty: %v", err)
		}
		if !s.IsZero() {
			t.Fatal("expected zero after Scan(\"\")")
		}
	})

	t.Run("empty marshals to empty string", func(t *testing.T) {
		out, err := json.Marshal(NewSecret(""))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(out) != `""` {
			t.Fatalf("marshal empty = %s, want \"\"", out)
		}
	})
}

func TestSecretRevealReturnsPlaintext(t *testing.T) {
	s := NewSecret("plaintext-here")
	if s.Reveal() != "plaintext-here" {
		t.Fatalf("Reveal() = %q", s.Reveal())
	}
	if NewSecret("").Reveal() != "" {
		t.Fatalf("empty Reveal() = %q, want \"\"", NewSecret("").Reveal())
	}
}

func TestSecretMasterKeyUnset(t *testing.T) {
	// Force the unset state for this test and restore afterwards.
	configureTestMasterKey(t, nil)

	if _, err := NewSecret("x").Value(); err != ErrSecretMasterKeyUnset {
		t.Fatalf("Value err = %v, want ErrSecretMasterKeyUnset", err)
	}
	var s Secret
	if err := s.Scan("some-ciphertext"); err != ErrSecretMasterKeyUnset {
		t.Fatalf("Scan err = %v, want ErrSecretMasterKeyUnset", err)
	}
}

func TestSecretScanUnsupportedType(t *testing.T) {
	configureTestMasterKey(t, newTestMasterKey(t))
	var s Secret
	if err := s.Scan(12345); err == nil {
		t.Fatal("expected error scanning int")
	}
}

// Compile-time assertions that Secret satisfies the required interfaces.
var (
	_ driver.Valuer = Secret{}
	_ json.Marshaler = Secret{}
)
