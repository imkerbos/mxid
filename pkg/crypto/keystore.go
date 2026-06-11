package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// MasterKey wraps a 256-bit AES master key used to encrypt/decrypt at-rest
// secrets such as OIDC signing private keys. The raw bytes never leave the
// struct; callers go through Encrypt / Decrypt only.
type MasterKey struct {
	raw []byte
}

// NewMasterKey loads a 32-byte AES-256 master key from a base64 string.
// Returns an error if the input is empty, not valid base64, or not 32 bytes long.
//
// Accepts both standard and URL-safe base64, with or without padding, so
// operators can paste whichever variant their secret manager emits.
func NewMasterKey(b64 string) (*MasterKey, error) {
	if b64 == "" {
		return nil, errors.New("master key is empty")
	}
	raw, err := decodeAnyBase64(b64)
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("master key must decode to 32 bytes, got %d", len(raw))
	}
	return &MasterKey{raw: raw}, nil
}

// Encrypt seals the plaintext with AES-256-GCM and returns the base64
// (standard, padded) ciphertext. Layout: nonce || ciphertext || tag.
func (k *MasterKey) Encrypt(plaintext []byte) (string, error) {
	return EncryptAES256GCM(plaintext, k.raw)
}

// Decrypt opens ciphertext produced by Encrypt.
func (k *MasterKey) Decrypt(encoded string) ([]byte, error) {
	return DecryptAES256GCM(encoded, k.raw)
}

func decodeAnyBase64(s string) ([]byte, error) {
	encs := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encs {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}
