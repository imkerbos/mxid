package crypto

import (
	"crypto/rand"
	"math/big"
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// GenerateBase62 returns a cryptographically-random base62 string of the
// requested length. ~5.95 bits of entropy per character.
func GenerateBase62(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	alphaLen := big.NewInt(int64(len(base62Alphabet)))
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, alphaLen)
		if err != nil {
			return "", err
		}
		out[i] = base62Alphabet[n.Int64()]
	}
	return string(out), nil
}

// GenerateClientID returns an OIDC client_id of the form "client_" + 22 base62
// characters (≈ 131 bits of entropy), matching the Auth0 / Okta convention.
func GenerateClientID() (string, error) {
	suffix, err := GenerateBase62(22)
	if err != nil {
		return "", err
	}
	return "client_" + suffix, nil
}

// GenerateClientSecret returns 48 random bytes encoded as URL-safe base64
// (≈ 64 characters), to be returned to the caller once at create / rotate
// time and stored only in bcrypt-hashed form.
func GenerateClientSecret() (string, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// URL-safe base64 without padding
	return base64URLNoPad(b), nil
}

// GenerateOpaqueToken returns n random bytes encoded as URL-safe base64
// without padding. Used for authorization codes (n=32) and refresh tokens (n=64).
func GenerateOpaqueToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64URLNoPad(b), nil
}

func base64URLNoPad(b []byte) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// Standard base64 emit without padding.
	enc := make([]byte, 0, (len(b)+2)/3*4)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		switch len(b) - i {
		case 1:
			n = uint32(b[i]) << 16
			enc = append(enc, table[(n>>18)&0x3F], table[(n>>12)&0x3F])
		case 2:
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8
			enc = append(enc, table[(n>>18)&0x3F], table[(n>>12)&0x3F], table[(n>>6)&0x3F])
		default:
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
			enc = append(enc, table[(n>>18)&0x3F], table[(n>>12)&0x3F], table[(n>>6)&0x3F], table[n&0x3F])
		}
	}
	return string(enc)
}
