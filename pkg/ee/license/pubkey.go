package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

// vendorPublicKeyB64 is the embedded Ed25519 public key that verifies license
// signatures. It is intentionally HARDCODED (not env-configurable): allowing an
// operator to swap it would let them forge any license. The matching private
// key is held offline by the vendor (see cmd/license-sign).
//
// DEV KEY — this is a development key pair generated for local testing. Before
// any real release, generate the production vendor key in the private license
// repo and replace this constant with its public half.
const vendorPublicKeyB64 = "kDytldykOxFOttul68P706SGTkiiK23HKrnQ7EITBbo="

func publicKey() (ed25519.PublicKey, error) {
	if vendorPublicKeyB64 == "" {
		return nil, errors.New("license: no vendor public key embedded")
	}
	raw, err := base64.StdEncoding.DecodeString(vendorPublicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("license: bad embedded public key")
	}
	return ed25519.PublicKey(raw), nil
}
