package saml

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// SignOptions carries an app's signing material (active key + cert PEM) loaded
// from the cert store. crewjam/saml does the actual XML signing; this just
// transports the key/cert from loadSignOptions to loadKeyAndCert.
type SignOptions struct {
	Key     *rsa.PrivateKey
	CertPEM string
}

// pemCertBytes extracts the DER bytes from a PEM CERTIFICATE block, accepting a
// raw base64 blob too (no BEGIN/END armor) for the case where an operator
// pasted just the metadata value.
func pemCertBytes(certPEM string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		return block.Bytes, nil
	}
	clean := bytes.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		}
		return r
	}, []byte(certPEM))
	der, err := base64.StdEncoding.DecodeString(string(clean))
	if err != nil {
		return nil, fmt.Errorf("not a PEM certificate and not base64: %w", err)
	}
	return der, nil
}
