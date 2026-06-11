package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// publicCertToJWK projects a resolver.CertConfig into a JWK Set entry per
// RFC 7517 §4 + RFC 7518 §6.3 (RSA public key parameters).
//
// Only the public key fields are emitted; private material never leaves
// the server.
func publicCertToJWK(cert *resolver.CertConfig) (gin.H, error) {
	pub, err := parseRSAPublicKey([]byte(cert.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	kid := cert.KID
	if kid == "" {
		// Fall back to numeric cert ID; preserves backward compat with legacy
		// records that pre-date the kid column.
		kid = fmt.Sprintf("%d", cert.ID)
	}
	alg := cert.Algorithm
	if alg == "" {
		alg = "RS256"
	}
	return gin.H{
		"kty": "RSA",
		"use": "sig",
		"alg": alg,
		"kid": kid,
		"n":   base64URLEncodeBigInt(pub.N),
		"e":   base64URLEncodeInt(pub.E),
	}, nil
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		return rsaKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		// X.509 cert wrapping an RSA pubkey. Used by SAML/CAS apps so the
		// IdP metadata can carry a real <ds:X509Certificate>; the inner RSA
		// key is what OIDC JWKS / id_token verification needs.
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("cert public key is not RSA")
		}
		return rsaKey, nil
	}
	return nil, fmt.Errorf("unsupported pem type: %s", block.Type)
}

func base64URLEncodeInt(i int) string {
	b := big.NewInt(int64(i)).Bytes()
	return base64.RawURLEncoding.EncodeToString(b)
}
