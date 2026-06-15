package oidcop

import (
	"crypto/rsa"

	jose "github.com/go-jose/go-jose/v4"
)

// signingKey adapts an oidckey active key to op.SigningKey (signs new tokens).
type signingKey struct {
	id  string
	alg jose.SignatureAlgorithm
	key *rsa.PrivateKey
}

func (s signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return s.alg }
func (s signingKey) Key() any                                    { return s.key }
func (s signingKey) ID() string                                  { return s.id }

// publicKey adapts an oidckey verification key to op.Key (published in JWKS).
type publicKey struct {
	id  string
	alg jose.SignatureAlgorithm
	key *rsa.PublicKey
}

func (p publicKey) ID() string                         { return p.id }
func (p publicKey) Algorithm() jose.SignatureAlgorithm { return p.alg }
func (p publicKey) Use() string                        { return "sig" }
func (p publicKey) Key() any                           { return p.key }

// joseAlg maps our stored algorithm string to a go-jose signature algorithm,
// defaulting to RS256 (the only algorithm oidckey mints today).
func joseAlg(alg string) jose.SignatureAlgorithm {
	switch alg {
	case "RS384":
		return jose.RS384
	case "RS512":
		return jose.RS512
	default:
		return jose.RS256
	}
}
