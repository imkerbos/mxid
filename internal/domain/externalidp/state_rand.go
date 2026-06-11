package externalidp

import (
	"crypto/rand"
	"encoding/base64"
)

// Small indirection over crypto/rand + base64 url-encoding so the
// service.go state token mint stays compact. Kept in its own file so the
// imports don't leak into other concerns.
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

func base64URL(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}
