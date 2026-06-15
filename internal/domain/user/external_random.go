package user

import "crypto/rand"

// randReadDummy isolates the crypto/rand dependency so the auto-provisioning
// dummy-hash helper in external_login.go doesn't pull rand into its core
// imports.
func randReadDummy(b []byte) (int, error) { return rand.Read(b) }
