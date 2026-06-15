package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

// macKey derives the installation fingerprint. Fixed forever — changing it
// invalidates every install-bound license. In the EE binary it is garble-
// obfuscated; HMAC preimage-resistance keeps binding sound even if it leaks
// (an attacker still cannot make a different install hash to a target id).
const macKey = "mxid:fp:v1:Q7$kP2!xR9#vL6@nW4*dZ8&hJ3%sT5^"

// Fingerprint derives this installation's identity from a per-install UUID
// (stored in the DB) and the PostgreSQL cluster's system_identifier (unique per
// cluster). Copying the license + a DB dump to a different cluster yields a
// different system_identifier → a different fingerprint → the bound license no
// longer verifies.
//
//	fingerprint = HMAC-SHA256(macKey, install_uuid | system_identifier)[:32]
func Fingerprint(installUUID string, systemIdentifier uint64) string {
	h := hmac.New(sha256.New, []byte(macKey))
	h.Write([]byte(installUUID))
	h.Write([]byte("|"))
	fmt.Fprintf(h, "%d", systemIdentifier)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// installFP holds this process's fingerprint, set once at boot. Empty until set
// (then install-bound licenses can't be verified — they stay portable-only).
var installFP atomic.Pointer[string]

// SetInstallFingerprint installs the current installation fingerprint, used to
// verify install-bound licenses.
func SetInstallFingerprint(fp string) { installFP.Store(&fp) }

// InstallFingerprint returns this installation's fingerprint (empty if unset).
// The console shows it so an operator can request an install-bound license.
func InstallFingerprint() string {
	if p := installFP.Load(); p != nil {
		return *p
	}
	return ""
}
