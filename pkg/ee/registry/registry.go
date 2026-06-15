// Package registry is the extension seam between the public CE product and the
// private EE distribution (github.com/imkerbos/mxid-ee). EE feature packages
// register implementations here from their init(); the CE binary imports none,
// so EE code is physically absent from it — there is nothing to patch out.
//
// The app calls the accessors during startup. With no EE module imported they
// return empty, so CE behaves as if the features don't exist.
package registry

import "github.com/gin-gonic/gin"

// ConsoleMounter mounts EE-only routes onto the authenticated console group
// (/api/v1/console). Register one from an EE package's init().
type ConsoleMounter func(rg *gin.RouterGroup)

var consoleMounters []ConsoleMounter

// RegisterConsole adds an EE console route mounter. Called from EE init().
func RegisterConsole(m ConsoleMounter) {
	if m != nil {
		consoleMounters = append(consoleMounters, m)
	}
}

// ConsoleMounters returns the registered EE console mounters (nil in CE).
func ConsoleMounters() []ConsoleMounter { return consoleMounters }

// registeredFeatures records which code-separated feature keys this binary
// actually carries. An EE feature package calls MarkFeature from its init(); the
// CE binary imports none, so the set stays empty. /system/info uses it to avoid
// advertising a license-unlocked feature whose code isn't in this binary (e.g. a
// CE image with an EE license still 404s external_idp).
var registeredFeatures = map[string]bool{}

// MarkFeature records that the named code-separated feature is built into this
// binary. Idempotent. Called from an EE package's init().
func MarkFeature(key string) {
	if key != "" {
		registeredFeatures[key] = true
	}
}

// IsFeatureRegistered reports whether a code-separated feature is present in
// this binary (false in CE for everything).
func IsFeatureRegistered(key string) bool { return registeredFeatures[key] }

// RegisteredFeatures returns the code-separated feature keys built into this
// binary (empty in CE). The app passes this to /system/info so it advertises
// only features whose code is actually present.
func RegisteredFeatures() []string {
	out := make([]string, 0, len(registeredFeatures))
	for k := range registeredFeatures {
		out = append(out, k)
	}
	return out
}
