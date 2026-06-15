// Package version exposes build-time identity injected via -ldflags at compile
// time. Values stay at their "dev" defaults for plain `go build`; release images
// stamp them from the git tag / commit / build timestamp.
package version

// Injected with: -ldflags "-X github.com/imkerbos/mxid/pkg/version.Version=v1.2.3 ..."
var (
	// Version is the SemVer release tag (e.g. v1.2.3), or "dev" for local builds.
	Version = "dev"
	// Commit is the short git SHA the binary was built from.
	Commit = "none"
	// BuildTime is the RFC3339 UTC build timestamp.
	BuildTime = "unknown"
)

// Info is the structured build identity returned by the /health endpoint.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Get returns the current build identity.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildTime: BuildTime}
}
