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
