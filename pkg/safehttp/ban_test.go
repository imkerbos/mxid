package safehttp_test

// This test is an SSRF-regression guard. It walks the repository source tree and
// FAILS if any server-side .go file uses http.DefaultClient or http.Get(, which
// bypass the SSRF protections in pkg/safehttp. Every attacker-influenced
// outbound fetch must go through safehttp.New(...). New legitimate uses of these
// stdlib calls must be added to the allow-list below WITH a justification.
//
// The walk is anchored at the module root (found by ascending to the dir holding
// go.mod) so it covers the whole server, not just this package.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedSubstrings are the stdlib outbound-HTTP entry points that skip the
// safehttp guard. http.DefaultClient follows redirects and applies no IP guard;
// http.Get / http.Post use http.DefaultClient under the hood.
var bannedSubstrings = []string{
	"http.DefaultClient",
	"http.Get(",
	"http.Post(",
	"http.PostForm(",
	"http.Head(",
}

// allowedFiles is the explicit exception list, keyed by module-relative path.
// Each entry MUST be justified. Anything not listed here that trips a banned
// substring fails the test.
var allowedFiles = map[string]string{
	// safehttp itself is the guarded client; it legitimately references
	// http.DefaultClient/etc. in docs/tests.
	"pkg/safehttp/safehttp.go":      "the guarded client implementation",
	"pkg/safehttp/safehttp_test.go": "tests for the guarded client",
	"pkg/safehttp/ban_test.go":      "this regression test references the banned strings",

	// SMS providers: HOST is a hardcoded constant cloud endpoint
	// (api.twilio.com / dysmsapi.aliyuncs.com / sms.tencentcloudapi.com); admin
	// config only affects path/query, never the authority — no SSRF surface.
	"pkg/sms/twilio.go":  "constant host api.twilio.com; admin input never alters authority",
	"pkg/sms/aliyun.go":  "constant host dysmsapi.aliyuncs.com; admin input never alters authority",
	"pkg/sms/tencent.go": "constant host sms.tencentcloudapi.com; admin input never alters authority",

	// Dev/test CLI binary, not part of the server runtime SSRF surface.
	"tools/saml-sp-test/main.go": "dev/test CLI binary, flag-driven, not admin-config-driven",
}

func TestNoUnguardedOutboundHTTP(t *testing.T) {
	root := moduleRoot(t)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip vendored deps and VCS metadata.
			base := info.Name()
			if base == "vendor" || base == ".git" || base == "node_modules" || base == "web" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		content := string(data)

		for _, banned := range bannedSubstrings {
			if !strings.Contains(content, banned) {
				continue
			}
			if _, ok := allowedFiles[rel]; ok {
				continue
			}
			t.Errorf("%s uses banned outbound-HTTP call %q which bypasses the safehttp SSRF guard. "+
				"Route the fetch through safehttp.New(...), or if the host is a genuine hardcoded "+
				"constant add the file to allowedFiles in ban_test.go with a justification.", rel, banned)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking source tree: %v", err)
	}
}

// moduleRoot ascends from the current working directory until it finds the dir
// containing go.mod (the module root).
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod from %s", dir)
		}
		dir = parent
	}
}
