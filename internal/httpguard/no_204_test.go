package httpguard

// Every write API answers with the {code,message,data} envelope. A 204 carries
// no body, so the SPA's success interceptor reads `data.code` off an empty
// string, sees undefined, and reports a successful delete as "删除失败" — the
// exact defect that cost a user their Lark login on 2026-08-10. This guard
// fails the build if a 204 ever reappears in a handler.
//
// Scope: the same {app, internal, pkg, cmd} set pkg/response's no-bypass guard
// walks. Handlers are not confined to internal/ — app/ registers routes and
// closures of its own, and a 204 written there would have been invisible here.
//
// Exemption: the repo-wide `//response:ok <reason>` marker, on the line itself
// or the line above, exactly as pkg/response/no_bypass_test.go reads it. The
// previous hardcoded path allow-list named internal/middleware/cors.go, which
// already carries that marker — one convention, in the file it is about,
// instead of two lists to keep in sync.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const exemption = "//response:ok"

// A 204 is written several ways. StatusNoContent is the idiomatic one, but gin
// takes a bare int just as happily, and `c.JSON(204, …)` / `c.Status(204)` slid
// straight past a match on the constant's name.
var noContentWrite = regexp.MustCompile(
	`StatusNoContent|response\.NoContent\(|c\.JSON\(\s*204|c\.Status\(\s*204|` +
		`c\.AbortWithStatus\(\s*204|c\.AbortWithStatusJSON\(\s*204|WriteHeader\(\s*204`)

func TestNoHandlerAnswers204(t *testing.T) {
	root := repoRoot(t)
	var offenders []string

	for _, dir := range []string{"app", "internal", "pkg", "cmd"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path) //nolint:gosec // walking our own tree
			if rerr != nil {
				return rerr
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			lines := strings.Split(string(src), "\n")
			for i, line := range lines {
				if !noContentWrite.MatchString(line) || strings.Contains(line, exemption) {
					continue
				}
				if i > 0 && strings.Contains(lines[i-1], exemption) {
					continue
				}
				offenders = append(offenders, rel+":"+strconv.Itoa(i+1)+" "+strings.TrimSpace(line))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("handlers must answer with the {code,message,data} envelope, not 204.\n"+
			"Use response.OK(c, nil) instead. If a bare 204 genuinely IS the whole "+
			"response (a CORS preflight), mark it `%s <reason>`. Offenders:\n  %s",
			exemption, strings.Join(offenders, "\n  "))
	}
}

// repoRoot walks up to the module root so the guard is independent of the
// package's own depth. Same helper shape as pkg/response/no_bypass_test.go.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}
