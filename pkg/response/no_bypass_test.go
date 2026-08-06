package response_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every error response must go through this package.
//
// The response envelope is {code, message, data, traceId}, and the traceId is
// the only handle anyone has for finding the matching server log line. Writing
// a body by hand skips it: a 500 then arrives as a bare status with no code, no
// message and nothing to quote, and the SPA can only fall back to axios'
// "Request failed with status code 500". That is what a customer saw for a
// panic whose stack was sitting in the log the whole time.
//
// Seventeen call sites had drifted this way — authz, tenant, rate-limit and
// CSRF middleware, plus the panic recovery — each one a place where an error
// silently lost its request id. The convention existed; nothing enforced it.
var (
	bypassCall  = regexp.MustCompile(`c\.AbortWithStatusJSON\(|c\.AbortWithStatus\(`)
	literalCode = regexp.MustCompile(`"code":\s*\d{5}`)
)

const exemption = "//response:ok"

func TestNoHandWrittenErrorResponses(t *testing.T) {
	root := repoRoot(t)
	var findings []string

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
			// This package IS the sanctioned writer.
			if strings.Contains(path, filepath.Join("pkg", "response")) {
				return nil
			}
			src, err := os.ReadFile(path) //nolint:gosec // walking our own tree
			if err != nil {
				return err
			}
			lines := strings.Split(string(src), "\n")
			for i, line := range lines {
				hit := bypassCall.MatchString(line) || literalCode.MatchString(line)
				if !hit || strings.Contains(line, exemption) {
					continue
				}
				if i > 0 && strings.Contains(lines[i-1], exemption) {
					continue
				}
				rel, _ := filepath.Rel(root, path)
				findings = append(findings, rel+":"+strconv.Itoa(i+1)+"  "+strings.TrimSpace(line))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if len(findings) > 0 {
		t.Errorf("error response written by hand — it carries no traceId, so the "+
			"server log line for it cannot be found:\n  %s\n\n"+
			"Use response.BadRequest / Forbidden / InternalError / Error, and a "+
			"catalogued errcode.Num* rather than a numeric literal. If a bare "+
			"status genuinely is the whole response (a 204, a redirect), mark it "+
			"`%s <reason>`.",
			strings.Join(findings, "\n  "), exemption)
	}
}

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
