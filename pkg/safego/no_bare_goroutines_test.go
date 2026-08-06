package safego_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Production code must not start a goroutine without a recover.
//
// This guard exists because the rule is only worth as much as its weakest call
// site. A deployment sat in CrashLoopBackOff because ONE goroutine — written
// before the rule — let a panic reach the runtime, which terminates the whole
// process. Restarting did not help: the row that triggered it was still there.
// Every login in the installation was down until somebody found and deleted the
// data.
//
// A comment saying "use safego" would not have caught it. Nine more bare
// goroutines were found by grep afterwards, in code written by people who knew
// the rule. So the check runs.
//
// To exempt a line, put `//safego:ok <reason>` on it or the line above. The
// reason is required: the exemptions that are actually fine (waiting on a
// WaitGroup, a body already wrapped in safego.Run) are all one-liners whose
// justification fits, and anything that needs a paragraph is not an exemption.
var bareGoroutine = regexp.MustCompile(`(^|\s)go func\(`)

const exemption = "//safego:ok"

func TestNoBareGoroutinesInProductionCode(t *testing.T) {
	root := repoRoot(t)
	var findings []string

	for _, dir := range []string{"app", "internal", "pkg", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// safego itself is where the recover lives.
			if strings.Contains(path, filepath.Join("pkg", "safego")) {
				return nil
			}
			src, err := os.ReadFile(path) //nolint:gosec // walking our own tree
			if err != nil {
				return err
			}
			lines := strings.Split(string(src), "\n")
			for i, line := range lines {
				if !bareGoroutine.MatchString(line) {
					continue
				}
				if strings.Contains(line, exemption) {
					continue
				}
				if i > 0 && strings.Contains(lines[i-1], exemption) {
					continue
				}
				rel, _ := filepath.Rel(root, path)
				findings = append(findings, rel+":"+itoa(i+1)+"  "+strings.TrimSpace(line))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if len(findings) > 0 {
		t.Errorf("bare goroutine(s) — a panic in any of these terminates the whole "+
			"process, taking every login down with it:\n  %s\n\n"+
			"Use safego.Go(logger, name, fn), or App.SpawnWorker for a long-lived "+
			"worker that shutdown must wait for. If the goroutine genuinely cannot "+
			"panic (waiting on a WaitGroup, a body already inside safego.Run), mark "+
			"it `%s <reason>`.",
			strings.Join(findings, "\n  "), exemption)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// repoRoot walks up from the test's working directory to the module root.
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
