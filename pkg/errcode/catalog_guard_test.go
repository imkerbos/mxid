package errcode_test

// These are the enforcement half of catalog.go. Comments had already failed at
// this job three times, so the rules live in a test.

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/imkerbos/mxid/pkg/errcode"
)

// scanRoots are the Go trees that may emit an API error response.
var scanRoots = []string{"internal", "app", "pkg"}

// Two shapes to match, because response.Error takes the HTTP status first and
// the business code second, while every other helper takes the code first.
// Reading the wrong argument is not academic: the first mechanical pass over
// this codebase rewrote three `response.Error(c, 429, ...)` HTTP statuses as
// business codes because it did not distinguish them.
var (
	responseErrorCall = regexp.MustCompile(`response\.Error\(c,\s*[A-Za-z0-9_.]+,\s*([A-Za-z0-9_.]+),\s*([^,)]*)`)
	responseCall      = regexp.MustCompile(`response\.(?:[A-Za-z]+)\(c,\s*([A-Za-z0-9_.]+),\s*([^,)]*)`)
)

// codeUse is one response-helper call: which code it passes, and the message
// argument that follows it.
type codeUse struct {
	arg     string
	message string
}

// codeUses parses the response helper calls on a line. The message is captured
// as written (a quoted literal, or an expression such as err.Error()), which is
// enough to tell "same refusal from two paths" from "two unrelated refusals".
func codeUses(line string) []codeUse {
	re := responseCall
	if responseErrorCall.MatchString(line) {
		re = responseErrorCall
	}
	var out []codeUse
	for _, g := range re.FindAllStringSubmatch(line, -1) {
		out = append(out, codeUse{arg: g[1], message: strings.TrimSpace(g[2])})
	}
	return out
}

// codeArgs returns just the code arguments.
func codeArgs(line string) []string {
	uses := codeUses(line)
	out := make([]string, 0, len(uses))
	for _, u := range uses {
		out = append(out, u.arg)
	}
	return out
}

// A bare numeric code at a call site is what let 40003 and 40010 be reused: the
// number carries no hint that the SPA has claimed it. Every call must name a
// catalogued constant instead.
func TestNoNumericCodeLiteralsAtCallSites(t *testing.T) {
	forEachSourceLine(t, func(rel string, lineNo int, line string) {
		for _, arg := range codeArgs(line) {
			if _, err := strconv.Atoi(arg); err != nil {
				continue // a name, not a literal
			}
			t.Errorf("%s:%d passes the bare numeric code %s. Some numbers are "+
				"localized — the SPA discards the server message and renders a fixed "+
				"sentence for them — so a hand-picked number can silently show the user "+
				"the wrong text. Use the named constant from pkg/errcode/catalog.go, "+
				"adding one there if the code is new.", rel, lineNo, arg)
		}
	})
}

// Every constant referenced at a call site must be catalogued. This is the step
// that forces whoever adds a code to look at the localized list.
func TestEveryReferencedCodeIsCatalogued(t *testing.T) {
	byName := map[string]int{}
	for num := range errcode.Catalog {
		byName[constNameFor(num)] = num
	}

	forEachSourceLine(t, func(rel string, lineNo int, line string) {
		for _, arg := range codeArgs(line) {
			name, ok := strings.CutPrefix(arg, "errcode.")
			if !ok {
				continue // a local alias or a variable; out of scope for this check
			}
			if _, known := byName[name]; !known {
				t.Errorf("%s:%d uses errcode.%s, which is not in Catalog. "+
					"Add it to pkg/errcode/catalog.go with its Kind so the localized-code "+
					"collision guard can see it.", rel, lineNo, name)
			}
		}
	})
}

// A localized code stands for one fixed sentence, so it must carry one meaning.
// Several call sites are fine when they are the same refusal raised from
// different paths — what is not fine is the same localized code attached to
// different messages, because then at most one of them matches the sentence the
// user actually sees.
//
// This is the check that found three live instances on its first run: 40005
// ("new password matches a recent one") was also emitted for a disabled login
// method and for a missing TOTP code.
func TestLocalizedCodesCarryOneMeaning(t *testing.T) {
	// constant name -> message text -> the sites using it
	byMessage := map[string]map[string][]string{}
	forEachSourceLine(t, func(rel string, lineNo int, line string) {
		for _, use := range codeUses(line) {
			name, ok := strings.CutPrefix(use.arg, "errcode.")
			if !ok {
				continue
			}
			if byMessage[name] == nil {
				byMessage[name] = map[string][]string{}
			}
			// A non-literal message (err.Error() and friends) is keyed per site,
			// not by its text. Two sites both writing err.Error() are two
			// different errors, and bucketing them together made this check miss
			// a real collision when it was first written: a disabled-login-method
			// refusal shared 40005 with the password-reuse one, both dynamic.
			// Passing a dynamic message with a localized code is itself a smell —
			// the SPA throws it away.
			key := use.message
			if !strings.HasPrefix(key, `"`) {
				key = "<dynamic:" + key + "> @ " + rel + ":" + strconv.Itoa(lineNo)
			}
			byMessage[name][key] = append(byMessage[name][key], rel+":"+strconv.Itoa(lineNo))
		}
	})

	for num, entry := range errcode.Catalog {
		if entry.Kind != errcode.Localized {
			continue
		}
		name := constNameFor(num)
		msgs := byMessage[name]
		if len(msgs) <= 1 {
			continue
		}
		var detail []string
		for msg, sites := range msgs {
			detail = append(detail, msg+" @ "+strings.Join(sites, ", "))
		}
		sort.Strings(detail)
		t.Errorf("localized code %d (errcode.%s, %q) is emitted with %d different messages:\n  %s\n"+
			"The SPA discards these messages and renders one fixed sentence, so all but one of "+
			"these show the user text about something else. Give the others a generic code.",
			num, name, entry.Desc, len(msgs), strings.Join(detail, "\n  "))
	}
}

// The localized set is a contract with the SPA, and half-applying a change to it
// is silent: the backend emits a number the frontend does not localize (user
// sees raw English) or the frontend localizes a number the backend reuses
// generically (user sees an unrelated sentence). Both sides must move together.
func TestLocalizedSetMatchesTheFrontend(t *testing.T) {
	root := moduleRoot(t)
	path := filepath.Join(root, "web/packages/shared/src/ui/toast.tsx")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("frontend not present in this checkout: %v", err)
	}

	feCodes := parseLocalizedCodes(t, root, string(src))
	goCodes := map[int]bool{}
	for num, e := range errcode.Catalog {
		if e.Kind == errcode.Localized {
			goCodes[num] = true
		}
	}

	for num := range goCodes {
		if !feCodes[num] {
			t.Errorf("catalog.go marks %d as Localized but toast.tsx LOCALIZED_CODES has no entry: "+
				"the user will see the raw server message where a translated one was intended", num)
		}
	}
	for num := range feCodes {
		if !goCodes[num] {
			t.Errorf("toast.tsx LOCALIZED_CODES localizes %d but catalog.go does not mark it Localized: "+
				"any generic reuse of %d will show that fixed sentence instead of the real error",
				num, num)
		}
	}
}

// parseLocalizedCodes extracts the numeric keys of LOCALIZED_CODES. One entry is
// written as a computed key ([CODE_EE_FEATURE_REQUIRED]), so its value is
// resolved from client.ts rather than assumed.
func parseLocalizedCodes(t *testing.T, root, src string) map[int]bool {
	t.Helper()
	start := strings.Index(src, "LOCALIZED_CODES")
	if start < 0 {
		t.Fatal("LOCALIZED_CODES not found in toast.tsx — the guard cannot verify the contract")
	}
	open := strings.Index(src[start:], "{")
	end := strings.Index(src[start:], "\n}")
	if open < 0 || end < 0 {
		t.Fatal("could not delimit the LOCALIZED_CODES object literal")
	}
	body := src[start+open : start+end]

	out := map[int]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(\d+)\s*:`).FindAllStringSubmatch(body, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("bad numeric key %q: %v", m[1], err)
		}
		out[n] = true
	}
	for _, m := range regexp.MustCompile(`\[([A-Z_][A-Z0-9_]*)\]\s*:`).FindAllStringSubmatch(body, -1) {
		out[resolveTSConst(t, root, m[1])] = true
	}
	if len(out) == 0 {
		t.Fatal("parsed zero localized codes — the parser has drifted from toast.tsx")
	}
	return out
}

// resolveTSConst reads `export const NAME = <number>` out of client.ts.
func resolveTSConst(t *testing.T, root, name string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "web/packages/shared/src/api/client.ts"))
	if err != nil {
		t.Fatalf("read client.ts: %v", err)
	}
	m := regexp.MustCompile(`export const ` + name + `\s*=\s*(\d+)`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("toast.tsx keys LOCALIZED_CODES on %s, but client.ts does not export it", name)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("bad value for %s: %v", name, err)
	}
	return n
}

// constNameFor maps a catalogued number back to its exported constant name.
// Kept as an explicit table because Go has no reflection over constants; the
// TestConstantNameTableIsComplete check below stops it from going stale.
func constNameFor(num int) string {
	names := map[int]string{
		errcode.NumBadRequest: "NumBadRequest", errcode.NumInvalidInput: "NumInvalidInput",
		errcode.NumTOTPCodeReused: "NumTOTPCodeReused", errcode.NumInputRejected: "NumInputRejected",
		errcode.NumPasswordReused: "NumPasswordReused", errcode.NumInvalidCode: "NumInvalidCode",
		errcode.NumTOTPRequired: "NumTOTPRequired", errcode.NumSignatureFailed: "NumSignatureFailed",
		errcode.NumAppNoLoginURL: "NumAppNoLoginURL", errcode.NumAppValidation: "NumAppValidation",
		errcode.NumSelfApproval: "NumSelfApproval", errcode.NumApproverNotEligible: "NumApproverNotEligible",
		errcode.NumBadGroupRule: "NumBadGroupRule", errcode.NumInvalidClientType: "NumInvalidClientType",
		errcode.NumCaptchaRequired: "NumCaptchaRequired", errcode.NumUnauthenticated: "NumUnauthenticated",
		errcode.NumInvalidMFACode: "NumInvalidMFACode", errcode.NumForbidden: "NumForbidden",
		errcode.NumForbiddenScope: "NumForbiddenScope", errcode.NumStepUpRequiredNum: "NumStepUpRequiredNum",
		errcode.NumMFAEnrollRequired: "NumMFAEnrollRequired", errcode.NumEEFeatureRequired: "NumEEFeatureRequired",
		errcode.NumStepUpVerifyFailed: "NumStepUpVerifyFailed",
		errcode.NumPasswordChangeRequired: "NumPasswordChangeRequired",
		errcode.NumNotFound:               "NumNotFound", errcode.NumTemplateNotFound: "NumTemplateNotFound",
		errcode.NumConflict: "NumConflict", errcode.NumRouteNotFound: "NumRouteNotFound",
		errcode.NumAccessDenied: "NumAccessDenied", errcode.NumAccountDisabled: "NumAccountDisabled",
		errcode.NumAccountLocked:       "NumAccountLocked",
		errcode.NumPasswordTooShort:    "NumPasswordTooShort",
		errcode.NumPasswordNeedUpper:   "NumPasswordNeedUpper",
		errcode.NumPasswordNeedLower:   "NumPasswordNeedLower",
		errcode.NumPasswordNeedDigit:   "NumPasswordNeedDigit",
		errcode.NumPasswordNeedSpecial: "NumPasswordNeedSpecial",
		errcode.NumTooManyAttempts:   "NumTooManyAttempts",
		errcode.NumCodeExists:        "NumCodeExists",
		errcode.NumInternalError:     "NumInternalError",
		errcode.NumNotConfigured:     "NumNotConfigured",
		errcode.NumDependencyDown:    "NumDependencyDown",
		errcode.NumCSRFOriginMissing: "NumCSRFOriginMissing",
		errcode.NumCSRFOriginDenied:  "NumCSRFOriginDenied",
	}
	return names[num]
}

// Every Localized entry must be reachable by name, otherwise the single-call-site
// check above silently passes by looking up "".
func TestConstantNameTableCoversLocalizedCodes(t *testing.T) {
	for num, e := range errcode.Catalog {
		if e.Kind == errcode.Localized && constNameFor(num) == "" {
			t.Errorf("localized code %d has no entry in constNameFor, so "+
				"TestLocalizedCodesCarryOneMeaning cannot check it", num)
		}
	}
}

func forEachSourceLine(t *testing.T, fn func(rel string, lineNo int, line string)) {
	t.Helper()
	root := moduleRoot(t)
	for _, r := range scanRoots {
		dir := filepath.Join(root, r)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			// catalog.go and errcode.go quote example call sites in their docs.
			if strings.HasPrefix(rel, "pkg/errcode/") {
				return nil
			}
			f, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for n := 1; sc.Scan(); n++ {
				line := sc.Text()
				if strings.HasPrefix(strings.TrimSpace(line), "//") {
					continue
				}
				fn(rel, n, line)
			}
			return sc.Err()
		})
		if err != nil {
			t.Fatalf("walking %s: %v", r, err)
		}
	}
}

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
