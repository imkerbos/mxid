package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders sets defensive response headers on every response.
//
// Note on CSP: the SPA HTML is served by the edge (nginx), not this Go app, so
// a page Content-Security-Policy belongs in the nginx config (it also must be
// tuned for the SPA's inline styles + admin branding CSS). These app-level
// headers harden the API + the DB-backed static asset responses and any HTML
// the Go app ever emits. `release` gates HSTS (only meaningful over TLS).
func SecurityHeaders(release bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		// Never MIME-sniff a response into a different type (blocks e.g. an
		// image/* upload being interpreted as HTML/JS).
		h.Set("X-Content-Type-Options", "nosniff")
		// Deny framing — login / consent / console must not be clickjackable.
		h.Set("X-Frame-Options", "DENY")
		// Don't leak full URLs (which can carry tokens/redirect state) cross-site.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Isolate the browsing context group from cross-origin openers.
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if release {
			// Two years, subdomains, preload-eligible. Release runs behind TLS.
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		c.Next()
	}
}
