package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	AllowOrigins []string
	// SkipPrefixes are request-path prefixes this middleware must not answer
	// for. It still runs — the chain is global — but it adds no headers and,
	// crucially, does not short-circuit the preflight.
	//
	// The OIDC subtree needs this. Its CORS is decided per registered
	// application rather than by this deployment-wide list, and the OPTIONS
	// handling below used to abort every preflight before the protocol layer
	// could answer: a public client's token exchange got a bare 204 with no
	// Access-Control-* headers at all, so the browser refused to send the POST.
	// The endpoints looked CORS-enabled on GET (the library answered those) and
	// broken only on preflight, which is a confusing way to fail.
	SkipPrefixes []string
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing.
func CORS(cfg CORSConfig) gin.HandlerFunc {
	allowedOrigins := make(map[string]bool)
	for _, origin := range cfg.AllowOrigins {
		allowedOrigins[origin] = true
	}

	return func(c *gin.Context) {
		for _, p := range cfg.SkipPrefixes {
			if strings.HasPrefix(c.Request.URL.Path, p) {
				c.Next()
				return
			}
		}

		origin := c.GetHeader("Origin")

		// Reflect the origin only if it is explicitly allow-listed. An empty
		// allow-list means deny-all — never reflect an arbitrary Origin with
		// Access-Control-Allow-Credentials, which would be a credentialed
		// wildcard defeating the SameSite/CSRF model.
		if origin != "" && allowedOrigins[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Request-ID, X-API-Key")
			c.Header("Access-Control-Expose-Headers", "X-Request-ID")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == http.MethodOptions {
			//response:ok a CORS preflight answer is a 204 with no body by definition
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// DefaultCORSConfig returns a development-friendly CORS config.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins: []string{
			"http://localhost:3500",
			"http://localhost:3501",
			"http://127.0.0.1:3500",
			"http://127.0.0.1:3501",
		},
	}
}
