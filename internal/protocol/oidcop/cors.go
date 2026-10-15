package oidcop

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
)

// browserOriginTTL is how long the derived origin set is reused before the
// registered applications are read again. A newly registered SPA starts working
// within this window without a restart; a removed one stops within it.
const browserOriginTTL = 60 * time.Second

// CORS returns the cross-origin policy for the OIDC endpoints a browser calls
// directly: a public client runs the code exchange from page JavaScript, so
// /token, /userinfo and the discovery documents all face a preflight.
//
// It differs from the console/portal CORS middleware on two points, and both
// are the point.
//
// ORIGINS COME FROM THE REGISTERED APPS, not from a deployment-wide env var.
// Requiring an operator to add every relying party's domain to MXID's own
// configuration does not scale and confuses two unrelated lists — the one that
// protects MXID's cookie-authenticated SPAs, and the one that says which sites
// may complete an OIDC exchange. An origin that is already trusted to receive
// an authorization code is trusted to present it back, so the redirect URIs are
// the answer. Keycloak, Auth0 and Okta all derive it the same way.
//
// NO Access-Control-Allow-Credentials. These endpoints authenticate with a
// code, a client secret or a bearer token — never with the session cookie — so
// the browser has no reason to attach one, and withholding the header means a
// mistake in the origin comparison still cannot hand a cookie to a third party.
// This is also why the upstream library's default had to be replaced rather
// than narrowed: zitadel/oidc ships AllowOriginFunc returning true for every
// origin together with AllowCredentials, i.e. credentialed access from anywhere.
//
// A nil resolver yields an empty allow-list, which denies every cross-origin
// request rather than opening up — the direction a missing wiring should fail.
func CORS(apps resolver.AppResolver, logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	cache := &originCache{apps: apps, logger: logger}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			// Same-origin or a non-browser caller: no CORS to negotiate. A
			// preflight always carries Origin, so this cannot swallow one.
			c.Next()
			return
		}

		if cache.allows(c.Request.Context(), origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Requested-With")
			c.Header("Access-Control-Max-Age", "600")
		}
		// Vary regardless of the outcome: the response differs by Origin, and a
		// cache that stored the allowed answer under a key that ignores it would
		// serve those headers to everyone.
		c.Header("Vary", "Origin")

		if c.Request.Method == http.MethodOptions {
			//response:ok a CORS preflight answer is a 204 with no body by definition
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// originCache memoises the derived origin set. The preflight sits in front of
// every token exchange, and reading all registered applications on each one
// would put a database query on the hot path of a flow that is already
// latency-sensitive.
type originCache struct {
	apps   resolver.AppResolver
	logger *zap.Logger

	mu       sync.RWMutex
	allowed  map[string]struct{}
	expires  time.Time
	refreshK sync.Mutex
}

func (o *originCache) allows(ctx context.Context, origin string) bool {
	o.mu.RLock()
	fresh := time.Now().Before(o.expires)
	if fresh {
		_, ok := o.allowed[origin]
		o.mu.RUnlock()
		return ok
	}
	o.mu.RUnlock()

	// One refresher at a time; the rest wait and then read the new set. A
	// thundering herd of preflights must not become a herd of queries.
	o.refreshK.Lock()
	defer o.refreshK.Unlock()

	o.mu.RLock()
	if time.Now().Before(o.expires) {
		_, ok := o.allowed[origin]
		o.mu.RUnlock()
		return ok
	}
	o.mu.RUnlock()

	set := map[string]struct{}{}
	if o.apps != nil {
		raw, err := o.apps.ListBrowserOrigins(ctx)
		if err != nil {
			// Loud, because the symptom is silent: every cross-origin exchange
			// is refused and the browser reports only a generic CORS block.
			// Tracking that back to a failed query took far longer than it
			// should have.
			o.logger.Error("oidc CORS: cannot list registered browser origins; "+
				"cross-origin token exchanges will be refused", zap.Error(err))
			// Keep serving the stale set rather than silently denying every
			// cross-origin exchange because one query failed. Expiry is pushed
			// out a little so a database that is down does not turn every
			// preflight into a retry.
			o.mu.Lock()
			o.expires = time.Now().Add(5 * time.Second)
			_, ok := o.allowed[origin]
			o.mu.Unlock()
			return ok
		}
		for _, r := range raw {
			if norm := NormalizeOrigin(r); norm != "" {
				set[norm] = struct{}{}
			}
		}
	}

	o.mu.Lock()
	o.allowed = set
	o.expires = time.Now().Add(browserOriginTTL)
	o.mu.Unlock()

	_, ok := set[origin]
	return ok
}

// NormalizeOrigin reduces a registered redirect URI to the origin a browser
// would send in the Origin header: scheme://host[:port], lowercased, with the
// default port for the scheme dropped.
//
// Exported because the adapter that reads redirect URIs out of the database
// normalises with the same rules; two implementations of "what is an origin"
// would eventually disagree, and the disagreement would look like a CORS bug.
//
// Anything that is not an absolute http(s) URL returns "": a custom scheme
// (native apps register things like com.example://cb) has no web origin, and a
// relative value cannot name one.
func NormalizeOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}
