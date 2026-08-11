package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/session"
)

func optionalTestRouter(t *testing.T, mgr *session.Manager, ns string, probe func(*gin.Context)) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/cb", OptionalAuthMiddleware(mgr, ns), func(c *gin.Context) {
		if probe != nil {
			probe(c)
		}
		c.Status(http.StatusOK)
	})
	return r
}

// No cookie at all — the callback also serves an anonymous IdP login through
// this exact route, so the middleware must let the request through untouched
// rather than rejecting it (that is the whole reason it exists instead of
// AuthMiddleware).
func TestOptionalAuthMiddleware_NoCookie_PassesThroughUnauthenticated(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 24*time.Hour)

	var sawUserID int64 = -1
	var sawActorOK bool
	r := optionalTestRouter(t, mgr, session.NamespacePortal, func(c *gin.Context) {
		sawUserID = c.GetInt64(CtxUserID)
		_, sawActorOK = auditctx.From(c.Request.Context())
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/cb", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (never rejects), got %d", w.Code)
	}
	if sawUserID != 0 {
		t.Fatalf("CtxUserID: want 0 (unset), got %d", sawUserID)
	}
	if sawActorOK {
		t.Fatal("auditctx actor present with no cookie at all")
	}
}

// A garbage/expired session id must be treated the same as no cookie: pass
// through, resolve nothing. This is the case a plain lookup failure (not a
// Get() error) produces.
func TestOptionalAuthMiddleware_InvalidCookie_PassesThroughUnauthenticated(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 24*time.Hour)

	var sawUserID int64 = -1
	r := optionalTestRouter(t, mgr, session.NamespacePortal, func(c *gin.Context) {
		sawUserID = c.GetInt64(CtxUserID)
	})

	req := httptest.NewRequest(http.MethodGet, "/cb", nil)
	req.AddCookie(&http.Cookie{Name: CookiePortal, Value: "does-not-exist"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (never rejects), got %d", w.Code)
	}
	if sawUserID != 0 {
		t.Fatalf("CtxUserID: want 0 (unset) for an unresolvable cookie, got %d", sawUserID)
	}
}

// The property Task 15's callback branch depends on: a VALID cookie resolves
// into both the gin context AND the auditctx actor, with the actor id and
// tenant matching the session. mxid-ee cannot import this package, so it is
// auditctx — not CtxUserID — that the callback actually reads.
func TestOptionalAuthMiddleware_ValidCookie_ResolvesSessionAndActor(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 24*time.Hour)

	const uid, tid = int64(4242), int64(7)
	sess, err := mgr.Create(t.Context(), session.NamespacePortal, uid, tid, "1.2.3.4", "ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	var sawUserID, sawTenantID int64
	var actor auditctx.Actor
	var actorOK bool
	r := optionalTestRouter(t, mgr, session.NamespacePortal, func(c *gin.Context) {
		sawUserID = c.GetInt64(CtxUserID)
		sawTenantID = c.GetInt64(CtxTenantID)
		actor, actorOK = auditctx.From(c.Request.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/cb", nil)
	req.AddCookie(&http.Cookie{Name: CookiePortal, Value: sess.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if sawUserID != uid {
		t.Fatalf("CtxUserID: want %d, got %d", uid, sawUserID)
	}
	if sawTenantID != tid {
		t.Fatalf("CtxTenantID: want %d, got %d", tid, sawTenantID)
	}
	if !actorOK {
		t.Fatal("auditctx actor missing for a valid session")
	}
	if actor.ActorID != uid || actor.TenantID != tid {
		t.Fatalf("auditctx actor: want id=%d tenant=%d, got id=%d tenant=%d", uid, tid, actor.ActorID, actor.TenantID)
	}
}

// The security/product property this middleware's own doc comment promises:
// resolving a session here must NOT extend its idle window. AuthMiddleware
// touches deliberately on real user activity; a callback visit — anonymous
// login or authenticated bind alike — is not that, and touching here would
// let an idle session live forever if the browser happened to still be
// carrying its cookie. A test that only checked "the route responds 200"
// would pass whether or not this line was ever removed, so this asserts the
// stored LastActiveAt is bit-identical to what Create wrote: Touch always
// stamps a fresh time.Now(), so any call to it changes this value.
func TestOptionalAuthMiddleware_DoesNotTouchSession(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 24*time.Hour)

	const uid, tid = int64(9001), int64(7)
	created, err := mgr.Create(t.Context(), session.NamespacePortal, uid, tid, "1.2.3.4", "ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	r := optionalTestRouter(t, mgr, session.NamespacePortal, nil)
	req := httptest.NewRequest(http.MethodGet, "/cb", nil)
	req.AddCookie(&http.Cookie{Name: CookiePortal, Value: created.ID})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}

	after, err := mgr.Get(t.Context(), session.NamespacePortal, created.ID)
	if err != nil || after == nil {
		t.Fatalf("re-fetch session: %v, got=%v", err, after)
	}
	if !after.LastActiveAt.Equal(created.LastActiveAt) {
		t.Fatalf("LastActiveAt changed (%v -> %v): OptionalAuthMiddleware touched the session",
			created.LastActiveAt, after.LastActiveAt)
	}
}
