package oidcop

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"github.com/imkerbos/mxid/pkg/auditctx"
	"github.com/imkerbos/mxid/pkg/event"
)

// The observer's whole value is that a refused token exchange becomes
// attributable, so these tests assert on the two things an operator actually
// consumes — the gin keys the request logger emits, and the bus event the audit
// chain and the alert webhook subscribe to — rather than on internal state.
//
// The success case is the one that matters most: a 2xx token response carries
// the access and refresh tokens, and the observer holds a copy of that body in
// a buffer. TestTokenObserver_SuccessExposesNoToken drives a real success
// response through and fails if either token string shows up in ANYTHING
// observable. Without it, a later change that moved the status check (or
// dropped it) would silently start logging bearer tokens.

const obsTokenPath = "/protocol/oidc/token"

// obsAppResolver stubs only GetAppByClientID. The embedded nil interface makes
// any other call panic loudly instead of returning a zero value.
type obsAppResolver struct {
	resolver.AppResolver
	app *resolver.AppConfig
}

func (f *obsAppResolver) GetAppByClientID(_ context.Context, _ string) (*resolver.AppConfig, error) {
	return f.app, nil
}

// obsCapture records what the observer left behind once the chain unwinds. It
// is registered BEFORE the observer so its own c.Next() returns after the
// observer's post-handler work has run — the same position the real request
// logger occupies.
type obsCapture struct {
	keys     map[any]any
	actor    auditctx.Actor
	hasActor bool
}

func obsCaptureMW(got *obsCapture) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		got.keys = map[any]any{}
		for k, v := range c.Keys {
			got.keys[k] = v
		}
		got.actor, got.hasActor = auditctx.From(c.Request.Context())
	}
}

// obsRun wires [capture][observer][handler] and performs one request.
func obsRun(t *testing.T, bus *event.Bus, apps resolver.AppResolver, req *http.Request, handler gin.HandlerFunc) (*httptest.ResponseRecorder, *obsCapture) {
	t.Helper()
	return obsRunRedis(t, nil, bus, apps, req, handler)
}

// obsRunRedis is obsRun with a Redis client, for the burst counter. The
// no-Redis form is the common case: every other assertion here is about the
// per-request record, which must not depend on the counter working.
func obsRunRedis(t *testing.T, rdb *redis.Client, bus *event.Bus, apps resolver.AppResolver, req *http.Request, handler gin.HandlerFunc) (*httptest.ResponseRecorder, *obsCapture) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	got := &obsCapture{}
	r.Use(obsCaptureMW(got), WithTokenObserver(rdb, bus, apps, obsTokenPath))
	r.Any("/protocol/oidc/*any", handler)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w, got
}

// obsBus returns a bus plus a channel receiving every OIDCGrantRejected.
// Publish dispatches asynchronously (safego.Go), so the event must be awaited.
func obsBus(t *testing.T) (*event.Bus, <-chan event.Event) {
	t.Helper()
	bus := event.NewBus(zap.NewNop())
	ch := make(chan event.Event, 4)
	bus.Subscribe(event.OIDCGrantRejected, func(_ context.Context, e event.Event) { ch <- e })
	return bus, ch
}

// obsPayload unwraps the bus payload. event.Event.Payload is `any`; every
// publisher in this package sends a map, and a test that silently skipped its
// assertions on a type change would be worse than one that fails.
func obsPayload(t *testing.T, e event.Event) map[string]any {
	t.Helper()
	m, ok := e.Payload.(map[string]any)
	if !ok {
		t.Fatalf("event payload is %T, want map[string]any", e.Payload)
	}
	return m
}

func obsTokenPost(body string, basicUser string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, obsTokenPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, "some-secret")
	}
	return req
}

func TestTokenObserver_RejectionIsAttributableAndPublished(t *testing.T) {
	bus, events := obsBus(t)
	apps := &obsAppResolver{app: &resolver.AppConfig{ID: 42, TenantID: 7, ClientID: "client_abc"}}

	// client_secret_basic: the client_id lives in the Authorization header, which
	// is exactly the case that produced unattributable log lines in production.
	req := obsTokenPost("grant_type=authorization_code&code=bogus", "client_abc")

	w, got := obsRun(t, bus, apps, req, func(c *gin.Context) {
		c.String(http.StatusBadRequest, `{"error":"invalid_grant","error_description":"invalid code"}`)
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("observer changed the protocol answer: status = %d, want 400", w.Code)
	}
	if got.keys[GinCtxOIDCClientID] != "client_abc" {
		t.Errorf("%s = %v, want client_abc", GinCtxOIDCClientID, got.keys[GinCtxOIDCClientID])
	}
	if got.keys[GinCtxOIDCError] != "invalid_grant" {
		t.Errorf("%s = %v, want invalid_grant", GinCtxOIDCError, got.keys[GinCtxOIDCError])
	}

	// A token call carries no session cookie, so no auth middleware stamps an
	// actor; without the observer's own stamp the audit row would have no IP.
	if !got.hasActor {
		t.Fatal("no auditctx actor stamped: the audit row would carry no IP or actor type")
	}
	if got.actor.ActorType != auditctx.TypeAPI {
		t.Errorf("actor type = %q, want %q", got.actor.ActorType, auditctx.TypeAPI)
	}
	if got.actor.ActorName != "client_abc" {
		t.Errorf("actor name = %q, want client_abc", got.actor.ActorName)
	}
	if got.actor.IP == "" {
		t.Error("actor IP is empty")
	}

	select {
	case e := <-events:
		p := obsPayload(t, e)
		if p["client_id"] != "client_abc" {
			t.Errorf("payload client_id = %v, want client_abc", p["client_id"])
		}
		if p["error"] != "invalid_grant" {
			t.Errorf("payload error = %v, want invalid_grant", p["error"])
		}
		if p["app_id"] != int64(42) {
			t.Errorf("payload app_id = %v, want 42", p["app_id"])
		}
		if p["tenant_id"] != int64(7) {
			t.Errorf("payload tenant_id = %v, want 7", p["tenant_id"])
		}
		if p["ip"] == "" || p["ip"] == nil {
			t.Error("payload ip is empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no OIDCGrantRejected published: the console alert webhook would never fire")
	}
}

// A rejection naming a client that does not exist is still recorded — it is a
// probe, and dropping it would hide exactly the reconnaissance worth seeing.
func TestTokenObserver_UnknownClientStillPublishes(t *testing.T) {
	bus, events := obsBus(t)
	apps := &obsAppResolver{app: nil}

	req := obsTokenPost("grant_type=authorization_code&client_id=client_nope&code=x", "")
	_, _ = obsRun(t, bus, apps, req, func(c *gin.Context) {
		c.String(http.StatusUnauthorized, `{"error":"invalid_client"}`)
	})

	select {
	case e := <-events:
		p := obsPayload(t, e)
		if p["client_id"] != "client_nope" {
			t.Errorf("payload client_id = %v, want client_nope", p["client_id"])
		}
		if p["error"] != "invalid_client" {
			t.Errorf("payload error = %v, want invalid_client", p["error"])
		}
		if _, ok := p["app_id"]; ok {
			t.Errorf("app_id present for an unresolvable client: %v", p["app_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no OIDCGrantRejected published for an unknown client")
	}
}

// THE leak guard. The observer buffers the response body; on a 2xx that body is
// the tokens. Nothing observable may contain them, and the client must still
// receive the response byte-for-byte.
func TestTokenObserver_SuccessExposesNoToken(t *testing.T) {
	bus, events := obsBus(t)
	apps := &obsAppResolver{app: &resolver.AppConfig{ID: 42, TenantID: 7, ClientID: "client_abc"}}

	const accessTok = "AT-must-never-be-logged-0001"
	const refreshTok = "RT-must-never-be-logged-0002"
	body := fmt.Sprintf(`{"access_token":%q,"refresh_token":%q,"token_type":"Bearer","expires_in":3600}`, accessTok, refreshTok)

	req := obsTokenPost("grant_type=authorization_code&code=good", "client_abc")
	w, got := obsRun(t, bus, apps, req, func(c *gin.Context) {
		c.String(http.StatusOK, body)
	})

	if w.Code != http.StatusOK || w.Body.String() != body {
		t.Fatalf("observer altered a successful token response:\n got %q\nwant %q", w.Body.String(), body)
	}

	// Everything an operator or the audit chain can see, flattened.
	var observable strings.Builder
	for k, v := range got.keys {
		fmt.Fprintf(&observable, "%s=%v\n", k, v)
	}
	fmt.Fprintf(&observable, "actor=%+v\n", got.actor)
	for _, tok := range []string{accessTok, refreshTok} {
		if strings.Contains(observable.String(), tok) {
			t.Fatalf("token leaked into an observable field:\n%s", observable.String())
		}
	}

	if _, ok := got.keys[GinCtxOIDCError]; ok {
		t.Errorf("%s set on a successful exchange: %v", GinCtxOIDCError, got.keys[GinCtxOIDCError])
	}

	select {
	case e := <-events:
		t.Fatalf("a successful exchange published a rejection event: %+v", e.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// Every other route on the subtree must be untouched: no keys, no event, no
// actor stamped. The observer is mounted on the whole /oidc/* catch-all.
func TestTokenObserver_NonTokenRequestUntouched(t *testing.T) {
	bus, events := obsBus(t)
	apps := &obsAppResolver{app: nil}

	req := httptest.NewRequest(http.MethodGet, "/protocol/oidc/authorize?client_id=client_abc", nil)
	_, got := obsRun(t, bus, apps, req, func(c *gin.Context) { c.Status(http.StatusFound) })

	if _, ok := got.keys[GinCtxOIDCClientID]; ok {
		t.Errorf("%s set on /authorize", GinCtxOIDCClientID)
	}
	if got.hasActor {
		t.Errorf("auditctx actor stamped on /authorize: %+v", got.actor)
	}
	select {
	case e := <-events:
		t.Fatalf("/authorize published a token rejection: %+v", e.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// A GET to the token path is not a token exchange; only POST is.
func TestTokenObserver_GetOnTokenPathUntouched(t *testing.T) {
	bus, events := obsBus(t)
	req := httptest.NewRequest(http.MethodGet, obsTokenPath, nil)
	_, got := obsRun(t, bus, &obsAppResolver{}, req, func(c *gin.Context) {
		c.String(http.StatusMethodNotAllowed, `{"error":"invalid_request"}`)
	})
	if len(got.keys) != 0 {
		t.Errorf("keys set on GET %s: %v", obsTokenPath, got.keys)
	}
	select {
	case e := <-events:
		t.Fatalf("GET on the token path published an event: %+v", e.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// A rejection written by a layer ABOVE op (the rate limiter's 429, a proxy's
// HTML error page) still has to produce a record. The reason may be missing;
// the client and the status must not be.
func TestTokenObserver_NonJSONRejectionStillPublishes(t *testing.T) {
	bus, events := obsBus(t)
	req := obsTokenPost("grant_type=authorization_code", "client_abc")
	_, got := obsRun(t, bus, &obsAppResolver{}, req, func(c *gin.Context) {
		c.String(http.StatusBadGateway, "<html>upstream exploded</html>")
	})

	if got.keys[GinCtxOIDCClientID] != "client_abc" {
		t.Errorf("%s = %v, want client_abc", GinCtxOIDCClientID, got.keys[GinCtxOIDCClientID])
	}
	if _, ok := got.keys[GinCtxOIDCError]; ok {
		t.Errorf("%s set from a non-JSON body: %v", GinCtxOIDCError, got.keys[GinCtxOIDCError])
	}
	select {
	case e := <-events:
		p := obsPayload(t, e)
		if p["error"] != "" {
			t.Errorf("payload error = %v, want empty for a non-JSON body", p["error"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a non-JSON rejection published nothing")
	}
}

// The body the observer retains is bounded: it sits on the request path and a
// response body is not a thing we control the size of.
func TestTokenObserver_BodyCaptureIsBounded(t *testing.T) {
	rec := &errorBodyRecorder{ResponseWriter: nil}
	// keep() never touches ResponseWriter, so a nil one is fine here and keeps
	// the test about the bound rather than about gin.
	rec.keep([]byte(strings.Repeat("x", maxCapturedErrorBody*3)))
	if rec.buf.Len() != maxCapturedErrorBody {
		t.Errorf("retained %d bytes, want the %d-byte cap", rec.buf.Len(), maxCapturedErrorBody)
	}
	rec.keep([]byte("more"))
	if rec.buf.Len() != maxCapturedErrorBody {
		t.Errorf("buffer grew past the cap to %d bytes", rec.buf.Len())
	}
}

func TestOAuthErrorCode(t *testing.T) {
	long := strings.Repeat("e", 200)
	tests := []struct {
		name string
		body string
		want string
	}{
		{"rfc6749 error", `{"error":"invalid_grant","error_description":"invalid code"}`, "invalid_grant"},
		{"rate limiter slow_down", `{"error":"slow_down","error_description":"..."}`, "slow_down"},
		{"empty body", "", ""},
		{"not json", "<html>nope</html>", ""},
		{"json without error member", `{"foo":"bar"}`, ""},
		{"whitespace trimmed", `{"error":"  invalid_client  "}`, "invalid_client"},
		{"overlong clamped", fmt.Sprintf(`{"error":%q}`, long), long[:64]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := oauthErrorCode([]byte(tc.body)); got != tc.want {
				t.Errorf("oauthErrorCode(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// obsBurstBus subscribes to BOTH events so a test can tell an escalation apart
// from the per-request records it rides on.
func obsBurstBus(t *testing.T) (*event.Bus, <-chan event.Event, <-chan event.Event) {
	t.Helper()
	bus := event.NewBus(zap.NewNop())
	rejected := make(chan event.Event, 64)
	burst := make(chan event.Event, 8)
	bus.Subscribe(event.OIDCGrantRejected, func(_ context.Context, e event.Event) { rejected <- e })
	bus.Subscribe(event.OIDCGrantRejectedBurst, func(_ context.Context, e event.Event) { burst <- e })
	return bus, rejected, burst
}

func obsNewRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// The burst event fires on the request that crosses the threshold and NOT on
// the ones before or after it: one escalation per window, not one per request.
func TestTokenObserver_BurstFiresOnceAtThreshold(t *testing.T) {
	rdb := obsNewRedis(t)
	bus, _, burst := obsBurstBus(t)
	apps := &obsAppResolver{app: &resolver.AppConfig{ID: 42, TenantID: 7, ClientID: "client_abc"}}

	reject := func(c *gin.Context) {
		c.String(http.StatusBadRequest, `{"error":"invalid_grant"}`)
	}
	for i := 1; i <= grantRejectBurstThreshold+3; i++ {
		obsRunRedis(t, rdb, bus, apps, obsTokenPost("grant_type=authorization_code&code=x", "client_abc"), reject)
	}

	select {
	case e := <-burst:
		p := obsPayload(t, e)
		if p["client_id"] != "client_abc" {
			t.Errorf("burst client_id = %v, want client_abc", p["client_id"])
		}
		if p["count"] != int64(grantRejectBurstThreshold) {
			t.Errorf("burst count = %v, want %d", p["count"], grantRejectBurstThreshold)
		}
		if p["window_seconds"] != int(grantRejectBurstWindow.Seconds()) {
			t.Errorf("burst window_seconds = %v, want %d", p["window_seconds"], int(grantRejectBurstWindow.Seconds()))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no burst event after %d rejections", grantRejectBurstThreshold+3)
	}

	select {
	case e := <-burst:
		t.Fatalf("burst fired more than once in a window: %+v", e.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// Below the threshold there is no escalation — only the per-request records.
func TestTokenObserver_NoBurstBelowThreshold(t *testing.T) {
	rdb := obsNewRedis(t)
	bus, rejected, burst := obsBurstBus(t)
	apps := &obsAppResolver{app: nil}

	for i := 0; i < grantRejectBurstThreshold-1; i++ {
		obsRunRedis(t, rdb, bus, apps, obsTokenPost("grant_type=authorization_code&client_id=client_abc", ""), func(c *gin.Context) {
			c.String(http.StatusBadRequest, `{"error":"invalid_grant"}`)
		})
	}

	// The individual rejections must still all be published.
	for i := 0; i < grantRejectBurstThreshold-1; i++ {
		select {
		case <-rejected:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d rejections published", i, grantRejectBurstThreshold-1)
		}
	}
	select {
	case e := <-burst:
		t.Fatalf("burst fired at %d rejections, threshold is %d: %+v", grantRejectBurstThreshold-1, grantRejectBurstThreshold, e.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// Two clients are counted separately. This is the whole reason the burst event
// exists: the alert dispatcher's suppression gate is keyed by tenant + event
// type, so without a per-client count one chatty RP would bury the probe
// against a different client.
func TestTokenObserver_BurstIsPerClient(t *testing.T) {
	rdb := obsNewRedis(t)
	bus, _, burst := obsBurstBus(t)
	apps := &obsAppResolver{app: nil}

	reject := func(c *gin.Context) { c.String(http.StatusBadRequest, `{"error":"invalid_grant"}`) }

	// "noisy" crosses the threshold; "quiet" stays one short of it.
	for i := 0; i < grantRejectBurstThreshold; i++ {
		obsRunRedis(t, rdb, bus, apps, obsTokenPost("grant_type=authorization_code", "client_noisy"), reject)
	}
	for i := 0; i < grantRejectBurstThreshold-1; i++ {
		obsRunRedis(t, rdb, bus, apps, obsTokenPost("grant_type=authorization_code", "client_quiet"), reject)
	}

	select {
	case e := <-burst:
		if got := obsPayload(t, e)["client_id"]; got != "client_noisy" {
			t.Errorf("burst client_id = %v, want client_noisy", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no burst for the noisy client")
	}
	select {
	case e := <-burst:
		t.Fatalf("burst fired for a client below the threshold: %+v", e.Payload)
	case <-time.After(300 * time.Millisecond):
	}

	// One more from the quiet client now crosses ITS own count, proving the
	// noisy client did not consume the budget.
	obsRunRedis(t, rdb, bus, apps, obsTokenPost("grant_type=authorization_code", "client_quiet"), reject)
	select {
	case e := <-burst:
		if got := obsPayload(t, e)["client_id"]; got != "client_quiet" {
			t.Errorf("burst client_id = %v, want client_quiet", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("quiet client never produced its own burst")
	}
}

// A successful exchange must not advance the burst counter.
func TestTokenObserver_SuccessDoesNotCountTowardBurst(t *testing.T) {
	rdb := obsNewRedis(t)
	bus, _, burst := obsBurstBus(t)
	apps := &obsAppResolver{app: nil}

	for i := 0; i < grantRejectBurstThreshold*2; i++ {
		obsRunRedis(t, rdb, bus, apps, obsTokenPost("grant_type=authorization_code", "client_abc"), func(c *gin.Context) {
			c.String(http.StatusOK, `{"access_token":"AT","token_type":"Bearer"}`)
		})
	}
	select {
	case e := <-burst:
		t.Fatalf("successful exchanges triggered a burst: %+v", e.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// A broken counter must not invent an incident, and must not cost the
// per-request record either.
func TestTokenObserver_BurstFailsQuietWithoutRedis(t *testing.T) {
	bus, rejected, burst := obsBurstBus(t)
	apps := &obsAppResolver{app: nil}

	for i := 0; i < grantRejectBurstThreshold+5; i++ {
		obsRunRedis(t, nil, bus, apps, obsTokenPost("grant_type=authorization_code", "client_abc"), func(c *gin.Context) {
			c.String(http.StatusBadRequest, `{"error":"invalid_grant"}`)
		})
	}
	select {
	case <-rejected:
	case <-time.After(2 * time.Second):
		t.Fatal("rejections stopped being published when the counter had no Redis")
	}
	select {
	case e := <-burst:
		t.Fatalf("a nil Redis produced a burst event: %+v", e.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}
