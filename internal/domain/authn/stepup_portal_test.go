package authn

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/session"
)

// The portal needs a step-up route of its own: the sudo window lives on the
// session, and the console route stamps the console session. Without it a
// portal-side gate (form-fill reveal / extension pairing) that went stale could
// only be cleared by signing out and back in — which is exactly what users hit.
// These tests pin both halves of the fix: the portal route exists, and the
// challenge adapts to what the account actually has.

type stubMFAVerifier struct {
	enrolled bool
	code     string
	backup   string
	spent    string
}

func (s *stubMFAVerifier) HasVerifiedTOTP(context.Context, int64) (bool, error) {
	return s.enrolled, nil
}

func (s *stubMFAVerifier) VerifyTOTP(_ context.Context, _ int64, code string) error {
	if code == s.spent && s.spent != "" {
		// What the real replay guard reports: the digits were right, the code
		// was already consumed this window.
		return ErrMFACodeReused
	}
	if code == s.code {
		return nil
	}
	return ErrMFAVerifyFailed
}

func (s *stubMFAVerifier) ConsumeBackupCode(_ context.Context, _ int64, code string) error {
	if s.backup != "" && code == s.backup {
		return nil
	}
	return ErrMFAVerifyFailed
}

// portalStepUpUser is both the UserQuerier (id → username) and the
// UserAuthQuerier (username → password hash) the step-up path walks.
type portalStepUpUser struct {
	username string
	hash     string
	status   int
}

func (u *portalStepUpUser) GetByID(_ context.Context, id int64) (*UserInfo, error) {
	return &UserInfo{ID: id, Username: u.username, Status: u.status}, nil
}
func (u *portalStepUpUser) UpdateLastLogin(context.Context, int64, string) error { return nil }
func (u *portalStepUpUser) UpdateStatus(context.Context, int64, int) error       { return nil }
func (u *portalStepUpUser) GetByEmail(context.Context, int64, string) (*UserAuth, error) {
	return nil, ErrEmailLoginUnsupported
}
func (u *portalStepUpUser) GetByUsername(_ context.Context, _ int64, name string) (*UserAuth, error) {
	if name != u.username {
		return nil, ErrAuthFailed
	}
	return &UserAuth{ID: 1, Username: u.username, PasswordHash: u.hash, Status: u.status}, nil
}

type portalStepUpEnv struct {
	handler *Handler
	engine  *Engine
	mgr     *session.Manager
	sid     string
	mfa     *stubMFAVerifier
	users   *portalStepUpUser
}

func newPortalStepUpEnv(t *testing.T, password string, mfaEnrolled bool) *portalStepUpEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, 30*time.Minute, 12*time.Hour)

	hash := ""
	if password != "" {
		h, err := crypto.HashPassword(password)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		hash = h
	}
	users := &portalStepUpUser{username: "alice", hash: hash, status: statusActive}
	mfa := &stubMFAVerifier{enrolled: mfaEnrolled, code: "123456", backup: "", spent: ""}

	e := &Engine{
		providers:      map[string]Provider{LocalProviderType: NewLocalProvider(users, 0)},
		sessionMgr:     mgr,
		eventBus:       event.NewBus(zap.NewNop()),
		userRepo:       users,
		rdb:            rdb,
		mfaVerifier:    mfa,
		mfaRateLimiter: NewMFARateLimiter(rdb),
	}

	sess, err := mgr.Create(context.Background(), session.NamespacePortal, 1, 1, "ip", "ua", "password")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return &portalStepUpEnv{handler: &Handler{engine: e}, engine: e, mgr: mgr, sid: sess.ID, mfa: mfa, users: users}
}

func (e *portalStepUpEnv) do(method, body string) *httptest.ResponseRecorder {
	return e.doWithCookie(method, body, CookiePortal, e.sid)
}

func (e *portalStepUpEnv) doWithCookie(method, body, cookieName, sid string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/step-up", e.handler.stepUpMethodHandler(session.NamespacePortal, CookiePortal))
	r.POST("/step-up", e.handler.stepUpHandler(session.NamespacePortal, CookiePortal))

	req := httptest.NewRequest(method, "/step-up", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if cookieName != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// console runs the same request against the CONSOLE-namespace routes, to prove
// the two windows are independent.
func (e *portalStepUpEnv) console(method, body, sid string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/step-up", e.handler.stepUpHandler(session.NamespaceConsole, CookieConsole))

	req := httptest.NewRequest(method, "/step-up", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: CookieConsole, Value: sid})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func (e *portalStepUpEnv) fresh(t *testing.T) bool {
	t.Helper()
	sess, err := e.mgr.Get(context.Background(), session.NamespacePortal, e.sid)
	if err != nil || sess == nil {
		t.Fatalf("get session: %v", err)
	}
	return sess.StepUpFresh(time.Now(), 10*time.Minute)
}

// An enrolled account answers TOTP, and passing it re-opens the sudo window on
// the PORTAL session.
func TestPortalStepUp_TOTPRefreshesPortalWindow(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", true)

	if got := env.do(http.MethodGet, "").Body.String(); !bytes.Contains([]byte(got), []byte(`"method":"totp"`)) {
		t.Fatalf("enrolled account must be challenged for totp, got %s", got)
	}
	if env.fresh(t) {
		t.Fatal("session must not start inside the sudo window")
	}
	if w := env.do(http.MethodPost, `{"code":"123456"}`); w.Code != http.StatusOK {
		t.Fatalf("valid totp: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !env.fresh(t) {
		t.Fatal("a passed step-up must stamp the portal session")
	}
}

// The regression that logged people out: a wrong answer is a refused challenge
// on a LIVE session, so it must not be a 401 — both SPAs read any 401 as
// "session died" and bounce to the login screen.
func TestPortalStepUp_WrongAnswerDoesNotLogOut(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enrolled bool
		body     string
	}{
		{"wrong totp", true, `{"code":"000000"}`},
		{"wrong password", false, `{"password":"nope"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newPortalStepUpEnv(t, "Sup3rSecret!", tc.enrolled)
			w := env.do(http.MethodPost, tc.body)
			if w.Code == http.StatusUnauthorized {
				t.Fatalf("a failed step-up must not answer 401 (it signs the user out), got %s", w.Body.String())
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d (%s)", w.Code, w.Body.String())
			}
			// A LOCALIZED code, so the SPA renders its own sentence. A generic
			// one makes the SPA print the server's English message verbatim —
			// which is what a Chinese-locale user saw ("step-up verification
			// failed") under an otherwise translated toast title.
			if !bytes.Contains(w.Body.Bytes(), []byte("40334")) {
				t.Fatalf("want the localized step-up failure code 40334, got %s", w.Body.String())
			}
			if env.fresh(t) {
				t.Fatal("a failed step-up must not stamp the session")
			}
		})
	}
}

// No authenticator enrolled: the account is challenged for its password instead
// of being handed a gate it can never satisfy.
func TestPortalStepUp_PasswordFallbackWhenNoMFA(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", false)

	if got := env.do(http.MethodGet, "").Body.String(); !bytes.Contains([]byte(got), []byte(`"method":"password"`)) {
		t.Fatalf("account without a factor must be challenged for its password, got %s", got)
	}
	if w := env.do(http.MethodPost, `{"password":"Sup3rSecret!"}`); w.Code != http.StatusOK {
		t.Fatalf("valid password: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !env.fresh(t) {
		t.Fatal("a passed password step-up must stamp the portal session")
	}
}

// An enrolled account cannot swap its second factor for the password it already
// typed at login — that would make the factor optional for anyone holding the
// password.
func TestPortalStepUp_EnrolledAccountCannotDowngradeToPassword(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", true)

	w := env.do(http.MethodPost, `{"password":"Sup3rSecret!"}`)
	if w.Code == http.StatusOK {
		t.Fatal("an enrolled account must not clear step-up with its password")
	}
	if env.fresh(t) {
		t.Fatal("rejected downgrade must not stamp the session")
	}
}

// External-IdP account: no factor, no local password. Nothing to verify
// against, so the answer is "enroll first", not an unanswerable challenge.
func TestPortalStepUp_NoMethodDemandsEnrollment(t *testing.T) {
	env := newPortalStepUpEnv(t, "", false)

	if got := env.do(http.MethodGet, "").Body.String(); !bytes.Contains([]byte(got), []byte(`"method":"none"`)) {
		t.Fatalf("account with neither factor nor password: want method none, got %s", got)
	}
	w := env.do(http.MethodPost, `{"password":"anything"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("40331")) {
		t.Fatalf("want mfa_enroll_required (40331), got %s", w.Body.String())
	}
	if env.fresh(t) {
		t.Fatal("an unanswerable challenge must not stamp the session")
	}
}

// A code that was CORRECT but already spent this window gets its own sentence.
// The two prompts landing inside one 30-second step is the ordinary case — the
// user finishes an MFA challenge and is immediately asked to step up — and
// telling them their code is "wrong" sends them to re-read digits that were
// right. Found by hitting it during a live run of this very flow.
func TestPortalStepUp_ReusedCodeIsNotAWrongCode(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", true)
	env.mfa.spent = "654321"

	w := env.do(http.MethodPost, `{"code":"654321"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("40003")) {
		t.Fatalf("a spent code must report totpCodeReused (40003), not a generic failure: %s", w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("40334")) {
		t.Fatalf("a spent code must NOT be reported as a wrong one: %s", w.Body.String())
	}
	if env.fresh(t) {
		t.Fatal("a spent code must not stamp the session")
	}
}

// A backup code is a valid step-up answer — it is the recovery path for a lost
// authenticator, and blocking it here would strand the user the same way the
// missing portal route did.
func TestPortalStepUp_BackupCodeAccepted(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", true)
	env.mfa.backup = "abcd-efgh-1234"

	if w := env.do(http.MethodPost, `{"code":"abcd-efgh-1234"}`); w.Code != http.StatusOK {
		t.Fatalf("backup code: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !env.fresh(t) {
		t.Fatal("a backup code must stamp the portal session")
	}
}

// Submitting nothing is a malformed request, not a failed challenge: the user
// gets a "what to type" refusal (400) rather than being told they got it wrong.
func TestPortalStepUp_MissingProofIsBadRequest(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enrolled bool
		body     string
		wantCode int
	}{
		{"enrolled, no code", true, `{}`, 40007},         // errcode.NumTOTPRequired
		{"not enrolled, no password", false, `{}`, 40002}, // errcode.NumInvalidInput
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newPortalStepUpEnv(t, "Sup3rSecret!", tc.enrolled)
			w := env.do(http.MethodPost, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d (%s)", w.Code, w.Body.String())
			}
			if !bytes.Contains(w.Body.Bytes(), []byte(strconv.Itoa(tc.wantCode))) {
				t.Fatalf("want business code %d, got %s", tc.wantCode, w.Body.String())
			}
		})
	}
}

// No cookie / a dead session are the ONE case that legitimately answers 401 —
// there is no session to step up, so bouncing to the login screen is right.
func TestPortalStepUp_NoSessionIsUnauthorized(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", true)

	if w := env.doWithCookie(http.MethodPost, `{"code":"123456"}`, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie: want 401, got %d (%s)", w.Code, w.Body.String())
	}
	if w := env.doWithCookie(http.MethodPost, `{"code":"123456"}`, CookiePortal, "not-a-session"); w.Code != http.StatusUnauthorized {
		t.Fatalf("dead session: want 401, got %d (%s)", w.Code, w.Body.String())
	}
	if w := env.doWithCookie(http.MethodGet, "", CookiePortal, "not-a-session"); w.Code != http.StatusUnauthorized {
		t.Fatalf("method probe on a dead session: want 401, got %d (%s)", w.Code, w.Body.String())
	}
}

// The heart of bug #1: the sudo window is per session namespace. Verifying in
// the console must not open the portal's window (and vice versa) — the old code
// stamped the CONSOLE session from a route the portal had no way to reach, so a
// portal-side gate stayed shut no matter what the user did.
func TestPortalStepUp_NamespacesAreIndependent(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", true)

	consoleSess, err := env.mgr.Create(context.Background(), session.NamespaceConsole, 1, 1, "ip", "ua", "password")
	if err != nil {
		t.Fatalf("create console session: %v", err)
	}
	if w := env.console(http.MethodPost, `{"code":"123456"}`, consoleSess.ID); w.Code != http.StatusOK {
		t.Fatalf("console step-up: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if env.fresh(t) {
		t.Fatal("a CONSOLE step-up must not open the PORTAL window — that was the original bug")
	}

	// And the reverse: the portal step-up leaves the console session alone.
	if w := env.do(http.MethodPost, `{"code":"123456"}`); w.Code != http.StatusOK {
		t.Fatalf("portal step-up: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	got, err := env.mgr.Get(context.Background(), session.NamespaceConsole, consoleSess.ID)
	if err != nil || got == nil {
		t.Fatalf("get console session: %v", err)
	}
	if !got.StepUpFresh(time.Now(), 10*time.Minute) {
		t.Fatal("the console session should still carry its own stamp")
	}
}

// The window is a window: it opens on a passed challenge and closes on its own.
// A stamp that never expired would turn step-up into a one-time formality.
func TestPortalStepUp_WindowExpires(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", true)

	if w := env.do(http.MethodPost, `{"code":"123456"}`); w.Code != http.StatusOK {
		t.Fatalf("step-up: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	sess, err := env.mgr.Get(context.Background(), session.NamespacePortal, env.sid)
	if err != nil || sess == nil {
		t.Fatalf("get session: %v", err)
	}
	if !sess.StepUpFresh(time.Now(), 10*time.Minute) {
		t.Fatal("just-verified session must be inside a 10m window")
	}
	if sess.StepUpFresh(time.Now().Add(11*time.Minute), 10*time.Minute) {
		t.Fatal("the stamp must age out of the window")
	}
	// A zero/negative window means "never fresh", not "always fresh".
	if sess.StepUpFresh(time.Now(), 0) {
		t.Fatal("a zero window must never report fresh")
	}
}

// Brute force: the password fallback shares the MFA step-up's per-user+IP
// limiter, so it is not a softer password oracle than the login form.
func TestPortalStepUp_PasswordFallbackIsRateLimited(t *testing.T) {
	env := newPortalStepUpEnv(t, "Sup3rSecret!", false)

	var last *httptest.ResponseRecorder
	for i := 0; i < 12; i++ {
		last = env.do(http.MethodPost, `{"password":"wrong"}`)
		if last.Code == http.StatusTooManyRequests {
			break
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("repeated wrong passwords must trip the limiter, still got %d", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Fatal("a 429 must carry Retry-After so the SPA can show a countdown")
	}
	// Even the CORRECT password is refused while the limiter holds.
	if w := env.do(http.MethodPost, `{"password":"Sup3rSecret!"}`); w.Code == http.StatusOK {
		t.Fatal("the limiter must hold even for the right password")
	}
	if env.fresh(t) {
		t.Fatal("a rate-limited step-up must not stamp the session")
	}
}

// A locked or disabled account cannot step up, even with the right password —
// the fallback reuses the login provider precisely so account state still rules.
func TestPortalStepUp_PasswordFallbackRespectsAccountState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"locked", statusLocked},
		{"disabled", statusDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newPortalStepUpEnv(t, "Sup3rSecret!", false)
			env.users.status = tc.status

			if w := env.do(http.MethodPost, `{"password":"Sup3rSecret!"}`); w.Code == http.StatusOK {
				t.Fatalf("a %s account must not clear step-up", tc.name)
			}
			if env.fresh(t) {
				t.Fatalf("a %s account must not stamp the session", tc.name)
			}
		})
	}
}
