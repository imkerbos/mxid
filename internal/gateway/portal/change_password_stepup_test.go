package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxid/internal/domain/authn"
	"github.com/imkerbos/mxid/pkg/errcode"
)

// A session that just passed MFA must not be challenged again to change its
// password.
//
// Sign-in and the forced change land inside the same 30-second TOTP window, so
// the only code the user has is the one they just spent — re-entering it is
// rejected as a replay. An account forced to change its password at first
// sign-in (the seeded administrator, or anyone an admin just reset) could
// therefore never change it, and every other route stays closed until it does.
// That is a locked-out installation, reached by following the product's own
// instructions.
type stubSessionQuerier struct {
	fresh    bool
	askedFor time.Duration
}

func (s *stubSessionQuerier) ListSessions(context.Context, string, int64) ([]*SessionInfo, error) {
	return nil, nil
}
func (s *stubSessionQuerier) DeleteSession(context.Context, string, string, int64) error { return nil }
func (s *stubSessionQuerier) DeleteAllByUserExcept(context.Context, string, int64, string) error {
	return nil
}
func (s *stubSessionQuerier) MarkStepUpFresh(context.Context, string, string) error { return nil }
func (s *stubSessionQuerier) StepUpFreshWithin(_ context.Context, _, _ string, window time.Duration) bool {
	s.askedFor = window
	return s.fresh
}

// enrolledMFAQuerier reports a verified TOTP factor, which is what makes the
// handler demand a code at all.
type enrolledMFAQuerier struct{ verifyErr error }

func (f enrolledMFAQuerier) ListMFA(context.Context, int64) ([]*MFAInfo, error) {
	return []*MFAInfo{{Type: "totp", Verified: true}}, nil
}
func (f enrolledMFAQuerier) SetupTOTP(context.Context, int64) (string, string, error) {
	return "", "", nil
}
func (f enrolledMFAQuerier) VerifyTOTP(context.Context, int64, string) error { return f.verifyErr }
func (f enrolledMFAQuerier) DeleteTOTP(context.Context, int64) error        { return nil }
func (f enrolledMFAQuerier) GenerateBackupCodes(context.Context, int64) ([]string, error) {
	return nil, nil
}
func (f enrolledMFAQuerier) CountBackupCodes(context.Context, int64) (int, error) { return 0, nil }

// recordingUserQuerier records whether the password actually changed. Only
// ChangePassword matters here; the rest satisfy the interface.
type recordingUserQuerier struct{ changed bool }

func (u *recordingUserQuerier) ChangePassword(context.Context, int64, string, string) error {
	u.changed = true
	return nil
}
func (u *recordingUserQuerier) GetByID(context.Context, int64) (*UserInfo, error) { return nil, nil }
func (u *recordingUserQuerier) GetDetail(context.Context, int64) (*UserDetail, error) {
	return nil, nil
}
func (u *recordingUserQuerier) UpdateProfile(context.Context, int64, string, string, string) error {
	return nil
}
func (u *recordingUserQuerier) UpdateAvatar(context.Context, int64, string) error       { return nil }
func (u *recordingUserQuerier) SetInitialPassword(context.Context, int64, string) error { return nil }
func (u *recordingUserQuerier) MarkEmailVerified(context.Context, int64) error          { return nil }
func (u *recordingUserQuerier) GetEmail(context.Context, int64) (string, error)         { return "", nil }
func (u *recordingUserQuerier) LookupByEmail(context.Context, int64, string) (int64, error) {
	return 0, nil
}
func (u *recordingUserQuerier) ResetPassword(context.Context, int64, string) error { return nil }
func (u *recordingUserQuerier) LookupByPhone(context.Context, int64, string) (int64, error) {
	return 0, nil
}
func (u *recordingUserQuerier) UpdateLastLogin(context.Context, int64, string) error { return nil }

func postChangePassword(t *testing.T, h *SecurityHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(authn.CtxUserID, int64(7))
		c.Set(authn.CtxSessionID, "sess-1")
		c.Next()
	})
	r.POST("/security/password", h.changePassword)

	req := httptest.NewRequest(http.MethodPost, "/security/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestChangePassword_FreshStepUpNeedsNoSecondCode(t *testing.T) {
	sess := &stubSessionQuerier{fresh: true}
	users := &recordingUserQuerier{}
	h := &SecurityHandler{
		namespace:      "portal",
		userQuerier:    users,
		sessionQuerier: sess,
		mfaQuerier:     enrolledMFAQuerier{},
		mfaRateLimiter: nil,
		stepUpWindowFn: func() time.Duration { return 12 * time.Minute },
	}

	w := postChangePassword(t, h, `{"old_password":"Old@Password1","new_password":"New@Password1"}`)

	if w.Code == http.StatusBadRequest && strings.Contains(w.Body.String(), "totp") {
		t.Fatalf("a session that just verified MFA was challenged again: %s", w.Body.String())
	}
	if !users.changed {
		t.Fatalf("the password was not changed (status=%d body=%s)", w.Code, w.Body.String())
	}
	if sess.askedFor != 12*time.Minute {
		t.Errorf("freshness was checked against %v, not the configured window — the handler and "+
			"StepUpMiddleware must agree on how recent \"recent\" is", sess.askedFor)
	}
}

// Outside the window the code is still required: the sudo window is the whole
// concession, and dropping the check entirely would let a hijacked session
// change the password using only a stolen old one.
func TestChangePassword_StaleStepUpStillDemandsACode(t *testing.T) {
	users := &recordingUserQuerier{}
	h := &SecurityHandler{
		namespace:      "portal",
		userQuerier:    users,
		sessionQuerier: &stubSessionQuerier{fresh: false},
		mfaQuerier:     enrolledMFAQuerier{},
		stepUpWindowFn: func() time.Duration { return time.Minute },
	}

	w := postChangePassword(t, h, `{"old_password":"Old@Password1","new_password":"New@Password1"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 demanding a code, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), itoaCode(errcode.NumTOTPRequired)) {
		t.Errorf("want business code %d so the SPA can reveal the field, got %s",
			errcode.NumTOTPRequired, w.Body.String())
	}
	if users.changed {
		t.Error("the password changed without a code on a stale session")
	}
}

func itoaCode(n int) string {
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
