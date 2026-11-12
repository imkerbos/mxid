package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxid/pkg/session"
)

// newObligationFixture builds a resolver over miniredis plus a real
// session.Manager. The records are written by the Manager itself rather than by
// a hand-rolled literal: SSOSession decodes whatever pkg/session encoded, so a
// drifting json tag has to fail here instead of silently decoding as false.
func newObligationFixture(t *testing.T, pwdPending, mfaPending bool) (SessionResolver, *session.Manager) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mgr := session.NewManager(rdb, time.Hour, 12*time.Hour)
	if pwdPending {
		mgr.SetPwdChangeDecider(func(context.Context, int64, int64) bool { return true })
	}
	if mfaPending {
		mgr.SetEnrollDecider(func(context.Context, int64, int64) bool { return true })
	}
	return NewSessionResolver(rdb), mgr
}

// A session that still owes a password change must not resolve as an SSO
// session in EITHER namespace. The SPA gates confine such a session to the
// change-password route, but the protocol endpoints read the session store
// directly: before this check, logging in with a reset password and calling a
// protocol SSO endpoint produced an assertion without the password ever being
// changed.
func TestGetSSOSession_PwdChangePending_ResolvesAsNoSession(t *testing.T) {
	for _, ns := range []string{session.NamespacePortal, session.NamespaceProtocol} {
		res, mgr := newObligationFixture(t, true, false)
		ctx := context.Background()
		sess, err := mgr.Create(ctx, ns, 42, 1, "1.2.3.4", "ua", "pwd")
		if err != nil {
			t.Fatalf("[%s] Create: %v", ns, err)
		}
		if !sess.PwdChangePending {
			t.Fatalf("[%s] fixture did not flag the session pending", ns)
		}

		got, err := res.GetSSOSession(ctx, sess.ID)
		if err != nil {
			t.Fatalf("[%s] GetSSOSession: %v", ns, err)
		}
		if got != nil {
			t.Fatalf("[%s] GetSSOSession returned a usable session for a "+
				"pwd-change-pending login — protocol handlers would mint an "+
				"assertion for it", ns)
		}

		got, err = res.GetProtocolSSOSession(ctx, sess.ID)
		if err != nil {
			t.Fatalf("[%s] GetProtocolSSOSession: %v", ns, err)
		}
		if got != nil {
			t.Fatalf("[%s] GetProtocolSSOSession returned a usable session for "+
				"a pwd-change-pending login", ns)
		}
	}
}

// Same for a session owing an MFA enrollment: unlike the password gate, the
// login bridge does write a protocol session for these, so the protocol
// namespace is the live attack path here.
func TestGetSSOSession_MFAEnrollPending_ResolvesAsNoSession(t *testing.T) {
	for _, ns := range []string{session.NamespacePortal, session.NamespaceProtocol} {
		res, mgr := newObligationFixture(t, false, true)
		ctx := context.Background()
		sess, err := mgr.Create(ctx, ns, 42, 1, "1.2.3.4", "ua", "pwd")
		if err != nil {
			t.Fatalf("[%s] Create: %v", ns, err)
		}
		if !sess.MFAEnrollPending {
			t.Fatalf("[%s] fixture did not flag the session pending", ns)
		}

		if got, err := res.GetSSOSession(ctx, sess.ID); err != nil || got != nil {
			t.Fatalf("[%s] GetSSOSession = %+v, %v — want no session for an "+
				"MFA-enrollment-pending login", ns, got, err)
		}
		if got, err := res.GetProtocolSSOSession(ctx, sess.ID); err != nil || got != nil {
			t.Fatalf("[%s] GetProtocolSSOSession = %+v, %v — want no session", ns, got, err)
		}
	}
}

// The counter-test: an ordinary session must still resolve in both namespaces.
// A gate that blocks everything is not a fix.
func TestGetSSOSession_NoObligation_StillResolves(t *testing.T) {
	for _, ns := range []string{session.NamespacePortal, session.NamespaceProtocol} {
		res, mgr := newObligationFixture(t, false, false)
		ctx := context.Background()
		sess, err := mgr.Create(ctx, ns, 42, 1, "1.2.3.4", "ua", "pwd")
		if err != nil {
			t.Fatalf("[%s] Create: %v", ns, err)
		}

		got, err := res.GetSSOSession(ctx, sess.ID)
		if err != nil || got == nil {
			t.Fatalf("[%s] GetSSOSession = %+v, %v — a clean session must resolve", ns, got, err)
		}
		if got.UserID != 42 {
			t.Fatalf("[%s] UserID = %d, want 42", ns, got.UserID)
		}

		// The portal namespace is deliberately invisible to the
		// protocol-only getter; only assert the protocol one.
		if ns == session.NamespaceProtocol {
			if got, err := res.GetProtocolSSOSession(ctx, sess.ID); err != nil || got == nil {
				t.Fatalf("[%s] GetProtocolSSOSession = %+v, %v — want the session", ns, got, err)
			}
		}
	}
}
