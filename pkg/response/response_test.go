package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func newTestContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/console/whatever", nil)
	return c, rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) Response {
	t.Helper()
	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return body
}

// TestInternalError_WithCauseAndLogger verifies the cause is logged at ERROR
// level with useful context, while the client-facing body stays generic and
// never contains the raw error text.
func TestInternalError_WithCauseAndLogger(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	SetLogger(zap.New(core))
	t.Cleanup(func() { SetLogger(nil) })

	c, rec := newTestContext(t)
	cause := errors.New("db connection refused: secret-dsn-leak")

	InternalError(c, "something went wrong", cause)

	// Response body: generic message, code 50001, no leaked error text.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := decodeBody(t, rec)
	if body.Code != 50001 {
		t.Fatalf("code = %d, want 50001", body.Code)
	}
	if body.Message != "something went wrong" {
		t.Fatalf("message = %q, want %q", body.Message, "something went wrong")
	}
	if strings.Contains(rec.Body.String(), cause.Error()) {
		t.Fatalf("response body leaked the underlying error: %s", rec.Body.String())
	}

	// Log side: the cause must have been recorded.
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Level != zapcore.ErrorLevel {
		t.Fatalf("log level = %v, want ERROR", entry.Level)
	}
	fields := entry.ContextMap()
	if fields["error"] != cause.Error() {
		t.Fatalf("logged error field = %v, want %q", fields["error"], cause.Error())
	}
	if fields["message"] != "something went wrong" {
		t.Fatalf("logged message field = %v", fields["message"])
	}
	if fields["method"] != http.MethodGet {
		t.Fatalf("logged method field = %v", fields["method"])
	}
	if fields["path"] != "/api/v1/console/whatever" {
		t.Fatalf("logged path field = %v", fields["path"])
	}
}

// TestInternalError_WithRequestID verifies request_id is included in the log
// fields when present on the gin context (set by the RequestID middleware in
// real requests).
func TestInternalError_WithRequestID(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	SetLogger(zap.New(core))
	t.Cleanup(func() { SetLogger(nil) })

	c, _ := newTestContext(t)
	c.Set("request_id", "req-123")

	InternalError(c, "boom", errors.New("root cause"))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	if got := entries[0].ContextMap()["request_id"]; got != "req-123" {
		t.Fatalf("request_id field = %v, want req-123", got)
	}
}

// TestInternalError_NoCause verifies the no-cause call path (all ~150
// existing call sites) still compiles, doesn't panic, doesn't log anything,
// and still writes the generic 500 body.
func TestInternalError_NoCause(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	SetLogger(zap.New(core))
	t.Cleanup(func() { SetLogger(nil) })

	c, rec := newTestContext(t)

	InternalError(c, "no cause here")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := decodeBody(t, rec)
	if body.Code != 50001 || body.Message != "no cause here" {
		t.Fatalf("unexpected body: %+v", body)
	}
	if len(logs.All()) != 0 {
		t.Fatalf("expected no log entries when no cause is given, got %d", len(logs.All()))
	}
}

// TestInternalError_NoLogger verifies that with a cause but no logger wired
// (SetLogger never called, or called with nil), InternalError doesn't panic
// and the response is unaffected.
func TestInternalError_NoLogger(t *testing.T) {
	SetLogger(nil)
	t.Cleanup(func() { SetLogger(nil) })

	c, rec := newTestContext(t)

	InternalError(c, "still works", errors.New("some cause"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := decodeBody(t, rec)
	if body.Code != 50001 || body.Message != "still works" {
		t.Fatalf("unexpected body: %+v", body)
	}
}
