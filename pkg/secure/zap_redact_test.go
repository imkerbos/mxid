package secure

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func newRedactingLogger(t *testing.T) (*zap.Logger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(enc, zapcore.AddSync(buf), zapcore.DebugLevel)
	return zap.New(NewRedactingCore(core)), buf
}

func TestRedacting_KnownSensitiveKeys(t *testing.T) {
	keys := []string{
		"password", "passwd", "secret", "client_secret", "client-secret",
		"api_key", "apikey", "api-key", "access_token", "refresh_token",
		"private_key", "Authorization", "Cookie", "Set-Cookie", "session_id", "sid", "csrf",
	}
	for _, k := range keys {
		logger, buf := newRedactingLogger(t)
		logger.Info("event", zap.String(k, "leak-me"))
		out := buf.String()
		if strings.Contains(out, "leak-me") {
			t.Errorf("key %q leaked: %s", k, strings.TrimSpace(out))
		}
		if !strings.Contains(out, `"`+k+`":"***"`) {
			t.Errorf("key %q not redacted: %s", k, strings.TrimSpace(out))
		}
	}
}

func TestRedacting_NormalFieldsPassThrough(t *testing.T) {
	logger, buf := newRedactingLogger(t)
	logger.Info("event",
		zap.String("user_id", "42"),
		zap.String("path", "/api/v1/users"),
		zap.Int("status", 200),
	)
	out := buf.String()
	if !strings.Contains(out, `"user_id":"42"`) ||
		!strings.Contains(out, `"path":"/api/v1/users"`) ||
		!strings.Contains(out, `"status":200`) {
		t.Errorf("normal fields mangled: %s", strings.TrimSpace(out))
	}
}

func TestRedacting_WithFieldsAlsoMasked(t *testing.T) {
	logger, buf := newRedactingLogger(t)
	scoped := logger.With(zap.String("password", "leak-me"))
	scoped.Info("event")
	out := buf.String()
	if strings.Contains(out, "leak-me") {
		t.Errorf("With() fields not redacted: %s", out)
	}
}
