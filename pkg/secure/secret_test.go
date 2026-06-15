package secure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestSecret_StringMasked(t *testing.T) {
	s := Secret("hunter2")
	if s.String() != "***" {
		t.Errorf("String must mask, got %q", s.String())
	}
	if got := fmt.Sprintf("%v", s); got != "***" {
		t.Errorf("%%v must mask, got %q", got)
	}
	if got := fmt.Sprintf("%#v", s); got != "secure.Secret(***)" {
		t.Errorf("%%#v must mask, got %q", got)
	}
}

func TestSecret_Reveal(t *testing.T) {
	s := Secret("hunter2")
	if s.Reveal() != "hunter2" {
		t.Errorf("Reveal must return raw, got %q", s.Reveal())
	}
}

func TestSecret_MarshalJSON(t *testing.T) {
	payload := struct {
		Token Secret `json:"token"`
	}{Token: "topsecret"}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(b) != `{"token":"***"}` {
		t.Errorf("Marshal leaked, got %s", b)
	}
}

func TestSecret_ZapObjectMarshaler(t *testing.T) {
	buf := &bytes.Buffer{}
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(enc, zapcore.AddSync(buf), zapcore.DebugLevel)
	logger := zap.New(core)

	logger.Info("login", zap.Object("password", Secret("hunter2")))
	out := buf.String()
	if bytes.Contains([]byte(out), []byte("hunter2")) {
		t.Errorf("zap leaked raw secret: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte(`"value":"***"`)) {
		t.Errorf("expected masked value in zap output, got %s", out)
	}
}
