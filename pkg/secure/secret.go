// Package secure offers wrapper types whose String / encoding methods
// suppress the raw value. Use Secret for password hashes, JWT signing
// keys, API tokens, and any other field where the cost of an accidental
// log line is high.
//
// The wrapper is opt-in by design: callers that genuinely need the value
// (e.g. bcrypt.CompareHashAndPassword, jwt.Sign) call Reveal() so the
// reveal is searchable in code review. Anything else gets "***".
package secure

import (
	"encoding/json"

	"go.uber.org/zap/zapcore"
)

// Secret wraps a sensitive string. Behaviours:
//
//   - String() returns "***"
//   - GoString() returns "secure.Secret(***)" so %#v in a panic dump
//     stays masked
//   - MarshalJSON returns "\"***\"" so accidental encoding/json on a
//     struct containing this field doesn't leak the value
//   - MarshalLogObject implements zapcore.ObjectMarshaler so zap.Object
//     ("password", secret) emits {"value":"***"}
//   - Reveal() returns the raw value; callers MUST use it deliberately
type Secret string

// Reveal returns the unmasked value. Audited at code review by grep —
// keep call sites few.
func (s Secret) Reveal() string { return string(s) }

func (Secret) String() string   { return mask }
func (Secret) GoString() string { return "secure.Secret(" + mask + ")" }

// MarshalJSON masks the value when the wrapping struct is JSON-encoded
// (which includes the path Gin uses to render responses).
func (Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(mask)
}

// MarshalLogObject implements zap's ObjectMarshaler so structured loggers
// drop the value to "***" automatically.
func (Secret) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("value", mask)
	return nil
}

const mask = "***"
