package secure

import (
	"regexp"

	"go.uber.org/zap/zapcore"
)

// sensitiveKeyPattern matches field keys whose values should be redacted
// before they hit the log encoder. Case-insensitive substring match.
//
// Extend with care: every entry here is a backstop, NOT a primary
// defense. Code that knows it is touching a secret should wrap the value
// in secure.Secret instead of relying on this regex.
var sensitiveKeyPattern = regexp.MustCompile(`(?i)(password|passwd|secret|api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|private[-_]?key|cookie|authorization|set[-_]?cookie|session[-_]?id|sid|csrf)`)

// RedactingCore wraps a zapcore.Core and rewrites any field whose key
// looks sensitive to "***". The original Core handles encoding / output;
// we only mutate the Field slice before forwarding.
//
// Cost: one regex match per field per log line. Negligible against the
// JSON encode + IO that follows.
type RedactingCore struct {
	zapcore.Core
}

// NewRedactingCore wraps the given core with the redaction filter. Use
// it in bootstrap when constructing the logger; the wrapper participates
// in level + sampling decisions transparently because we embed Core.
func NewRedactingCore(inner zapcore.Core) zapcore.Core {
	return &RedactingCore{Core: inner}
}

// Check forwards level decision then re-wraps the returned entry so our
// own Write is the one that runs.
func (c *RedactingCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// Write redacts sensitive fields then delegates to the wrapped Core.
func (c *RedactingCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	for i := range fields {
		if sensitiveKeyPattern.MatchString(fields[i].Key) {
			fields[i] = redacted(fields[i].Key)
		}
	}
	return c.Core.Write(ent, fields)
}

// With re-wraps so any logger derived via logger.With(...) keeps
// redaction in place.
func (c *RedactingCore) With(fields []zapcore.Field) zapcore.Core {
	for i := range fields {
		if sensitiveKeyPattern.MatchString(fields[i].Key) {
			fields[i] = redacted(fields[i].Key)
		}
	}
	return &RedactingCore{Core: c.Core.With(fields)}
}

func redacted(key string) zapcore.Field {
	return zapcore.Field{
		Key:    key,
		Type:   zapcore.StringType,
		String: "***",
	}
}
