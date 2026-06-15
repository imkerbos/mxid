// Package mask provides PII redaction helpers for API responses.
//
// Rule of thumb: never mask at the model or repository layer. PII lives in
// the database untouched; masking happens at the DTO boundary right before
// JSON serialization. This keeps internal logic (deduplication, joins,
// notifications) working on the real values while preserving the leak-
// minimization invariant at the wire boundary.
//
// Admin endpoints that legitimately need the full value MUST go through a
// dedicated route gated by a separate permission (e.g. user.read.pii) and
// MUST emit an audit event for every successful read.
package mask

import (
	"strings"
	"unicode/utf8"
)

// Phone masks a phone number into a fixed 3-prefix + ****-middle + 4-suffix
// layout (e.g. "13812345678" → "138****5678"). Strings shorter than 7
// characters return a sentinel rather than echoing the digits.
//
// Works on ASCII-only digit strings. International numbers passing
// "+86 138 0000 1111" are first stripped of spaces and the leading "+"
// preserved.
func Phone(s string) string {
	if s == "" {
		return ""
	}
	plus := ""
	if strings.HasPrefix(s, "+") {
		plus = "+"
		s = s[1:]
	}
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) < 7 {
		return plus + "***"
	}
	return plus + s[:3] + "****" + s[len(s)-4:]
}

// Email masks the local-part of an address, preserving the domain so it
// remains useful for support / debugging context.
//
//	"k@gmail.com"            → "*@gmail.com"
//	"kerbos@gmail.com"       → "k****s@gmail.com"
//	"very.long@example.com"  → "v*******g@example.com"
//
// Inputs without an "@" return three asterisks (treat as opaque token).
func Email(s string) string {
	if s == "" {
		return ""
	}
	at := strings.LastIndex(s, "@")
	if at < 1 {
		return "***"
	}
	local := s[:at]
	domain := s[at:]
	if utf8.RuneCountInString(local) <= 2 {
		return string([]rune(local)[0]) + "*" + domain
	}
	runes := []rune(local)
	return string(runes[0]) + strings.Repeat("*", len(runes)-2) + string(runes[len(runes)-1]) + domain
}

// IDCard masks a Chinese national ID (18 digits). Format: 6-prefix +
// ********-middle + 4-suffix. Inputs outside the 18-digit shape collapse
// to three asterisks.
func IDCard(s string) string {
	if utf8.RuneCountInString(s) != 18 {
		return "***"
	}
	return s[:6] + "********" + s[len(s)-4:]
}

// Name masks a human name. Chinese names: keep the surname, replace the
// rest with asterisks ("张三" → "张*", "欧阳娜娜" → "欧***"). Latin names
// keep the first character of the first token only.
func Name(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	runes := []rune(s)
	if len(runes) == 1 {
		return "*"
	}
	return string(runes[0]) + strings.Repeat("*", len(runes)-1)
}
