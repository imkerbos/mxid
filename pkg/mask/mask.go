// Package mask provides PII redaction helpers for API responses.
//
// Rule of thumb: never mask at the model or repository layer. PII lives in
// the database untouched; masking happens at the DTO boundary right before
// JSON serialization. This keeps internal logic (deduplication, joins,
// notifications) working on the real values while preserving the leak-
// minimization invariant at the wire boundary.
//
// # Known gap: no separate permission for the full value
//
// The intended design is that an admin endpoint returning unmasked PII sits
// behind its own permission AND emits an audit event. Only the second half
// ships today.
//
// What is actually true: GET /users/:id and GET /users/:id/detail return
// phone, email and the detail block (address, employee_no, birthday)
// unmasked, and both are gated by the SAME `user.read` as the masked list
// endpoint — there is no `user.read.pii` permission in the catalog or in any
// migration. So "can list users" is also "can read every user's raw PII".
// GET /users/:id does emit the audit event (`user.pii_view`, chain class
// sensitive_read); GET /users/:id/detail does not.
//
// Closing it means adding a permission code, a migration, and a grant path
// for already-deployed instances — a product decision, not a refactor. Until
// that happens, do not cite a dedicated PII permission as an existing
// control.
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
//	"alice@gmail.com"        → "a***e@gmail.com"
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
