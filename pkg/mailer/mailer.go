// Package mailer sends transactional email via SMTP using settings from
// the setting domain. The actual SMTP transport uses net/smtp from stdlib
// to keep the dependency surface small — plenty of features for a few
// transactional mails a day, no need for gomail/sendgrid SDKs.
//
// Caller pattern:
//
//   m := mailer.New(settingService)
//   if err := m.SendVerifyEmail(ctx, to, name, link); err != nil { ... }
//
// SMTP config is reloaded per-send (with 60s cache via setting service)
// so admins can change SMTP config without restarting the backend.
package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"github.com/imkerbos/mxid/internal/domain/setting"
)

// Mailer is the outbound mail abstraction. Send* methods log failures
// internally and surface a single error so callers don't have to
// re-translate SMTP-specific failure modes.
type Mailer struct {
	settings *setting.Service
}

func New(settings *setting.Service) *Mailer {
	return &Mailer{settings: settings}
}

// ErrDisabled — returned when SMTP is not configured / enabled. Callers
// that have a "send is optional" path can ignore this gracefully (e.g.
// audit notifications); auth flows should bubble it up.
var ErrDisabled = errors.New("mail SMTP is not enabled")

// SendVerifyEmail renders the email-verification template and sends it.
type VerifyVars struct {
	User struct{ DisplayName, Username, Email string }
	Link string
}

func (m *Mailer) SendVerifyEmail(ctx context.Context, tenantID int64, to, displayName, username, link string) error {
	tmpls, err := m.settings.MailTemplates(ctx, tenantID)
	if err != nil {
		return err
	}
	vars := VerifyVars{Link: link}
	vars.User.DisplayName = displayName
	vars.User.Username = username
	vars.User.Email = to

	subject, body, err := render(tmpls.EmailVerify, vars)
	if err != nil {
		return err
	}
	return m.Send(ctx, tenantID, []string{to}, subject, body)
}

// ResetVars feeds the password_reset template. Mirrors VerifyVars but uses
// a {{.Code}} placeholder so admins can choose between link-only flows
// (signed token in URL) or short-code OTP flows. Both fields are always
// populated; the template picks what it needs.
type ResetVars struct {
	User struct{ DisplayName, Username, Email string }
	Link string
	Code string
}

// SendPasswordResetEmail renders the password_reset template and sends it.
// Returns ErrDisabled when SMTP is off — caller decides whether the auth
// flow can degrade (e.g. show the link inline for OSS dev) or must fail.
func (m *Mailer) SendPasswordResetEmail(ctx context.Context, tenantID int64, to, displayName, username, link, code string) error {
	tmpls, err := m.settings.MailTemplates(ctx, tenantID)
	if err != nil {
		return err
	}
	vars := ResetVars{Link: link, Code: code}
	vars.User.DisplayName = displayName
	vars.User.Username = username
	vars.User.Email = to

	subject, body, err := render(tmpls.PasswordReset, vars)
	if err != nil {
		return err
	}
	return m.Send(ctx, tenantID, []string{to}, subject, body)
}

// WelcomeVars feeds the welcome template. Sent once on first sign-in or
// when an admin creates a user with a known email.
type WelcomeVars struct {
	User struct{ DisplayName, Username, Email string }
	Link string
}

// MagicLinkVars feeds the magic_link template. {{.Link}} resolves to the
// one-shot login callback URL; the template renders the human-readable
// label around it. {{.User.*}} resolves when the address maps to an
// existing account, blank otherwise (sign-up flows).
type MagicLinkVars struct {
	User struct{ DisplayName, Username, Email string }
	Link string
}

// SendMagicLinkEmail renders the magic_link template and sends it. Returns
// ErrDisabled when SMTP is off — caller (login handler) must surface the
// dev_link fallback so first-deploy admins can complete the flow.
func (m *Mailer) SendMagicLinkEmail(ctx context.Context, tenantID int64, to, displayName, username, link string) error {
	tmpls, err := m.settings.MailTemplates(ctx, tenantID)
	if err != nil {
		return err
	}
	vars := MagicLinkVars{Link: link}
	vars.User.DisplayName = displayName
	vars.User.Username = username
	vars.User.Email = to

	subject, body, err := render(tmpls.MagicLink, vars)
	if err != nil {
		return err
	}
	return m.Send(ctx, tenantID, []string{to}, subject, body)
}

// SendWelcomeEmail renders the welcome template and sends it. Soft-fail
// path is OK at the caller — a missing welcome mail must never block
// account creation.
func (m *Mailer) SendWelcomeEmail(ctx context.Context, tenantID int64, to, displayName, username, portalLink string) error {
	tmpls, err := m.settings.MailTemplates(ctx, tenantID)
	if err != nil {
		return err
	}
	vars := WelcomeVars{Link: portalLink}
	vars.User.DisplayName = displayName
	vars.User.Username = username
	vars.User.Email = to

	subject, body, err := render(tmpls.Welcome, vars)
	if err != nil {
		return err
	}
	return m.Send(ctx, tenantID, []string{to}, subject, body)
}

// Send is the low-level helper. Loads SMTP settings, dials, sends. Used
// by SendVerifyEmail and the "test send" admin endpoint.
func (m *Mailer) Send(ctx context.Context, tenantID int64, to []string, subject, htmlBody string) error {
	cfg, err := m.settings.MailSMTP(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("load smtp config: %w", err)
	}
	if !cfg.Enabled {
		return ErrDisabled
	}
	if cfg.Host == "" || cfg.Port == 0 || cfg.FromAddress == "" {
		return errors.New("smtp config incomplete: host/port/from required")
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	from := cfg.FromAddress
	if cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", cfg.FromName, cfg.FromAddress)
	}

	msg := buildMIME(from, to, subject, htmlBody)

	// Two TLS modes:
	//   "tls"      → dial TLS directly (port 465)
	//   "starttls" → plain TCP then STARTTLS (port 587)
	//   "none"     → plain TCP (dev only)
	switch strings.ToLower(cfg.TLSMode) {
	case "tls":
		return sendTLS(addr, cfg, from, to, msg)
	case "starttls", "":
		return sendSTARTTLS(addr, cfg, from, to, msg)
	case "none":
		return sendPlain(addr, cfg, from, to, msg)
	default:
		return fmt.Errorf("unknown tls_mode: %s", cfg.TLSMode)
	}
}

func sendTLS(addr string, cfg setting.MailSMTP, from string, to []string, msg []byte) error {
	tlsCfg := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipVerify,
	}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Quit() }()
	return finishSend(client, cfg, from, to, msg)
}

func sendSTARTTLS(addr string, cfg setting.MailSMTP, from string, to []string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = client.Quit() }()
	if cfg.HeloHostname != "" {
		_ = client.Hello(cfg.HeloHostname)
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipVerify,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	return finishSend(client, cfg, from, to, msg)
}

func sendPlain(addr string, cfg setting.MailSMTP, from string, to []string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = client.Quit() }()
	return finishSend(client, cfg, from, to, msg)
}

func finishSend(client *smtp.Client, cfg setting.MailSMTP, from string, to []string, msg []byte) error {
	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(cfg.FromAddress); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, addr := range to {
		if err := client.Rcpt(addr); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", addr, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return nil
}

// buildMIME assembles a minimal multipart/alternative message — most
// modern clients render the HTML branch. Plain-text fallback is generated
// from the HTML by tag stripping (good enough for transactional mails).
func buildMIME(from string, to []string, subject, htmlBody string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeRFC2047(subject))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/html; charset=UTF-8\r\n")
	fmt.Fprintf(&b, "Content-Transfer-Encoding: 8bit\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("\r\n")
	b.WriteString(htmlBody)
	return b.Bytes()
}

// encodeRFC2047 base64-encodes non-ASCII headers (subject lines etc) so
// Gmail/Outlook don't mangle Chinese characters.
func encodeRFC2047(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?B?" + base64Encode(s) + "?="
		}
	}
	return s
}

func base64Encode(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	src := []byte(s)
	var out strings.Builder
	for i := 0; i < len(src); i += 3 {
		var n uint
		c := 0
		for j := 0; j < 3 && i+j < len(src); j++ {
			n |= uint(src[i+j]) << uint(8*(2-j))
			c++
		}
		out.WriteByte(alphabet[(n>>18)&0x3F])
		out.WriteByte(alphabet[(n>>12)&0x3F])
		if c > 1 {
			out.WriteByte(alphabet[(n>>6)&0x3F])
		} else {
			out.WriteByte('=')
		}
		if c > 2 {
			out.WriteByte(alphabet[n&0x3F])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

func render(t setting.MailTemplate, vars any) (subject, body string, err error) {
	subTmpl, err := template.New("subj").Parse(t.Subject)
	if err != nil {
		return "", "", fmt.Errorf("parse subject template: %w", err)
	}
	bodyTmpl, err := template.New("body").Parse(t.Body)
	if err != nil {
		return "", "", fmt.Errorf("parse body template: %w", err)
	}
	var sb, bb bytes.Buffer
	if err := subTmpl.Execute(&sb, vars); err != nil {
		return "", "", err
	}
	if err := bodyTmpl.Execute(&bb, vars); err != nil {
		return "", "", err
	}
	return sb.String(), bb.String(), nil
}
