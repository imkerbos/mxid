package sms

// Twilio REST API: POST https://api.twilio.com/2010-04-01/Accounts/{AccountSID}/Messages.json
// Auth: HTTP Basic (AccountSID : AuthToken). Body: x-www-form-urlencoded with
// From, To, Body. The `code` we receive is interpolated into a hard-coded
// English template — Twilio's "Verify" service (separate product) would be
// the production choice but requires SDK + dedicated service SID; we stay
// on the basic Messages endpoint here for OSS simplicity.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/imkerbos/mxid/internal/domain/setting"
)

type twilioSender struct{}

func (twilioSender) SendCode(ctx context.Context, cfg setting.SMS, phone, code string) error {
	if cfg.AccessKey == "" || cfg.Secret == "" || cfg.SignName == "" {
		// SignName doubles as the From number for Twilio. Naming is
		// awkward (Aliyun calls it "signature"), but reusing one field
		// avoids per-provider schema explosion in the settings UI.
		return fmt.Errorf("twilio: account_sid (access_key), auth_token (secret), and from-number (sign_name) required")
	}

	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", cfg.AccessKey)
	body := url.Values{}
	body.Set("From", cfg.SignName)
	body.Set("To", phone)
	body.Set("Body", fmt.Sprintf("Your verification code is %s. Valid for 5 minutes.", code))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(cfg.AccessKey, cfg.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("twilio send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("twilio send status %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}
