package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/imkerbos/mxid/internal/domain/auditalert"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/outbox"
	"github.com/imkerbos/mxid/pkg/safehttp"
)

// newAuditAlertHandler returns the outbox handler that delivers an audit alert
// to the administrator's webhook.
//
// The URL is read at DELIVERY time rather than captured at enqueue, so
// correcting a mistyped one also rescues the alerts already queued behind it.
// Egress goes through safehttp because the URL is administrator-supplied and
// therefore an SSRF primitive: without the guard, "alert me about audit events"
// becomes "fetch this internal address for me, repeatedly, on a schedule I
// control".
func newAuditAlertHandler(settings *setting.Service) outbox.Handler {
	client := safehttp.New(safehttp.WithTimeout(10 * time.Second))
	return func(ctx context.Context, msg *outbox.Message) error {
		pol, err := settings.AuditPolicy(ctx, msg.TenantID)
		if err != nil {
			return fmt.Errorf("load audit policy: %w", err)
		}
		if pol.AlertWebhookURL == "" {
			// Cleared since the message was enqueued. Nothing to deliver, and
			// nowhere to deliver it — done rather than retried for ever.
			return nil
		}

		var alert auditalert.Alert
		if err := json.Unmarshal(msg.Payload, &alert); err != nil {
			// A payload this process wrote and cannot read back will not become
			// readable on the fourth attempt. Report it and let the outbox
			// dead-letter it rather than burning retries.
			return fmt.Errorf("decode audit alert payload: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, pol.AlertWebhookURL,
			bytes.NewReader(msg.Payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MXID-Event", "audit.alert")
		// The audited event type as its own header, so a receiver can route
		// without parsing the body.
		req.Header.Set("X-MXID-Audit-Event", alert.EventType)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("post audit alert: %w", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("audit alert webhook returned status %d", resp.StatusCode)
		}
		return nil
	}
}
