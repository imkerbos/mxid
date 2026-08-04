package setting

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Shortening audit retention is a way to destroy evidence that leaves no
// evidence, so a deployment can name a floor an administrator may not go under.
func TestValidateAuditPolicy_RejectsBelowFloor(t *testing.T) {
	s := &Service{}
	s.SetAuditRetentionFloor(180)

	err := s.ValidateAuditPolicy(AuditPolicy{RetentionDays: 30})
	if err == nil {
		t.Fatal("a 30-day retention was accepted under a 180-day floor")
	}

	var below ErrRetentionBelowFloor
	if !errors.As(err, &below) {
		t.Fatalf("want ErrRetentionBelowFloor, got %T", err)
	}
	if below.Requested != 30 || below.Floor != 180 {
		t.Errorf("requested/floor = %d/%d, want 30/180", below.Requested, below.Floor)
	}
	// An administrator who is only told "invalid value" has to guess.
	if !strings.Contains(err.Error(), "180") {
		t.Errorf("refusal does not name the floor: %q", err)
	}
}

func TestValidateAuditPolicy_Accepts(t *testing.T) {
	cases := []struct {
		name   string
		floor  int
		policy AuditPolicy
	}{
		{"at the floor", 180, AuditPolicy{RetentionDays: 180}},
		{"above the floor", 180, AuditPolicy{RetentionDays: 365}},
		{"no floor configured", 0, AuditPolicy{RetentionDays: 7}},
		// Retention off keeps every record for ever. A floor exists to stop
		// records being discarded early, so it has nothing to say here.
		{"retention switched off", 180, AuditPolicy{RetentionDays: 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			s.SetAuditRetentionFloor(tc.floor)
			if err := s.ValidateAuditPolicy(tc.policy); err != nil {
				t.Errorf("rejected a legitimate policy: %v", err)
			}
		})
	}
}

// The retention cron purges by whatever AuditPolicy reports, so the clamp has
// to happen there — asserting it against a copy of the rule in the test would
// prove nothing about the code that deletes records.
//
// The write path refuses a sub-floor value, so a stored one means the floor was
// raised later, the deployment predates it, or the row was edited directly. In
// all three the floor is the safer reading, and clamping can only ever retain
// MORE than the stored number asked for.
func TestAuditPolicyClampsStoredValueUpToFloor(t *testing.T) {
	const tenantID int64 = 1

	cases := []struct {
		name   string
		floor  int
		stored int
		want   int
	}{
		{"stored below floor is raised", 180, 30, 180},
		{"stored above floor is untouched", 180, 365, 365},
		{"stored at floor is untouched", 180, 180, 180},
		{"no floor leaves it alone", 0, 7, 7},
		{"retention off stays off", 180, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(newFakeRepo(), nil)
			// Store the sub-floor value the way a pre-floor deployment would
			// have: straight in, without passing through validation.
			if err := svc.Set(context.Background(), KeyAuditPolicy, tenantID,
				&AuditPolicy{RetentionDays: tc.stored}, nil); err != nil {
				t.Fatalf("seed policy: %v", err)
			}
			svc.SetAuditRetentionFloor(tc.floor)

			got, err := svc.AuditPolicy(context.Background(), tenantID)
			if err != nil {
				t.Fatalf("AuditPolicy: %v", err)
			}
			if got.RetentionDays != tc.want {
				t.Errorf("effective retention = %d, want %d", got.RetentionDays, tc.want)
			}
		})
	}
}

// An unconfigured tenant falls back to the 365-day default, which no sane floor
// touches — but the fallback path is a separate branch from the stored one, so
// it gets its own check.
func TestAuditPolicyDefaultIsNotClamped(t *testing.T) {
	svc := NewService(newFakeRepo(), nil)
	svc.SetAuditRetentionFloor(180)

	got, err := svc.AuditPolicy(context.Background(), 1)
	if err != nil {
		t.Fatalf("AuditPolicy: %v", err)
	}
	if got.RetentionDays != DefaultAuditPolicy().RetentionDays {
		t.Errorf("retention = %d, want the %d-day default",
			got.RetentionDays, DefaultAuditPolicy().RetentionDays)
	}
}

func TestSetAuditRetentionFloor_NegativeMeansNoFloor(t *testing.T) {
	s := &Service{}
	s.SetAuditRetentionFloor(-1)
	if got := s.AuditRetentionFloor(); got != 0 {
		t.Errorf("floor = %d, want 0", got)
	}
}

// Alerts go out through safehttp, which permits https only. Storing an http://
// URL would report "saved" and then dead-letter every alert against it — the
// same silent failure the alert webhook was fixed to stop being.
func TestValidateAuditPolicy_RejectsNonHTTPSWebhook(t *testing.T) {
	s := &Service{}

	bad := []string{
		"http://hook.example.com/a",
		"ftp://hook.example.com/a",
		"hook.example.com/a",
		"https://",
	}
	for _, raw := range bad {
		t.Run(raw, func(t *testing.T) {
			err := s.ValidateAuditPolicy(AuditPolicy{AlertWebhookURL: raw})
			if err == nil {
				t.Fatalf("accepted a webhook URL delivery would refuse: %q", raw)
			}
			var e ErrBadAlertWebhookURL
			if !errors.As(err, &e) {
				t.Errorf("want ErrBadAlertWebhookURL, got %T", err)
			}
		})
	}

	if err := s.ValidateAuditPolicy(AuditPolicy{AlertWebhookURL: "https://hook.example.com/a"}); err != nil {
		t.Errorf("rejected a valid https webhook: %v", err)
	}
	// Empty means alerting is off, which is not a misconfiguration.
	if err := s.ValidateAuditPolicy(AuditPolicy{AlertWebhookURL: ""}); err != nil {
		t.Errorf("rejected an empty webhook (alerting off): %v", err)
	}
}
