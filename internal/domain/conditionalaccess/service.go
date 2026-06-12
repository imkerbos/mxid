package conditionalaccess

import (
	"context"
	"time"
)

// RuntimeConfig is the per-tenant policy resolved at request time (from the DB
// security.conditional_access setting).
type RuntimeConfig struct {
	Policy       Policy
	TravelWindow time.Duration
}

// ConfigProvider resolves the runtime config for a tenant.
type ConfigProvider func(ctx context.Context, tenantID int64) RuntimeConfig

// RiskLogger records a risky login that could NOT be challenged with a second
// factor (the A3 audit fallback). Implementation publishes an audit event.
type RiskLogger interface {
	Risk(ctx context.Context, userID, tenantID int64, ip string, reasons []string)
}

// Service composes the policy, signal computer, device store, and risk audit
// into the login-time decision the auth handler consumes. Constructed in main.
type Service struct {
	cfg      ConfigProvider
	computer *SignalComputer
	devices  *DeviceService
	risk     RiskLogger
}

// NewService wires the conditional-access service.
func NewService(cfg ConfigProvider, computer *SignalComputer, devices *DeviceService, risk RiskLogger) *Service {
	return &Service{cfg: cfg, computer: computer, devices: devices, risk: risk}
}

// AssessInput is one login attempt's context for assessment.
type AssessInput struct {
	UserID    int64
	TenantID  int64
	IP        string
	UserAgent string
	DeviceID  string
	// CanSecondFactor is true when the user can actually be challenged (has a
	// factor enrolled). When risk demands MFA but this is false, the login is
	// allowed and audited instead of blocked (A3).
	CanSecondFactor bool
}

// Assessment is the decision returned to the auth handler.
type Assessment struct {
	RequireMFA bool
	Reasons    []string
}

// Assess evaluates a login's risk. Returns an empty assessment (no-op) when
// conditional access is disabled for the tenant. When risk requires MFA but the
// user has no factor, it audits the risky login (A3) and still allows it.
func (s *Service) Assess(ctx context.Context, in AssessInput) (Assessment, error) {
	rc := s.cfg(ctx, in.TenantID)
	if !rc.Policy.Enabled {
		return Assessment{}, nil
	}

	sig, err := s.computer.Compute(ctx, ComputeInput{
		UserID:                 in.UserID,
		IP:                     in.IP,
		DeviceID:               in.DeviceID,
		ImpossibleTravelWindow: rc.TravelWindow,
	})
	if err != nil {
		return Assessment{}, err
	}

	d := Evaluate(rc.Policy, sig)
	a := Assessment{Reasons: d.Reasons}
	if d.Action == ActionRequireMFA {
		a.RequireMFA = true
		if !in.CanSecondFactor && s.risk != nil {
			// A3: risky login the user cannot second-factor — allow, but record.
			s.risk.Risk(ctx, in.UserID, in.TenantID, in.IP, d.Reasons)
		}
	}
	return a, nil
}

// RememberDevice records the device after a successful login so future logins
// from it are recognised. Runs even when conditional access is disabled, so
// device history accumulates before an admin turns the policy on.
func (s *Service) RememberDevice(ctx context.Context, tenantID, userID int64, deviceID, userAgent string) error {
	return s.devices.Remember(ctx, tenantID, userID, deviceID, userAgent)
}
