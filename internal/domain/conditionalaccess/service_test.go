package conditionalaccess

import (
	"context"
	"testing"
	"time"
)

type fakeRisk struct{ calls int }

func (f *fakeRisk) Risk(context.Context, int64, int64, string, []string) { f.calls++ }

func buildService(t *testing.T, cfg RuntimeConfig, knownDevice bool, hist fakeHistory, geo fakeGeo) (*Service, *fakeRisk) {
	t.Helper()
	devSvc := NewDeviceService(newFakeRepo(), &seqIDGen{})
	if knownDevice {
		_ = devSvc.Remember(context.Background(), 1, 1, "dev-known", "ua")
	}
	comp := NewSignalComputer(geo, hist, devSvc)
	comp.now = func() time.Time { return time.Unix(100000, 0) }
	risk := &fakeRisk{}
	svc := NewService(func(context.Context, int64) RuntimeConfig { return cfg }, comp, devSvc, risk)
	return svc, risk
}

func TestAssess_DisabledIsNoop(t *testing.T) {
	cfg := RuntimeConfig{Policy: Policy{Enabled: false, OnNewDevice: true}}
	svc, risk := buildService(t, cfg, false, fakeHistory{}, fakeGeo{})
	a, err := svc.Assess(context.Background(), AssessInput{UserID: 1, TenantID: 1, DeviceID: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if a.RequireMFA || risk.calls != 0 {
		t.Fatalf("disabled policy must be a no-op, got %+v risk=%d", a, risk.calls)
	}
}

func TestAssess_RiskWithFactorRequiresMFANoAudit(t *testing.T) {
	cfg := RuntimeConfig{Policy: Policy{Enabled: true, OnNewDevice: true}}
	svc, risk := buildService(t, cfg, false, fakeHistory{}, fakeGeo{})
	a, _ := svc.Assess(context.Background(), AssessInput{UserID: 1, TenantID: 1, DeviceID: "new", CanSecondFactor: true})
	if !a.RequireMFA {
		t.Fatalf("new device must require MFA")
	}
	if risk.calls != 0 {
		t.Fatalf("user with a factor is challenged, not audited; risk calls=%d", risk.calls)
	}
}

func TestAssess_RiskWithoutFactorAuditsAndAllows(t *testing.T) {
	cfg := RuntimeConfig{Policy: Policy{Enabled: true, OnNewDevice: true}}
	svc, risk := buildService(t, cfg, false, fakeHistory{}, fakeGeo{})
	a, _ := svc.Assess(context.Background(), AssessInput{UserID: 1, TenantID: 1, DeviceID: "new", CanSecondFactor: false})
	if !a.RequireMFA {
		t.Fatalf("new device must require MFA")
	}
	if risk.calls != 1 {
		t.Fatalf("risky login with no factor must be audited once, got %d", risk.calls)
	}
}

func TestAssess_KnownDeviceCleanLoginNormal(t *testing.T) {
	cfg := RuntimeConfig{Policy: Policy{Enabled: true, OnNewDevice: true}}
	// Known device + no other risk → no MFA forced (a trusted network would NOT
	// change this; the engine never skips, only adds).
	svc, risk := buildService(t, cfg, true, fakeHistory{}, fakeGeo{})
	a, _ := svc.Assess(context.Background(), AssessInput{UserID: 1, TenantID: 1, IP: "10.1.2.3", DeviceID: "dev-known"})
	if a.RequireMFA || risk.calls != 0 {
		t.Fatalf("known-device clean login must be a no-op, got %+v risk=%d", a, risk.calls)
	}
}
