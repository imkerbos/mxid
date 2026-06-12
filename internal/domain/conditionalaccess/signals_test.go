package conditionalaccess

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/geoip"
)

type fakeGeo map[string]string // ip -> ISO country

func (f fakeGeo) Lookup(ip string) (geoip.Location, error) {
	return geoip.Location{Country: f[ip]}, nil
}

type fakeHistory []LoginEvent

func (f fakeHistory) RecentSuccessful(context.Context, int64, int) ([]LoginEvent, error) {
	return []LoginEvent(f), nil
}

type fakeDev struct{ known bool }

func (f fakeDev) IsKnown(context.Context, int64, string) (bool, error) { return f.known, nil }

func newComputer(geo fakeGeo, hist fakeHistory, knownDevice bool, now time.Time) *SignalComputer {
	c := NewSignalComputer(geo, hist, fakeDev{known: knownDevice})
	c.now = func() time.Time { return now }
	return c
}

func TestCompute_NewDevice(t *testing.T) {
	c := newComputer(fakeGeo{}, fakeHistory{}, false, time.Unix(1000, 0))
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "8.8.8.8", DeviceID: "d1"})
	if !s.NewDevice {
		t.Fatalf("unknown device must be NewDevice")
	}

	c2 := newComputer(fakeGeo{}, fakeHistory{}, true, time.Unix(1000, 0))
	s2, _ := c2.Compute(context.Background(), ComputeInput{UserID: 1, IP: "8.8.8.8", DeviceID: "d1"})
	if s2.NewDevice {
		t.Fatalf("known device must not be NewDevice")
	}
}

func TestCompute_NewCountry(t *testing.T) {
	geo := fakeGeo{"1.1.1.1": "US", "2.2.2.2": "CN"}
	now := time.Unix(100000, 0)

	// History only from US; current login from CN → new country.
	hist := fakeHistory{{IP: "1.1.1.1", At: now.Add(-48 * time.Hour)}}
	c := newComputer(geo, hist, true, now)
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d"})
	if !s.NewCountry {
		t.Fatalf("CN login with only US history must be NewCountry")
	}

	// Current country already in history → not new.
	s2, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "1.1.1.1", DeviceID: "d"})
	if s2.NewCountry {
		t.Fatalf("US login with US history must not be NewCountry")
	}
}

func TestCompute_FirstLoginNoGeoSignals(t *testing.T) {
	c := newComputer(fakeGeo{"2.2.2.2": "CN"}, fakeHistory{}, false, time.Unix(1, 0))
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d"})
	if s.NewCountry || s.ImpossibleTravel {
		t.Fatalf("empty history must not raise geo signals, got %+v", s)
	}
}

func TestCompute_ImpossibleTravel(t *testing.T) {
	geo := fakeGeo{"1.1.1.1": "US", "2.2.2.2": "CN"}
	now := time.Unix(100000, 0)
	window := time.Hour

	// Last login US 30 min ago, now CN → impossible travel.
	hist := fakeHistory{{IP: "1.1.1.1", At: now.Add(-30 * time.Minute)}}
	c := newComputer(geo, hist, true, now)
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d", ImpossibleTravelWindow: window})
	if !s.ImpossibleTravel {
		t.Fatalf("US→CN in 30min must be impossible travel")
	}

	// Same hop but 2h ago → outside window, not impossible.
	hist2 := fakeHistory{{IP: "1.1.1.1", At: now.Add(-2 * time.Hour)}}
	c2 := newComputer(geo, hist2, true, now)
	s2, _ := c2.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d", ImpossibleTravelWindow: window})
	if s2.ImpossibleTravel {
		t.Fatalf("US→CN in 2h must NOT be impossible travel")
	}
}

func TestCompute_TrustedNetworkAndUnknownGeo(t *testing.T) {
	// Trusted CIDR matches; geo unknown (empty) so no geo signals fire.
	c := newComputer(fakeGeo{}, fakeHistory{{IP: "9.9.9.9", At: time.Unix(1, 0)}}, true, time.Unix(100, 0))
	s, _ := c.Compute(context.Background(), ComputeInput{
		UserID: 1, IP: "10.0.0.5:443", DeviceID: "d",
		TrustedCIDRs:           []string{"10.0.0.0/8"},
		ImpossibleTravelWindow: time.Hour,
	})
	if !s.TrustedNetwork {
		t.Fatalf("10.0.0.5 must match 10.0.0.0/8")
	}
	if s.NewCountry || s.ImpossibleTravel {
		t.Fatalf("unknown geo must not raise geo signals")
	}
}

func TestIPInAnyCIDR(t *testing.T) {
	cases := []struct {
		ip    string
		cidrs []string
		want  bool
	}{
		{"10.0.0.5", []string{"10.0.0.0/8"}, true},
		{"10.0.0.5:443", []string{"10.0.0.0/8"}, true},
		{"192.168.1.1", []string{"10.0.0.0/8"}, false},
		{"203.0.113.7", []string{"203.0.113.0/24", "10.0.0.0/8"}, true},
		{"bad-ip", []string{"10.0.0.0/8"}, false},
		{"10.0.0.5", []string{"not-a-cidr"}, false},
	}
	for _, tc := range cases {
		if got := ipInAnyCIDR(tc.ip, tc.cidrs); got != tc.want {
			t.Errorf("ipInAnyCIDR(%q,%v)=%v want %v", tc.ip, tc.cidrs, got, tc.want)
		}
	}
}
