package geoip

import "testing"

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true}, // link-local
		{"::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700::1111", false},
		// host:port shapes
		{"10.0.0.1:8080", true},
		{"8.8.8.8:443", false},
		{"[::1]:443", true},
		{"not-an-ip", true}, // unparseable → fail closed (treat as private)
	}
	for _, tc := range cases {
		if got := IsPrivateOrLoopback(tc.in); got != tc.want {
			t.Errorf("IsPrivateOrLoopback(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNoopResolver(t *testing.T) {
	loc, err := NoopResolver{}.Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("noop must not error: %v", err)
	}
	if loc != (Location{}) {
		t.Errorf("noop must return empty Location, got %+v", loc)
	}
}

type stubGeo struct{ called bool }

func (s *stubGeo) Lookup(string) (Location, error) {
	s.called = true
	return Location{Country: "US", City: "MV"}, nil
}

func TestPrivateAwareResolver_SkipsPrivate(t *testing.T) {
	inner := &stubGeo{}
	r := PrivateAwareResolver{Inner: inner}
	loc, _ := r.Lookup("10.0.0.1")
	if inner.called {
		t.Errorf("inner resolver called for private IP")
	}
	if loc != (Location{}) {
		t.Errorf("private IP must return empty, got %+v", loc)
	}
}

func TestPrivateAwareResolver_PassesPublic(t *testing.T) {
	inner := &stubGeo{}
	r := PrivateAwareResolver{Inner: inner}
	loc, _ := r.Lookup("8.8.8.8")
	if !inner.called {
		t.Errorf("inner resolver must be called for public IP")
	}
	if loc.Country != "US" || loc.City != "MV" {
		t.Errorf("location not propagated: %+v", loc)
	}
}

func TestPrivateAwareResolver_NilInner(t *testing.T) {
	r := PrivateAwareResolver{Inner: nil}
	loc, err := r.Lookup("8.8.8.8")
	if err != nil || loc != (Location{}) {
		t.Errorf("nil inner must return empty Location, got %+v err=%v", loc, err)
	}
}
