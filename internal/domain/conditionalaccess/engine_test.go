package conditionalaccess

import (
	"reflect"
	"sort"
	"testing"
)

func TestEvaluate(t *testing.T) {
	allOn := Policy{Enabled: true, OnNewCountry: true, OnImpossibleTravel: true, OnNewDevice: true}

	cases := []struct {
		name        string
		policy      Policy
		signals     Signals
		wantAction  Action
		wantReasons []string
	}{
		{
			name:       "disabled policy is always normal",
			policy:     Policy{Enabled: false, OnNewCountry: true},
			signals:    Signals{NewCountry: true},
			wantAction: ActionNormal,
		},
		{
			name:       "no signals is normal",
			policy:     allOn,
			signals:    Signals{},
			wantAction: ActionNormal,
		},
		{
			name:        "new country requires mfa",
			policy:      allOn,
			signals:     Signals{NewCountry: true},
			wantAction:  ActionRequireMFA,
			wantReasons: []string{"new_country"},
		},
		{
			name:        "new device requires mfa",
			policy:      allOn,
			signals:     Signals{NewDevice: true},
			wantAction:  ActionRequireMFA,
			wantReasons: []string{"new_device"},
		},
		{
			name:        "impossible travel requires mfa",
			policy:      allOn,
			signals:     Signals{ImpossibleTravel: true},
			wantAction:  ActionRequireMFA,
			wantReasons: []string{"impossible_travel"},
		},
		{
			name:        "multiple signals collect all reasons",
			policy:      allOn,
			signals:     Signals{NewCountry: true, NewDevice: true},
			wantAction:  ActionRequireMFA,
			wantReasons: []string{"new_country", "new_device"},
		},
		{
			name:       "signal ignored when its toggle is off",
			policy:     Policy{Enabled: true, OnNewDevice: true}, // new-country off
			signals:    Signals{NewCountry: true},
			wantAction: ActionNormal,
		},
		{
			name:        "trusted network with skip allowed and no risk -> allow skip",
			policy:      Policy{Enabled: true, OnNewDevice: true, AllowTrustedSkip: true},
			signals:     Signals{TrustedNetwork: true},
			wantAction:  ActionAllowSkip,
			wantReasons: []string{"trusted_network"},
		},
		{
			name:       "trusted network but skip not allowed -> normal",
			policy:     Policy{Enabled: true, AllowTrustedSkip: false},
			signals:    Signals{TrustedNetwork: true},
			wantAction: ActionNormal,
		},
		{
			name:        "risk wins over trusted-network skip",
			policy:      Policy{Enabled: true, OnNewDevice: true, AllowTrustedSkip: true},
			signals:     Signals{TrustedNetwork: true, NewDevice: true},
			wantAction:  ActionRequireMFA,
			wantReasons: []string{"new_device"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(tc.policy, tc.signals)
			if got.Action != tc.wantAction {
				t.Fatalf("action = %v, want %v", got.Action, tc.wantAction)
			}
			gotR, wantR := append([]string{}, got.Reasons...), append([]string{}, tc.wantReasons...)
			sort.Strings(gotR)
			sort.Strings(wantR)
			if len(gotR) == 0 {
				gotR = nil
			}
			if len(wantR) == 0 {
				wantR = nil
			}
			if !reflect.DeepEqual(gotR, wantR) {
				t.Fatalf("reasons = %v, want %v", got.Reasons, tc.wantReasons)
			}
		})
	}
}
