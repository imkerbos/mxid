// Package conditionalaccess holds the adaptive-authentication decision engine:
// given a login's risk signals and the tenant's policy, decide whether to force
// a second factor, allow a low-friction skip, or keep the default behaviour.
//
// The Evaluate function is pure — signal computation (geo, login history,
// device recognition, network matching) lives in adapters that fill Signals.
// This keeps the security-critical decision logic trivially testable.
package conditionalaccess

// Action is the engine's verdict for a login attempt.
type Action int

const (
	// ActionNormal keeps the existing login behaviour (MFA iff the user has a
	// factor enrolled). Used when conditional access is off or sees no signal.
	ActionNormal Action = iota
	// ActionRequireMFA forces a second factor because a risk signal fired —
	// even for a user who would not otherwise be challenged.
	ActionRequireMFA
)

// Policy is the tenant's admin-configured rule set (DB-backed). Every toggle
// defaults to the zero value (off), so an unconfigured tenant keeps today's
// behaviour (Evaluate returns ActionNormal). The engine only ever ADDS a
// factor on risk — it never skips MFA (a trusted network still requires it).
type Policy struct {
	Enabled            bool
	OnNewCountry       bool // require MFA on login from a country never seen before
	OnImpossibleTravel bool // require MFA when the geo/time delta is physically implausible
	OnNewDevice        bool // require MFA from an unrecognised device
}

// Signals are the computed facts about one login attempt. Adapters fill these.
type Signals struct {
	NewCountry       bool
	ImpossibleTravel bool
	NewDevice        bool
}

// Decision is the engine output. Reasons carries machine tags for the audit
// trail (e.g. "new_country", "impossible_travel").
type Decision struct {
	Action  Action
	Reasons []string
}

// Evaluate maps (policy, signals) to a decision. Pure and deterministic. The
// engine only ever forces MFA on a risk signal; it never skips MFA.
func Evaluate(p Policy, s Signals) Decision {
	if !p.Enabled {
		return Decision{Action: ActionNormal}
	}

	var reasons []string
	if p.OnNewCountry && s.NewCountry {
		reasons = append(reasons, "new_country")
	}
	if p.OnImpossibleTravel && s.ImpossibleTravel {
		reasons = append(reasons, "impossible_travel")
	}
	if p.OnNewDevice && s.NewDevice {
		reasons = append(reasons, "new_device")
	}

	if len(reasons) > 0 {
		return Decision{Action: ActionRequireMFA, Reasons: reasons}
	}
	return Decision{Action: ActionNormal}
}
