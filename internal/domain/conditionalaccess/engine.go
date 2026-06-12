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
	// ActionAllowSkip permits skipping an otherwise-mandatory MFA because the
	// login is from a trusted network with no risk signals (opt-in friction
	// reduction).
	ActionAllowSkip
)

// Policy is the tenant's admin-configured rule set (DB-backed). Every toggle
// defaults to the zero value (off), so an unconfigured tenant keeps today's
// behaviour (Evaluate returns ActionNormal).
type Policy struct {
	Enabled            bool
	OnNewCountry       bool // require MFA on login from a country never seen before
	OnImpossibleTravel bool // require MFA when the geo/time delta is physically implausible
	OnNewDevice        bool // require MFA from an unrecognised device
	// AllowTrustedSkip lets a trusted-network login skip the MFA the user would
	// otherwise perform. Off by default — adding friction on risk is safe;
	// removing it must be a deliberate opt-in.
	AllowTrustedSkip bool
}

// Signals are the computed facts about one login attempt. Adapters fill these.
type Signals struct {
	NewCountry       bool
	ImpossibleTravel bool
	NewDevice        bool
	TrustedNetwork   bool
}

// Decision is the engine output. Reasons carries machine tags for the audit
// trail (e.g. "new_country", "impossible_travel").
type Decision struct {
	Action  Action
	Reasons []string
}

// Evaluate maps (policy, signals) to a decision. Pure and deterministic.
//
// Precedence: any active risk signal forces MFA and wins over a trusted-network
// skip — a new device on the corporate network still gets challenged. The
// low-friction skip applies only to an otherwise-clean login from a trusted
// network when the policy opts in.
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

	if s.TrustedNetwork && p.AllowTrustedSkip {
		return Decision{Action: ActionAllowSkip, Reasons: []string{"trusted_network"}}
	}

	return Decision{Action: ActionNormal}
}
