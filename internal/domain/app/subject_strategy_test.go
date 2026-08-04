package app

// The subject strategy decides what identifier MXID writes into the protocol
// response, and the three protocols put it somewhere with a different audience.
//
// A single shared default used to serve all of them, and the OIDC-shaped answer
// won: every CAS app created through the console emitted a snowflake id as
// `cas:user`, so JumpServer / Redmine / Zabbix — which key local accounts off
// that value — would have created accounts named "800000000000000001". The
// documentation, the mxid_app column default and the seeded demo apps all said
// the default was the username; only the runtime setting disagreed.

import "testing"

func TestSubjectDefaultsAreChosenPerProtocol(t *testing.T) {
	d := ProtocolDefaults{
		OIDCSubject: SubjectStrategyPersistentID,
		SAMLSubject: SubjectStrategyUsername,
		CASSubject:  SubjectStrategyUsername,
	}

	cases := map[string]string{
		ProtocolOIDC: SubjectStrategyPersistentID,
		ProtocolSAML: SubjectStrategyUsername,
		ProtocolCAS:  SubjectStrategyUsername,
	}
	for protocol, want := range cases {
		if got := d.subjectFor(protocol); got != want {
			t.Errorf("protocol %q: subject default = %q, want %q", protocol, got, want)
		}
	}
}

// An OIDC `sub` must stay opaque and survive a rename. If this ever flips to a
// username, every downstream SP loses the ability to recognise a renamed user.
func TestOIDCSubjectDefaultStaysOpaque(t *testing.T) {
	d := ProtocolDefaults{OIDCSubject: SubjectStrategyPersistentID}
	if got := d.subjectFor(ProtocolOIDC); got == SubjectStrategyUsername {
		t.Fatal("the OIDC subject default became the username; a rename would " +
			"then present as a different person to every relying party")
	}
}

// An unknown or empty protocol falls back to the OIDC slot rather than to "",
// so a new protocol cannot silently end up with no configured default.
func TestUnknownProtocolFallsBackToTheOIDCSlot(t *testing.T) {
	d := ProtocolDefaults{OIDCSubject: SubjectStrategyPersistentID}
	for _, protocol := range []string{"", "ldap", "something-new"} {
		if got := d.subjectFor(protocol); got != SubjectStrategyPersistentID {
			t.Errorf("protocol %q: got %q, want the OIDC slot", protocol, got)
		}
	}
}

// A deployment that has never customised the setting, and one that customised
// only the OIDC value, must both still get a username for CAS and SAML. The
// second case is the upgrade path: stored settings rows predate the new fields,
// so they unmarshal as empty and the caller keeps its own fallback.
func TestUnconfiguredProtocolLeavesTheCallerFallback(t *testing.T) {
	var none ProtocolDefaults
	for _, protocol := range []string{ProtocolOIDC, ProtocolSAML, ProtocolCAS} {
		if got := none.subjectFor(protocol); got != "" {
			t.Errorf("protocol %q: unset defaults returned %q, want empty so the "+
				"caller's own fallback applies", protocol, got)
		}
	}

	oidcOnly := ProtocolDefaults{OIDCSubject: SubjectStrategyPersistentID}
	if got := oidcOnly.subjectFor(ProtocolCAS); got != "" {
		t.Fatalf("a settings row that only configures the OIDC subject returned %q "+
			"for CAS; it must leave CAS to the caller's fallback (username)", got)
	}
}
