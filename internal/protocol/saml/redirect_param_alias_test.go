package saml

import (
	"net/url"
	"strings"
	"testing"
)

// The redirect-binding signature is recomputed over the raw bytes selected by
// parseRawRedirectParam, but the handlers that act on the message read it with
// c.Query(), which decodes parameter NAMES. If those two can select different
// occurrences, the signature covers bytes nobody acts on.
//
// Measured before the fix:
//
//	SAMLReque%73t=ATTACKER&SAMLRequest=SIGNED
//	  parseRawRedirectParam -> "SIGNED"    (raw name match, skips the encoded one)
//	  url.Values.Get        -> "ATTACKER"  (decodes the name, takes the first)
//
// An attacker holding any validly signed LogoutRequest — they travel through
// the user's own browser — could prepend their own under an encoded name and
// have it processed. Effect is a forced logout of a chosen user rather than a
// way in, but a signature check that can be routed around is not a check.

// assertAgreesWithHandler pins the invariant directly: whatever the verifier
// selects must be what the handler would act on.
func assertAgreesWithHandler(t *testing.T, rawQuery, key string) {
	t.Helper()
	verified, ok := parseRawRedirectParam(rawQuery, key)
	if !ok {
		return // refusing outright is a safe outcome; the divergence is what is not
	}
	decoded, err := url.QueryUnescape(verified)
	if err != nil {
		t.Fatalf("verifier selected a value that will not decode: %q", verified)
	}
	processed := mustParseQuery(t, rawQuery).Get(key)
	if decoded != processed {
		t.Fatalf("the verifier authenticates %q but the handler acts on %q — "+
			"the signature covers bytes nobody uses", decoded, processed)
	}
}

func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	return v
}

func TestParseRawRedirectParam_RejectsAnEncodedNameAlias(t *testing.T) {
	const q = "SAMLReque%73t=ATTACKER&SAMLRequest=SIGNED&SigAlg=alg&Signature=c2ln"

	if got, ok := parseRawRedirectParam(q, "SAMLRequest"); ok {
		t.Fatalf("accepted a query carrying SAMLRequest twice (once percent-encoded) and returned %q; "+
			"the handler would act on the other copy", got)
	}
	assertAgreesWithHandler(t, q, "SAMLRequest")
}

func TestParseRawRedirectParam_RejectsPlainDuplicates(t *testing.T) {
	const q = "SAMLRequest=FIRST&SAMLRequest=SECOND&SigAlg=alg"

	if got, ok := parseRawRedirectParam(q, "SAMLRequest"); ok {
		t.Fatalf("accepted a duplicated SAMLRequest and returned %q; which copy is authoritative "+
			"is precisely the ambiguity being exploited", got)
	}
	assertAgreesWithHandler(t, q, "SAMLRequest")
}

// TestParseRawRedirectParam_StillSelectsWhatTheHandlerUses is the other half:
// on the queries SPs actually send, the verifier and the handler must agree.
func TestParseRawRedirectParam_StillSelectsWhatTheHandlerUses(t *testing.T) {
	for name, q := range map[string]string{
		"typical redirect binding": "SAMLRequest=fVLL%2FjA&RelayState=https%3A%2F%2Fsp%2Fx&SigAlg=alg&Signature=c2ln",
		"no relay state":           "SAMLRequest=fVLL%2FjA&SigAlg=alg&Signature=c2ln",
		"relay state with plus":    "SAMLRequest=a%2Bb&RelayState=x+y&SigAlg=alg&Signature=c2ln",
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := parseRawRedirectParam(q, "SAMLRequest")
			if !ok {
				t.Fatal("a well-formed query must still yield its SAMLRequest")
			}
			// The raw bytes must survive: the signature is computed over them.
			if got != mustRawValue(t, q, "SAMLRequest") {
				t.Fatalf("value was altered to %q; signature recomputation needs the transmitted bytes", got)
			}
			assertAgreesWithHandler(t, q, "SAMLRequest")
			assertAgreesWithHandler(t, q, "RelayState")
			assertAgreesWithHandler(t, q, "SigAlg")
		})
	}
}

// mustRawValue pulls a value by exact raw name, independent of the function
// under test, so the assertion above does not compare a function with itself.
func mustRawValue(t *testing.T, rawQuery, key string) string {
	t.Helper()
	for _, pair := range strings.Split(rawQuery, "&") {
		if eq := strings.IndexByte(pair, '='); eq >= 0 && pair[:eq] == key {
			return pair[eq+1:]
		}
	}
	t.Fatalf("%q not present in %q", key, rawQuery)
	return ""
}
