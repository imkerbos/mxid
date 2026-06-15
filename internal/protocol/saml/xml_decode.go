package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// ErrXMLForbiddenDoctype is returned when an inbound SAML payload contains
// a <!DOCTYPE ... > declaration. SAML 2.0 documents MUST NOT carry one
// (saml-core §1.3.1); allowing them is the foothold for XXE and billion-
// laughs entity-expansion attacks.
var ErrXMLForbiddenDoctype = errors.New("saml xml: DOCTYPE declarations are forbidden")

// safeXMLDecode is the single XML entry point for inbound SAML payloads.
//
// Defenses layered here:
//   - Strict tokenizer: rejects malformed XML rather than silently
//     skipping (Go default).
//   - Pre-scan rejects any <!DOCTYPE: the cheapest XXE / billion-laughs
//     mitigation. Go's encoding/xml refuses to resolve external entities
//     out of the box, but a DOCTYPE with internal entities can still
//     trigger O(2^n) expansion through nested <!ENTITY ... > references.
//   - Empty Entity map: defense in depth against the same expansion
//     attack — even if the DOCTYPE check were bypassed, undefined
//     entities make the parser error rather than expand.
//   - CharsetReader=nil: refuse anything not utf-8, preventing
//     charset-smuggling tricks.
//
// Use this everywhere xml.Unmarshal would have been used on attacker-
// controlled bytes. Trusted bytes (e.g. our own metadata we just
// generated) do not need it.
func safeXMLDecode(payload []byte, dst any) error {
	if containsDoctype(payload) {
		return ErrXMLForbiddenDoctype
	}
	dec := xml.NewDecoder(bytes.NewReader(payload))
	dec.Strict = true
	dec.Entity = map[string]string{}
	dec.CharsetReader = nil
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("saml xml: %w", err)
	}
	return nil
}

// containsDoctype performs a quick case-insensitive scan rather than a
// real tokenize because the DOCTYPE token is always at the document
// prologue. We accept a few false positives (e.g. the string DOCTYPE
// appearing inside a base64-encoded blob nested in the XML) — the
// inbound shape is small attacker-controlled XML, not arbitrary data.
func containsDoctype(payload []byte) bool {
	if len(payload) > 64*1024 {
		payload = payload[:64*1024]
	}
	return strings.Contains(strings.ToLower(string(payload)), "<!doctype")
}
