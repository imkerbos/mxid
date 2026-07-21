package saml

// SAMLConfig holds SAML-specific settings from app.protocol_config JSONB.
//
// Field names mirror what the console UI writes; backend Unmarshal is the
// single source of truth. Don't add aliases — keep one canonical key per
// setting so the UI ↔ backend contract stays auditable.
type SAMLConfig struct {
	SPEntityID         string            `json:"sp_entity_id"`        // SP's entity ID (from SP metadata)
	ACSURL             string            `json:"acs_url"`             // Assertion Consumer Service URL — where IdP POSTs the SAML Response
	SLOURL             string            `json:"slo_url"`             // Single Logout Service URL on the SP
	SPCert             string            `json:"sp_cert"`             // SP's X.509 certificate (PEM). Used to verify signed AuthnRequest / encrypt assertion to SP
	NameIDFormat       string            `json:"name_id_format"`      // urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress | persistent | unspecified | transient
	SignAssertions     bool              `json:"sign_assertions"`     // sign SAML assertions (default true)
	SignResponse       bool              `json:"sign_response"`       // sign entire SAML response (default true)
	EncryptAssertion   bool              `json:"encrypt_assertion"`   // encrypt assertion with SP cert (default false)
	AttributeMapping   map[string]string `json:"attribute_mapping"`   // user attr -> SAML attribute name
	RoleAttribute      string            `json:"role_attribute"`      // multi-value attribute name carrying the user's app roles (JIT-first). Default "roles"; set "groups"/"memberOf"/"Role" to match the SP.
	GroupAttribute     string            `json:"group_attribute"`     // multi-value attribute name carrying the user's group codes. Empty (default) = groups NOT emitted (opt-in per app); set e.g. "groups"/"memberOf" to send them.
	SessionTTL         int               `json:"session_ttl"`         // seconds, default 28800 (8h)
	DigestAlgorithm    string            `json:"digest_algorithm"`    // sha256
	SignatureAlgorithm string            `json:"signature_algorithm"` // RSA-SHA256
}

// Defaults returns a SAMLConfig with sane defaults.
func Defaults() *SAMLConfig {
	return &SAMLConfig{
		NameIDFormat:       "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SignAssertions:     true,
		SignResponse:       true,
		RoleAttribute:      "roles",
		SessionTTL:         28800,
		DigestAlgorithm:    "sha256",
		SignatureAlgorithm: "RSA-SHA256",
		AttributeMapping: map[string]string{
			"username":     "uid",
			"email":        "mail",
			"display_name": "displayName",
			"phone":        "telephoneNumber",
		},
	}
}

// NameID format constants.
const (
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDUnspecified = "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)
