package license

// Feature is an EE-gated capability key. CE (no/invalid license) has NONE of
// these; an EE license unlocks the subset listed in its signed payload.
//
// Core IAM (password/TOTP/sessions, OIDC/SAML/CAS, users/orgs/groups, basic
// RBAC, SMTP, basic audit, the single default tenant) is NOT gated — it never
// goes through Has(), it's always available.
type Feature string

const (
	// FeatureMultiTenant — create/run more than the single default tenant.
	FeatureMultiTenant Feature = "multi_tenant"
	// FeatureExternalIDP — log in via external identity providers (social /
	// enterprise SSO upstreams).
	FeatureExternalIDP Feature = "external_idp"
	// FeatureBranding — white-label: logo, colors, product name, login page.
	FeatureBranding Feature = "branding"
	// FeatureConditionalAccess — risk-based / adaptive access policies.
	FeatureConditionalAccess Feature = "conditional_access"
	// FeatureWebAuthn — WebAuthn / passkeys / hardware security keys.
	FeatureWebAuthn Feature = "webauthn"
	// FeatureSCIM — SCIM 2.0 user/group provisioning.
	FeatureSCIM Feature = "scim"
	// FeatureAdvancedStepUp — advanced step-up / sudo policies.
	FeatureAdvancedStepUp Feature = "advanced_stepup"
	// FeatureSMS — SMS-based login / OTP.
	FeatureSMS Feature = "sms"
)

// AllFeatures is the full catalog — used by the signing tool's "all" shortcut
// and to validate feature strings in a license payload.
var AllFeatures = []Feature{
	FeatureMultiTenant,
	FeatureExternalIDP,
	FeatureBranding,
	FeatureConditionalAccess,
	FeatureWebAuthn,
	FeatureSCIM,
	FeatureAdvancedStepUp,
	FeatureSMS,
}
