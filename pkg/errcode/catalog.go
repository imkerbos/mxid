package errcode

// The catalog is the one place a numeric business code may be introduced.
//
// Why it has to exist: the numbers are a frozen wire contract, and a subset of
// them are *localized* — the SPA throws the server's message away and renders a
// fixed translated sentence keyed on the number (toast.tsx LOCALIZED_CODES).
// Reusing one of those for an unrelated error is not a style problem, it shows
// the user the wrong sentence.
//
// That had already happened three times, each time to a developer who was
// actively trying to avoid it. Six files carry a comment warning that 40003 is
// taken by totpCodeReused, and 40003 was still reused for "captcha is required".
// Two domains picked 40010 to *escape* 40003, after 40010 had itself become
// appNoLoginURL. Comments cannot enforce this: they live next to the code that
// already knows, not next to the developer picking a fresh number.
//
// So: every number lives here, exactly once, with its kind. Picking a new one
// means adding an entry, which means seeing the localized ones. A guard test
// (catalog_guard_test.go) fails the build if a response.* call uses a number
// that is not catalogued, and if the localized set here drifts from the SPA's.

// Kind says how the frontend treats a code.
type Kind int

const (
	// Generic — the SPA shows the server's message verbatim. Sharing a generic
	// code across unrelated domains is correct and expected: the number says
	// "your request was rejected", the message says why.
	Generic Kind = iota
	// Localized — the SPA REPLACES the server message with a fixed translated
	// string. Each of these has exactly one meaning product-wide, and reusing
	// one is a user-visible bug.
	Localized
)

// Generic codes. No fixed meaning beyond the HTTP-status family; reuse freely.
const (
	NumBadRequest      = 40001 // body malformed or unbindable
	NumInvalidInput    = 40002 // bound, but a value failed validation
	NumInputRejected   = 40004 // well-formed but unacceptable (weak password, bad captcha, expired challenge)
	NumInvalidCode     = 40006 // a supplied code/scope did not check out
	NumSignatureFailed = 40008 // signature or request-envelope verification failed
	NumAppValidation   = 40011 // app-domain validation refusal

	NumUnauthenticated = 40101 // no valid session
	NumInvalidMFACode  = 40102 // session valid, MFA answer wrong

	NumForbidden      = 40300 // requires a privilege the caller lacks
	NumForbiddenScope = 40301 // allowed in principle, refused for this target

	NumNotFound         = 40401 // the addressed resource does not exist
	NumTemplateNotFound = 40407 // app template lookup miss

	NumConflict = 40901 // uniqueness or state conflict

	// Emitted via response.Error, whose SECOND argument is the business code
	// (the first is the HTTP status).
	NumRouteNotFound   = 40400 // no such route
	NumAccessDenied    = 40302 // policy refused this subject
	NumAccountDisabled = 40303 // account disabled
	NumTooManyAttempts = 42901 // rate limited / temporarily locked
)

// Localized codes. Adding one here means adding the matching entry to
// LOCALIZED_CODES in web/packages/shared/src/ui/toast.tsx — the guard test
// asserts the two sets are identical, so a half-done change fails.
//
// Each of these must be referenced by name, never as a bare literal, and from
// exactly one place. The guard enforces both.
const (
	NumTOTPCodeReused      = 40003 // errors.totpCodeReused
	NumPasswordReused      = 40005 // errors.passwordReused
	NumTOTPRequired        = 40007 // errors.totpRequired
	NumAppNoLoginURL       = 40010 // errors.appNoLoginURL
	NumSelfApproval        = 40012 // errors.selfApproval
	NumApproverNotEligible = 40013 // errors.approverNotEligible
	NumEEFeatureRequired   = 40332 // errors.eeFeatureRequired
)

// Numbers that replaced a collided use of a localized code. Kept as named
// constants so the swap is greppable and cannot silently revert.
const (
	NumBadGroupRule      = 40014 // was 40010, which the SPA renders as appNoLoginURL
	NumInvalidClientType = 40015 // was 40010, same collision
	NumCaptchaRequired   = 40016 // was 40003, which the SPA renders as totpCodeReused
	NumStepUpRequiredNum = 40330
	NumMFAEnrollRequired = 40331
	// NumPasswordChangeRequired gates a session whose owner must pick a new
	// password before doing anything else. The SPA branches on it to route to
	// the change-password screen, so it must not be reused.
	NumPasswordChangeRequired = 40333
)

// Catalog is every number the API may return, with its kind and what it means.
// Domain-specific 404/409 variants are included so a new domain cannot silently
// mint a number that another domain already uses for something incompatible.
var Catalog = map[int]struct {
	Kind Kind
	Desc string
}{
	NumBadRequest:      {Generic, "malformed or unbindable request body"},
	NumInvalidInput:    {Generic, "request bound, a value failed validation"},
	NumTOTPCodeReused:  {Localized, "TOTP code already consumed this window"},
	NumInputRejected:   {Generic, "well-formed but unacceptable value"},
	NumPasswordReused:  {Localized, "new password matches a recent one"},
	NumInvalidCode:     {Generic, "supplied code or scope did not check out"},
	NumTOTPRequired:    {Localized, "step-up needs a TOTP code that was not supplied"},
	NumSignatureFailed: {Generic, "signature or request-envelope verification failed"},
	NumAppNoLoginURL:   {Localized, "form-fill app has no login URL configured"},
	NumAppValidation:   {Generic, "app-domain validation refusal"},

	NumSelfApproval:        {Localized, "JIT approval refused: separation of duties"},
	NumApproverNotEligible: {Localized, "JIT approval refused: approver not in eligibility"},
	NumBadGroupRule:        {Generic, "dynamic-group rule expression is invalid"},
	NumInvalidClientType:   {Generic, "app client type is not valid for this operation"},
	NumCaptchaRequired:     {Generic, "captcha required before this attempt"},

	40020: {Generic, "access: eligibility definition invalid"},
	40021: {Generic, "access: request not allowed by eligibility"},
	40022: {Generic, "access: request is not pending"},
	40023: {Generic, "access: request is not cancellable"},
	40024: {Generic, "access: grant is not revocable"},
	40030: {Generic, "approle: role definition invalid"},
	40031: {Generic, "approle: binding invalid"},
	40040: {Generic, "appaccess: policy invalid"},

	NumUnauthenticated: {Generic, "no valid session"},
	NumInvalidMFACode:  {Generic, "session valid, MFA answer wrong"},

	NumForbidden:              {Generic, "requires a privilege the caller lacks"},
	NumForbiddenScope:         {Generic, "refused for this specific target"},
	NumStepUpRequiredNum:      {Generic, "step-up MFA required (SPA branches on this)"},
	NumMFAEnrollRequired:      {Generic, "MFA enrollment required (SPA branches on this)"},
	NumPasswordChangeRequired: {Generic, "password change required (SPA branches on this)"},
	NumEEFeatureRequired:      {Localized, "feature requires an Enterprise licence"},

	40201: {Generic, "licence user quota exhausted"},

	NumNotFound:         {Generic, "addressed resource does not exist"},
	40402:               {Generic, "secondary resource not found / not in tenant"},
	40403:               {Generic, "tertiary resource not found / not in tenant"},
	40404:               {Generic, "quaternary resource not found / not in tenant"},
	40405:               {Generic, "app: account not found"},
	40406:               {Generic, "app: subject not in tenant"},
	NumTemplateNotFound: {Generic, "app template not found"},
	40410:               {Generic, "access: request not found"},
	40411:               {Generic, "access: eligibility not found"},
	40420:               {Generic, "approle: role not found"},
	40421:               {Generic, "approle: parent not in tenant"},
	40422:               {Generic, "approle: subject not in tenant"},
	40423:               {Generic, "approle: app role not in parent"},
	40430:               {Generic, "appaccess: parent not in tenant"},
	40431:               {Generic, "appaccess: subject not in tenant"},

	NumConflict: {Generic, "uniqueness or state conflict"},
	40902:       {Generic, "secondary uniqueness conflict"},
	40903:       {Generic, "tertiary uniqueness conflict"},
	40904:       {Generic, "user: last super admin cannot be demoted"},
	40905:       {Generic, "user: password already set"},

	NumRouteNotFound:   {Generic, "no such route"},
	NumAccessDenied:    {Generic, "policy refused this subject"},
	NumAccountDisabled: {Generic, "account disabled"},
	NumTooManyAttempts: {Generic, "rate limited or temporarily locked"},
}

// IsLocalized reports whether the SPA overrides the server message for num.
func IsLocalized(num int) bool {
	e, ok := Catalog[num]
	return ok && e.Kind == Localized
}
