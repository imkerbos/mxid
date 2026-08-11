package audit

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"

	"github.com/imkerbos/mxid/pkg/event"
)

// detailSchema describes what subset of the event payload should land in
// the audit Detail JSONB column. Two goals:
//
//  1. Stable field set per event_type — the audit UI can render columns
//     deterministically and a SQL JSONB index on common keys (target_id,
//     actor_id, app_id) is meaningful instead of guesswork.
//  2. Outbound filtering — values like `password`, `code`, `secret` that
//     occasionally leak into payloads are stripped before persist.
//
// We allow-list rather than block-list: any field not named here is
// dropped. Unknown event types fall through to a "best effort" set
// covering the common diagnostics keys; this keeps new event_types
// auditable without a migration but loses schema rigor — add an explicit
// schema entry when the event_type stabilizes.
type detailSchema struct {
	allow []string
}

func (d detailSchema) project(in map[string]any) map[string]any {
	out := make(map[string]any, len(d.allow))
	for _, k := range d.allow {
		if v, ok := in[k]; ok && !isSensitiveKey(k) {
			out[k] = v
		}
	}
	return out
}

// sensitiveKeys are dropped even if listed in the allow-list. Mirrors
// the zap redactor's posture: a final defense against a payload that
// accidentally smuggled a secret.
var sensitiveKeys = map[string]struct{}{
	"password":      {},
	"old_password":  {},
	"new_password":  {},
	"password_hash": {},
	"secret":        {},
	"client_secret": {},
	// Named precisely rather than as a bare "code".
	//
	// "code" used to be here, meaning OTPs and magic-link tokens — but no event
	// publisher ever put one in a field called that, while twelve allow-lists
	// DID name "code" for what an operator calls the code: the app code, the
	// org code, the group code. All twelve were silently dropped, so the audit
	// log recorded that a group was created without recording which code it was
	// created with — and the group code is precisely the string downstream
	// systems match on to grant access.
	//
	// An allow-list that names a field the filter then removes is worse than an
	// incomplete allow-list, because it reads as coverage.
	"otp_code":      {},
	"verify_code":   {},
	"magic_code":    {},
	"backup_code":   {},
	"reset_code":    {},
	"otp":           {},
	"token":         {},
	"refresh_token": {},
	"access_token":  {},
	"api_key":       {},
	"private_key":   {},
}

func isSensitiveKey(k string) bool {
	_, bad := sensitiveKeys[k]
	return bad
}

// fallbackSchema is the catch-all for unregistered event types. Keeps
// the common diagnostic fields so listings still render.
var fallbackSchema = detailSchema{allow: []string{
	"tenant_id", "user_id", "username", "target_id", "actor_id",
	"app_id", "client_id", "role_id", "group_id", "org_id",
	"resource_id", "resource_type", "session_id",
	"reason", "fields", "from", "to",
	"ip", "user_agent",
}}

var detailSchemas = map[string]detailSchema{
	event.LoginSuccess: {allow: []string{"user_id", "username", "tenant_id", "auth_type", "ip", "user_agent", "session_id"}},
	event.LoginFailed:  {allow: []string{"username", "tenant_id", "reason", "auth_type", "ip", "user_agent"}},
	event.LoginRisk:    {allow: []string{"user_id", "tenant_id", "ip", "user_agent", "reasons"}},
	event.Logout:       {allow: []string{"user_id", "tenant_id", "session_id", "ip", "user_agent"}},

	event.UserCreated: {allow: []string{"user_id", "tenant_id", "username", "email", "display_name", "actor_id"}},
	// UserUpdated is not only "a display name changed": the user domain rides
	// its whole identity-binding lifecycle on this event type and puts the
	// meaning in "action" — identity_bound, identity_taken_over,
	// identity_unbound, identity_restored, user_restored, mfa_removed,
	// batch_*. Without "action" every one of them projects down to the same
	// {user_id, tenant_id} row, indistinguishable from an edit to a display
	// name. "provider", "identity_id" and "previous_user_id" are the operands
	// that make the row answer a question: which external account, which
	// binding, and — for a takeover — whose it was before.
	//
	// takeOverIdentity (internal/domain/user/external_login.go) is the only
	// code path that moves an external identity between accounts, and it runs
	// on the external-IdP callback: a GET on publicPortalGroup, which the
	// catch-all api.* audit does not cover (middleware.go returns early for
	// GET, and auditCatchAll is only .Use'd on the console/portal groups). This
	// domain event is the ONLY record that a takeover happened, so a dropped
	// previous_user_id is a takeover with no previous owner on record.
	//
	// All four are safe for the tamper-evident chain: "action" is a closed set
	// of code-authored literals, "provider" is an IdP type ("lark", "oidc"),
	// and the two id fields are snowflakes that stringifyBigIDs keeps exact.
	// No credential, token or free-form user input reaches any of them.
	// Precedent: event.AppUpdated already allow-lists "action" for the same
	// reason.
	event.UserUpdated:          {allow: []string{"user_id", "tenant_id", "actor_id", "fields", "status", "action", "provider", "identity_id", "previous_user_id"}},
	event.UserDeleted:          {allow: []string{"user_id", "tenant_id", "username", "actor_id"}},
	event.UserLocked:           {allow: []string{"user_id", "tenant_id", "actor_id", "reason", "status", "source"}},
	event.UserUnlocked:         {allow: []string{"user_id", "tenant_id", "actor_id"}},
	event.UserPasswordChanged:  {allow: []string{"user_id", "tenant_id", "actor_id", "method"}},
	event.UserPIIView:          {allow: []string{"user_id", "target_id", "tenant_id", "fields"}},
	event.UserSuperAdminGrant:  {allow: []string{"user_id", "target_id", "tenant_id", "username"}},
	event.UserSuperAdminRevoke: {allow: []string{"user_id", "target_id", "tenant_id", "username"}},
	event.UserOffboarded:       {allow: []string{"user_id", "tenant_id", "username", "actor_id", "sessions_killed"}},

	event.AppCreated:  {allow: []string{"app_id", "tenant_id", "name", "code", "protocol", "actor_id"}},
	event.AppUpdated:  {allow: []string{"app_id", "tenant_id", "fields", "action", "status", "actor_id"}},
	event.AppDeleted:  {allow: []string{"app_id", "tenant_id", "name", "code", "actor_id"}},
	event.AppLaunched: {allow: []string{"app_id", "tenant_id", "user_id", "name", "session_id"}},

	// Security-sensitive app sub-resource changes.
	event.AppAccessGranted:       {allow: []string{"app_id", "tenant_id", "subject_type", "subject_id", "actor_id"}},
	event.AppAccessRevoked:       {allow: []string{"app_id", "tenant_id", "subject_type", "subject_id", "actor_id"}},
	event.AppCertCreated:         {allow: []string{"app_id", "tenant_id", "kid", "actor_id"}},
	event.AppCertDeleted:         {allow: []string{"app_id", "tenant_id", "kid", "cert_id", "actor_id"}},
	event.AppRoleCreated:         {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "code", "name", "actor_id"}},
	event.AppRoleUpdated:         {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "code", "name", "actor_id"}},
	event.AppRoleDeleted:         {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "code", "name", "actor_id"}},
	event.AppRoleBindingCreated:  {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "subject_type", "subject_id", "binding_id", "actor_id"}},
	event.AppRoleBindingDeleted:  {allow: []string{"app_id", "app_group_id", "tenant_id", "role_id", "subject_type", "subject_id", "binding_id", "actor_id"}},
	event.AppAccessPolicyCreated: {allow: []string{"app_id", "app_group_id", "tenant_id", "policy_id", "subject_type", "subject_id", "effect", "actor_id"}},
	event.AppAccessPolicyDeleted: {allow: []string{"app_id", "app_group_id", "tenant_id", "policy_id", "subject_type", "subject_id", "effect", "actor_id"}},

	event.OrgCreated: {allow: []string{"org_id", "tenant_id", "name", "code", "parent_id", "actor_id"}},
	event.OrgUpdated: {allow: []string{"org_id", "tenant_id", "fields", "actor_id"}},
	event.OrgDeleted: {allow: []string{"org_id", "tenant_id", "name", "code", "actor_id"}},
	// event.OrgMemberMoved deliberately has no entry: the event is reserved and
	// never published (see internal/domain/group/org_sync.go and
	// app/adapters_authz.go — org membership moves are covered by
	// Added/Removed). An allow-list for an event nobody emits reads as coverage
	// that exists; add it back alongside the first Publish call, not before.

	event.GroupCreated:       {allow: []string{"group_id", "tenant_id", "name", "code", "actor_id"}},
	event.GroupUpdated:       {allow: []string{"group_id", "tenant_id", "fields", "actor_id"}},
	event.GroupDeleted:       {allow: []string{"group_id", "tenant_id", "name", "actor_id"}},
	event.GroupMemberAdded:   {allow: []string{"group_id", "tenant_id", "user_id", "name"}},
	event.GroupMemberRemoved: {allow: []string{"group_id", "tenant_id", "user_id", "name"}},
	// added/removed are the point of these entries: a rule edit moves people in
	// bulk, and the counts are what tell a reviewer whether the change was the
	// small correction it was described as.
	event.GroupRuleUpdated: {allow: []string{"group_id", "tenant_id", "name", "added", "removed", "actor_id"}},
	event.GroupRuleDeleted: {allow: []string{"group_id", "tenant_id", "name", "actor_id"}},
	event.GroupRuleSynced:  {allow: []string{"group_id", "tenant_id", "name", "added", "removed", "actor_id"}},

	event.TenantCreated: {allow: []string{"id", "tenant_id", "name", "code", "actor_id"}},
	event.TenantUpdated: {allow: []string{"id", "tenant_id", "name", "fields", "actor_id"}},
	event.TenantDeleted: {allow: []string{"id", "tenant_id", "name", "code", "actor_id"}},

	event.IDPCreated: {allow: []string{"id", "tenant_id", "name", "type", "protocol", "actor_id"}},
	event.IDPUpdated: {allow: []string{"id", "tenant_id", "name", "fields", "actor_id"}},
	event.IDPDeleted: {allow: []string{"id", "tenant_id", "name", "type", "actor_id"}},

	event.AppGroupCreated:       {allow: []string{"id", "tenant_id", "name", "code", "actor_id"}},
	event.AppGroupUpdated:       {allow: []string{"id", "tenant_id", "name", "fields", "actor_id"}},
	event.AppGroupDeleted:       {allow: []string{"id", "tenant_id", "name", "actor_id"}},
	event.AppGroupMemberAdded:   {allow: []string{"id", "tenant_id", "app_id"}},
	event.AppGroupMemberRemoved: {allow: []string{"id", "tenant_id", "app_id"}},

	event.SettingsUpdated: {allow: []string{"section", "tenant_id", "fields", "actor_id"}},

	event.ProfileUpdated:  {allow: []string{"user_id", "tenant_id", "fields"}},
	event.APITokenCreated: {allow: []string{"user_id", "tenant_id", "token_id", "name", "scopes"}},
	event.APITokenRevoked: {allow: []string{"user_id", "tenant_id", "token_id"}},

	event.SessionKicked: {allow: []string{"user_id", "session_id", "tenant_id", "actor_id"}},
	event.MFAEnabled:    {allow: []string{"user_id", "tenant_id", "type"}},
	event.MFADisabled:   {allow: []string{"user_id", "tenant_id", "type", "actor_id"}},

	event.OIDCTokenIssued:       {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "scope"}},
	event.OIDCTokenRefreshed:    {allow: []string{"user_id", "tenant_id", "client_id", "app_id"}},
	event.OIDCTokenRevoked:      {allow: []string{"user_id", "tenant_id", "client_id", "app_id"}},
	event.OIDCTokenReuse:        {allow: []string{"user_id", "tenant_id", "client_id", "app_id"}},
	event.OIDCConsentGranted:    {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "scope"}},
	event.OIDCConsentRevoked:    {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "actor_id"}},
	event.OIDCBackchannelLogout: {allow: []string{"user_id", "tenant_id", "client_id", "app_id", "session_id"}},

	// JIT privileged-access (temporary elevation) lifecycle. Literal event_type
	// strings (not the access package consts) to keep audit free of a domain
	// import; they mirror internal/domain/access/events.go.
	//
	// No "actor_id" here on purpose: the audit row's actor COLUMN is owned by
	// enrich() (the request-scoped auditctx caller — approver / admin /
	// system). "requester_id" is the SUBJECT/beneficiary whose access is
	// affected, never the actor; a payload "actor_id" would just restate a
	// different person under the column's name and contradict it. Where a
	// distinct acting identity is worth recording in detail, it uses an
	// explicit key like "approver_id" (see access.grant.activated).
	"access.request.created":   {allow: []string{"resource_id", "resource_type", "tenant_id", "request_id", "requester_id", "requester_name", "target_kind", "role_id", "app_id", "expires_at"}},
	"access.request.approved":  {allow: []string{"resource_id", "resource_type", "tenant_id", "request_id", "requester_id", "requester_name", "target_kind", "role_id", "app_id", "expires_at"}},
	"access.request.rejected":  {allow: []string{"resource_id", "resource_type", "tenant_id", "request_id", "requester_id", "requester_name", "target_kind", "role_id", "app_id"}},
	"access.request.cancelled": {allow: []string{"resource_id", "resource_type", "tenant_id", "request_id", "requester_id", "requester_name", "target_kind", "role_id", "app_id"}},
	"access.grant.activated":   {allow: []string{"resource_id", "resource_type", "tenant_id", "request_id", "requester_id", "requester_name", "approver_id", "target_kind", "role_id", "app_id", "expires_at"}},
	"access.grant.expired":     {allow: []string{"resource_id", "resource_type", "tenant_id", "request_id", "requester_id", "requester_name", "target_kind", "role_id", "app_id", "expires_at"}},
	"access.grant.revoked":     {allow: []string{"resource_id", "resource_type", "tenant_id", "request_id", "requester_id", "requester_name", "target_kind", "role_id", "app_id"}},

	// Eligibility (policy config) writes: who may request elevation and how.
	"access.eligibility.created": {allow: []string{"resource_id", "resource_type", "tenant_id", "target_kind", "role_id", "app_id"}},
	"access.eligibility.updated": {allow: []string{"resource_id", "resource_type", "tenant_id", "target_kind", "role_id", "app_id"}},
	"access.eligibility.deleted": {allow: []string{"resource_id", "resource_type", "tenant_id", "target_kind", "role_id", "app_id"}},
}

// projectDetail picks the schema-allowed subset of payload for the given
// event_type, drops any sensitive keys, and returns the JSON-encoded
// bytes. Returns "{}" on encode failure so the column stays valid.
func projectDetail(eventType string, payload map[string]any) json.RawMessage {
	schema, ok := detailSchemas[eventType]
	if !ok {
		schema = fallbackSchema
	}
	picked := stringifyBigIDs(schema.project(payload))
	data, err := json.Marshal(picked)
	if err != nil {
		return json.RawMessage("{}")
	}
	return data
}

// maxExactJSNumber is 2^53-1 — the largest integer a JSON number survives a
// round trip through, in Go's map[string]any as much as in a browser.
const maxExactJSNumber = 1<<53 - 1

// stringifyBigIDs rewrites integers too large to survive as JSON numbers into
// strings, so an id in the audit detail still identifies the row it names.
//
// Snowflake ids are 18-19 digits, past the 53 bits a float64 holds exactly, and
// every hop between the event and the operator's screen re-parses the JSON:
// Go's encoding/json decodes numbers into float64, and so does the browser. The
// id was silently rounded at the last two digits — an audit entry that says
// group 360787997051850750 when the group is 360787997051850752. It looks
// right, it is off by two, and looking it up finds nothing. This is what audit
// exists to prevent, so an id that cannot be trusted is worse than no id.
//
// The same reason the wire DTOs carry `,string` on snowflake fields. Detail is
// a free-form map and cannot use a struct tag, so it is done here.
func stringifyBigIDs(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch n := v.(type) {
		case int64:
			out[k] = clampID(n)
		case int:
			out[k] = clampID(int64(n))
		case uint64:
			if n > maxExactJSNumber {
				out[k] = strconv.FormatUint(n, 10)
				continue
			}
			out[k] = n
		case float64:
			// Already through one decode; preserve whatever precision is left
			// rather than pretending to recover it.
			if n == math.Trunc(n) && math.Abs(n) > maxExactJSNumber {
				out[k] = strconv.FormatFloat(n, 'f', -1, 64)
				continue
			}
			out[k] = n
		default:
			out[k] = v
		}
	}
	return out
}

func clampID(n int64) any {
	if n > maxExactJSNumber || n < -maxExactJSNumber {
		return strconv.FormatInt(n, 10)
	}
	return n
}

// RegisteredEventTypes returns the sorted list of event_types this
// package knows a schema for. Useful for the console UI to render a
// filter dropdown without inventing the list there.
func RegisteredEventTypes() []string {
	out := make([]string, 0, len(detailSchemas))
	for k := range detailSchemas {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
