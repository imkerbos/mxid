package group

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the group domain, declared next to the sentinels they map.
// response.MapError does the lookup. The rule-validation sentinels all share
// codeBadRule; the wrapped error's own message carries the specific
// field/operator so MapError still returns a useful message.
var (
	codeGroupNotFound   = errcode.Code{HTTP: 404, Num: 40401}
	codeUserNotInTenant = errcode.Code{HTTP: 404, Num: 40402}
	// This started as 40003 (rendered as "TOTP code reused"), was moved to 40010
	// to escape that — and 40010 had meanwhile become appNoLoginURL, so a bad rule
	// rendered as "app has no login URL". It now uses a catalogued number; see
	// pkg/errcode/catalog.go for why picking one by hand kept going wrong.
	codeBadRule         = errcode.Code{HTTP: 400, Num: errcode.NumBadGroupRule}
	codeGroupNotDynamic = errcode.Code{HTTP: 400, Num: 40002}
	codeGroupHasMembers = errcode.Code{HTTP: 409, Num: 40901}
	codeGroupIsDynamic  = errcode.Code{HTTP: 409, Num: 40902}
	codeGroupCodeExists = errcode.Code{HTTP: 409, Num: errcode.NumCodeExists}
)

func init() {
	// service.go
	errcode.Bind(ErrGroupNotFound, codeGroupNotFound)
	errcode.Bind(ErrUserNotInTenant, codeUserNotInTenant)
	errcode.Bind(ErrGroupHasMembers, codeGroupHasMembers)
	errcode.Bind(ErrGroupCodeExists, codeGroupCodeExists)
	// rule_sync.go
	errcode.Bind(ErrRuleNotFound, codeGroupNotFound) // "group has no rule" — a 404
	errcode.Bind(ErrGroupNotDynamic, codeGroupNotDynamic)
	errcode.Bind(ErrGroupIsDynamic, codeGroupIsDynamic)
	// rule.go (validation)
	errcode.Bind(ErrRuleEmpty, codeBadRule)
	errcode.Bind(ErrRuleUnknownField, codeBadRule)
	errcode.Bind(ErrRuleUnknownCmp, codeBadRule)
	errcode.Bind(ErrRuleInvalidValue, codeBadRule)
	errcode.Bind(ErrRuleNestedNotSupported, codeBadRule)
}
