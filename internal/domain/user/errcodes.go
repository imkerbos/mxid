package user

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the user domain, declared next to the sentinels they map.
// Numeric values are the frozen API contract (unchanged from the former
// handleServiceError switch); response.MapError does the lookup.
var (
	codeUserNotFound     = errcode.Code{HTTP: 404, Num: 40401}
	codeInvalidPassword  = errcode.Code{HTTP: 400, Num: 40002}
	codePasswordReused   = errcode.Code{HTTP: 400, Num: 40003}
	codeWeakPassword     = errcode.Code{HTTP: 400, Num: 40004}
	codeLicenseQuota     = errcode.Code{HTTP: 402, Num: 40201}
	codeUsernameExists   = errcode.Code{HTTP: 409, Num: 40901}
	codeEmailExists      = errcode.Code{HTTP: 409, Num: 40902}
	codePhoneExists      = errcode.Code{HTTP: 409, Num: 40903}
	codeLastSuperAdmin   = errcode.Code{HTTP: 409, Num: 40904}
	codeMFAAlreadyExists = errcode.Code{HTTP: 409, Num: 40901}
)

func init() {
	errcode.Bind(ErrUserNotFound, codeUserNotFound)
	errcode.Bind(ErrDetailNotFound, codeUserNotFound)
	errcode.Bind(ErrIdentityNotFound, codeUserNotFound)
	errcode.Bind(ErrInvalidPassword, codeInvalidPassword)
	errcode.Bind(ErrPasswordReused, codePasswordReused)
	errcode.Bind(ErrWeakPassword, codeWeakPassword)
	errcode.Bind(ErrLicenseQuotaExceeded, codeLicenseQuota)
	errcode.Bind(ErrUsernameExists, codeUsernameExists)
	errcode.Bind(ErrEmailExists, codeEmailExists)
	errcode.Bind(ErrPhoneExists, codePhoneExists)
	errcode.Bind(ErrLastSuperAdmin, codeLastSuperAdmin)
	errcode.Bind(ErrMFAAlreadyExists, codeMFAAlreadyExists)
}
