package tenant

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the tenant domain. Numeric values unchanged from the former
// inline errors.Is chains; response.MapError does the lookup.
var (
	codeTenantNotFound   = errcode.Code{HTTP: 404, Num: 40401}
	codeLicenseQuota     = errcode.Code{HTTP: 402, Num: 40201}
	codeTenantCodeExists = errcode.Code{HTTP: 409, Num: 40901}
)

func init() {
	errcode.Bind(ErrTenantNotFound, codeTenantNotFound)
	errcode.Bind(ErrLicenseQuotaExceeded, codeLicenseQuota)
	errcode.Bind(ErrTenantCodeExists, codeTenantCodeExists)
}
