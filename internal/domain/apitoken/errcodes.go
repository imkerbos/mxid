package apitoken

import "github.com/imkerbos/mxid/pkg/errcode"

// ErrNotFound maps to 404/40401 (unchanged from the former inline mapping in the
// portal security handler). response.MapError does the lookup.
func init() {
	errcode.Bind(ErrNotFound, errcode.Code{HTTP: 404, Num: 40401})
}
