// Package ginutil holds small helpers shared across gin handlers in the
// console / portal gateways. Centralising them avoids the 29+ inline
// `strconv.ParseInt(c.Param("id"), 10, 64)` repetitions that drift in
// error code / response shape over time.
package ginutil

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/response"
)

// ParseInt64Param reads a path parameter as int64. On failure it writes
// a 400 response and returns ok=false so the caller can early-return:
//
//	id, ok := ginutil.ParseInt64Param(c, "id")
//	if !ok { return }
//
// errorCode is the 5-digit response code used in the failure body —
// distinct per caller so audit logs disambiguate which param parse failed.
func ParseInt64Param(c *gin.Context, name string) (int64, bool) {
	raw := c.Param(name)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		response.BadRequest(c, 40001, "invalid "+name+": "+raw)
		return 0, false
	}
	return id, true
}

// UserIDFromContext reads the authenticated user's id stamped by the
// auth middleware. Mirrors authn.GetUserID but lives here so handlers
// in domain packages don't have to import authn just for the ID.
func UserIDFromContext(c *gin.Context) (int64, bool) {
	v, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

// UserIDPtr returns the user id as a *int64, useful for service "CreatedBy"
// columns that are nullable.
func UserIDPtr(c *gin.Context) *int64 {
	id, ok := UserIDFromContext(c)
	if !ok {
		return nil
	}
	return &id
}
