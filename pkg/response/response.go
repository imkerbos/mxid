package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Response is the unified API response structure.
type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// PaginatedData wraps paginated results.
type PaginatedData struct {
	Items    any   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

// OK sends a success response.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data:    data,
	})
}

// Created sends a 201 response.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Response{
		Code:    0,
		Message: "created",
		Data:    data,
	})
}

// Paginated sends a paginated response.
func Paginated(c *gin.Context, items any, total int64, page, pageSize int) {
	c.JSON(http.StatusOK, Response{
		Code:    0,
		Message: "ok",
		Data: PaginatedData{
			Items:    items,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		},
	})
}

// Error sends an error response.
func Error(c *gin.Context, httpStatus int, code int, message, detail string) {
	c.JSON(httpStatus, Response{
		Code:    code,
		Message: message,
		Detail:  detail,
	})
}

// BadRequest sends a 400 error.
func BadRequest(c *gin.Context, code int, message string) {
	Error(c, http.StatusBadRequest, code, message, "")
}

// Unauthorized sends a 401 error.
func Unauthorized(c *gin.Context, code int, message string) {
	Error(c, http.StatusUnauthorized, code, message, "")
}

// Forbidden sends a 403 error.
func Forbidden(c *gin.Context, code int, message string) {
	Error(c, http.StatusForbidden, code, message, "")
}

// NotFound sends a 404 error.
func NotFound(c *gin.Context, code int, message string) {
	Error(c, http.StatusNotFound, code, message, "")
}

// Conflict sends a 409 error. Use when a uniqueness / state precondition
// fails (duplicate code, etc).
func Conflict(c *gin.Context, code int, message string) {
	Error(c, http.StatusConflict, code, message, "")
}

// NoContent sends a 204 with no body. Used by DELETE handlers.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// InternalError sends a 500 error. Default message is intentionally
// generic — callers MUST NOT pass raw err.Error() (leaks internals);
// log the real error via zap and pass a user-safe label here.
func InternalError(c *gin.Context, message string) {
	if message == "" {
		message = "internal server error"
	}
	Error(c, http.StatusInternalServerError, 50001, message, "")
}
