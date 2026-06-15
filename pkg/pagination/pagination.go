package pagination

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	DefaultPage     = 1
	DefaultPageSize = 20
	MaxPageSize     = 100
)

// Params holds pagination parameters.
type Params struct {
	Page     int
	PageSize int
}

// Offset returns the database offset.
func (p Params) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// Parse extracts pagination parameters from query string.
func Parse(c *gin.Context) Params {
	page := parseIntParam(c, "page", DefaultPage)
	pageSize := parseIntParam(c, "page_size", DefaultPageSize)

	if page < 1 {
		page = DefaultPage
	}
	if pageSize < 1 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	return Params{Page: page, PageSize: pageSize}
}

func parseIntParam(c *gin.Context, key string, defaultVal int) int {
	val := c.Query(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return n
}
