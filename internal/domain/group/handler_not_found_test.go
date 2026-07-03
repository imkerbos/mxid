package group

// Regression guard: AddMember / Update / UpsertRule / DeleteRule used to
// fetch the group via a bare s.repo.GetByID call and wrap any error
// (including gorm.ErrRecordNotFound) in a plain fmt.Errorf. The handler could
// then never errors.Is-match ErrGroupNotFound, so a nonexistent group id fell
// through to a bare 500 instead of 404. The service methods now route through
// requireGroup (which does the ErrRecordNotFound -> ErrGroupNotFound mapping,
// same as GetMembers/AddMembers/SyncRule already did) and the handlers map
// ErrGroupNotFound to 404.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

func withTenantScope(tenantID int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request = c.Request.WithContext(tenantscope.WithTenant(context.Background(), tenantID))
		c.Next()
	}
}

func TestHandler_AddMember_MissingGroupReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newGroupHandlerDB(t)
	svc := &Service{repo: NewRepository(db)}
	h := &Handler{service: svc}

	r := gin.New()
	r.Use(withTenantScope(100))
	r.POST("/groups/:id/members", h.AddMember)

	body := `{"user_id":"99"}`
	req := httptest.NewRequest(http.MethodPost, "/groups/999/members", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("AddMember on missing group: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestHandler_Update_MissingGroupReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newGroupHandlerDB(t)
	svc := &Service{repo: NewRepository(db)}
	h := &Handler{service: svc}

	r := gin.New()
	r.Use(withTenantScope(100))
	r.PUT("/groups/:id", h.Update)

	body := `{"name":"renamed"}`
	req := httptest.NewRequest(http.MethodPut, "/groups/999", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Update on missing group: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestHandler_UpsertRule_MissingGroupReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newGroupHandlerDB(t)
	svc := &Service{repo: NewRepository(db)}
	h := &Handler{service: svc}

	r := gin.New()
	r.Use(withTenantScope(100))
	r.PUT("/groups/:id/rule", h.UpsertRule)

	rule := RuleExpr{Op: "and", Conditions: []RuleCondition{{Field: "status", Cmp: "eq", Value: float64(1)}}}
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/groups/999/rule", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("UpsertRule on missing group: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestHandler_DeleteRule_MissingGroupReturns404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newGroupHandlerDB(t)
	svc := &Service{repo: NewRepository(db)}
	h := &Handler{service: svc}

	r := gin.New()
	r.Use(withTenantScope(100))
	r.DELETE("/groups/:id/rule", h.DeleteRule)

	req := httptest.NewRequest(http.MethodDelete, "/groups/999/rule", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("DeleteRule on missing group: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}
