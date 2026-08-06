package group

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
)

// withCodeUniqueIndex adds the (tenant_id, code) unique constraint that
// migration 000003 puts on mxid_user_group. AutoMigrate does not create it —
// the model carries no uniqueIndex tag, the constraint lives only in the
// migration SQL — so without this the duplicate simply inserts and the test
// would pass against the broken code.
func withCodeUniqueIndex(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(`CREATE UNIQUE INDEX mxid_user_group_tenant_id_code_key
		ON mxid_user_group(tenant_id, code)`).Error; err != nil {
		t.Fatalf("create unique index: %v", err)
	}
}

// A duplicate code is the administrator's mistake, not a server fault. It
// reached the console as a bare 500 "failed to create user group", which reads
// as "try again" — so administrators did, every retry collided with the row the
// first attempt had already created, and the log filled with 500s for a group
// that existed all along.
func TestService_Create_DuplicateCodeIsAConflict(t *testing.T) {
	db := newGroupHandlerDB(t)
	withCodeUniqueIndex(t, db)

	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	svc := &Service{repo: NewRepository(db), idGen: idGen}
	ctx := tenantscope.WithTenant(context.Background(), 100)

	req := &CreateGroupRequest{Name: "Ops", Code: "ops"}
	if _, err := svc.Create(ctx, 100, req); err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err = svc.Create(ctx, 100, &CreateGroupRequest{Name: "Ops again", Code: "ops"})
	if err == nil {
		t.Fatal("second create with the same code succeeded — the constraint is not being exercised")
	}
	if !strings.Contains(err.Error(), ErrGroupCodeExists.Error()) {
		t.Fatalf("want ErrGroupCodeExists, got %v", err)
	}
}

// The mapping has to survive all the way to the wire: the sentinel is only
// useful if MapError turns it into a 409 the SPA can localize, rather than the
// 500 the handler used to send for every error alike.
func TestHandler_Create_DuplicateCodeReturns409(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newGroupHandlerDB(t)
	withCodeUniqueIndex(t, db)

	idGen, err := snowflake.New(1)
	if err != nil {
		t.Fatalf("snowflake: %v", err)
	}
	svc := &Service{repo: NewRepository(db), idGen: idGen}
	h := &Handler{service: svc, tenantID: 100}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(tenantscope.WithTenant(context.Background(), 100))
		c.Next()
	})
	r.POST("/groups", h.Create)

	post := func() *httptest.ResponseRecorder {
		body := strings.NewReader(`{"name":"Ops","code":"ops"}`)
		req := httptest.NewRequest(http.MethodPost, "/groups", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := post(); w.Code != http.StatusCreated {
		t.Fatalf("first create: want 201, got %d (body=%s)", w.Code, w.Body.String())
	}

	w := post()
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate code: want 409, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Code != codeGroupCodeExists.Num {
		t.Errorf("business code = %d, want %d — the SPA branches on this number",
			resp.Code, codeGroupCodeExists.Num)
	}
}
