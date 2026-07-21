package cas

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/imkerbos/mxid/internal/protocol/resolver"
	"go.uber.org/zap"
)

// stubIdentityResolver returns a fixed user whose group membership drives the
// groups attribute under test.
type stubIdentityResolver struct{ info *resolver.IdentityInfo }

func (s stubIdentityResolver) ResolveUser(context.Context, int64) (*resolver.IdentityInfo, error) {
	return s.info, nil
}
func (s stubIdentityResolver) ResolveClaims(context.Context, int64, []string) (map[string]any, error) {
	return nil, nil
}

// stubAppRoles returns fixed app-role codes so we can assert app_roles still
// emit alongside groups.
type stubAppRoles struct{ roles []string }

func (s stubAppRoles) ResolveAppRoles(context.Context, int64, int64, int64) ([]string, error) {
	return s.roles, nil
}

func casGroupAppConfig(groupAttr string, serviceURLs ...string) *resolver.AppConfig {
	cfg := map[string]any{
		"service_urls":    serviceURLs,
		"role_attribute":  "roles",
		"group_attribute": groupAttr, // "" = opt-out (groups not sent)
	}
	raw, _ := json.Marshal(cfg)
	return &resolver.AppConfig{ID: 9, Code: "app1", Status: 1, Protocol: "cas", ProtocolConfig: raw}
}

func newValidateHandler(t *testing.T, app *resolver.AppConfig, groups, roles []string) *Handler {
	t.Helper()
	return &Handler{
		appRes: stubAppResolver{app: app},
		idRes: stubIdentityResolver{info: &resolver.IdentityInfo{
			ID: 5, TenantID: 1, Username: "alice", Groups: groups,
		}},
		appRoles: stubAppRoles{roles: roles},
		store:    NewTicketStore(miniredisClient(t)),
		logger:   zap.NewNop(),
	}
}

// GroupAttribute set → the CAS 3.0 validation response carries every group code
// as a <cas:groups> element, AND app_roles are still emitted as <cas:roles>.
func TestP3ServiceValidate_EmitsGroupsWhenConfigured(t *testing.T) {
	service := "https://backend.example/cb"
	app := casGroupAppConfig("groups", service)
	h := newValidateHandler(t, app, []string{"eng", "admins"}, []string{"viewer"})

	st, err := h.store.CreateTicket(context.Background(), 5, 1, service, "alice", 30)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	w := runGET(h.p3ServiceValidate, "app1", "ticket="+st.Ticket+"&service="+url.QueryEscape(service))
	body := w.Body.String()

	if !strings.Contains(body, "<cas:authenticationSuccess>") {
		t.Fatalf("expected success, got: %s", body)
	}
	if !strings.Contains(body, "<cas:groups>eng</cas:groups>") || !strings.Contains(body, "<cas:groups>admins</cas:groups>") {
		t.Fatalf("expected both group codes as <cas:groups>, got: %s", body)
	}
	// app_roles must still ride alongside groups (independent attributes).
	if !strings.Contains(body, "<cas:roles>viewer</cas:roles>") {
		t.Fatalf("expected app_roles still emitted, got: %s", body)
	}
}

// GroupAttribute empty (default) → groups are NOT sent; app_roles unaffected.
func TestP3ServiceValidate_OmitsGroupsWhenUnset(t *testing.T) {
	service := "https://backend.example/cb"
	app := casGroupAppConfig("", service) // opt-out
	h := newValidateHandler(t, app, []string{"eng", "admins"}, []string{"viewer"})

	st, err := h.store.CreateTicket(context.Background(), 5, 1, service, "alice", 30)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	w := runGET(h.p3ServiceValidate, "app1", "ticket="+st.Ticket+"&service="+url.QueryEscape(service))
	body := w.Body.String()

	if strings.Contains(body, "<cas:groups>") || strings.Contains(body, "eng") || strings.Contains(body, "admins") {
		t.Fatalf("groups must NOT be emitted when GroupAttribute empty, got: %s", body)
	}
	if !strings.Contains(body, "<cas:roles>viewer</cas:roles>") {
		t.Fatalf("expected app_roles still emitted, got: %s", body)
	}
}
