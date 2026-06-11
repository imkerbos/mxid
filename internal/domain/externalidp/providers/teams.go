package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imkerbos/mxid/internal/domain/externalidp"
)

// Microsoft Teams uses the Microsoft Identity Platform (Azure AD v2.0)
// OAuth2/OIDC endpoints. There is no Teams-specific OAuth surface — Teams
// sign-in IS Azure AD sign-in. We hit Microsoft Graph /me afterwards to
// get the canonical user attributes (id / displayName / mail / userPrincipalName).
//
// Tenant strategy:
//   - "common"        — accept work, school AND personal MSAs
//   - "organizations" — work/school only (most enterprise deployments want this)
//   - "<tenant-guid>" — single-tenant lock
//
// Default we use is "common" so a new Teams config "just works" for both
// personal and work accounts; admins can narrow via the tenant config field.
const (
	teamsAuthURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	teamsTokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	teamsGraphMeURL       = "https://graph.microsoft.com/v1.0/me"
)

// TeamsConfig — fields stored in mxid_external_idp.config for the teams type.
type TeamsConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Tenant       string   `json:"tenant,omitempty"` // "common" | "organizations" | "<tenant-guid>"
	Scopes       []string `json:"scopes,omitempty"`
}

type teams struct {
	idp        *externalidp.ExternalIDP
	cfg        TeamsConfig
	authURL    string
	tokenURL   string
	httpClient *http.Client
}

func newTeams(idp *externalidp.ExternalIDP) (externalidp.Provider, error) {
	var cfg TeamsConfig
	if err := json.Unmarshal(idp.Config, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", externalidp.ErrInvalidConfig, err)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client_id and client_secret required", externalidp.ErrInvalidConfig)
	}
	if cfg.Tenant == "" {
		cfg.Tenant = "common"
	}
	if len(cfg.Scopes) == 0 {
		// "User.Read" lets us call /me; openid+profile+email are required
		// to get an id_token back from Microsoft.
		cfg.Scopes = []string{"openid", "profile", "email", "User.Read"}
	}
	p := &teams{
		idp:        idp,
		cfg:        cfg,
		authURL:    fmt.Sprintf(teamsAuthURLTemplate, cfg.Tenant),
		tokenURL:   fmt.Sprintf(teamsTokenURLTemplate, cfg.Tenant),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
	return p, nil
}

func (p *teams) Type() string { return externalidp.TypeTeams }

func (p *teams) Authorize(_ context.Context, req *externalidp.AuthorizeRequest) (*externalidp.AuthorizeResponse, error) {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("response_mode", "query")
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", req.State)
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	// prompt=select_account forces the account picker on each login, matching
	// what users expect when they click "Sign in with Microsoft" multiple
	// times from a shared device. Skip via config later if undesired.
	q.Set("prompt", "select_account")
	return &externalidp.AuthorizeResponse{URL: p.authURL + "?" + q.Encode()}, nil
}

func (p *teams) Exchange(ctx context.Context, req *externalidp.CallbackRequest) (*externalidp.ExternalIdentity, error) {
	// Step 1: code → access_token (client secret in body — Microsoft accepts
	// both basic auth and form-encoded; we use form for consistency with the
	// OAuth2 RFC default).
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("scope", strings.Join(p.cfg.Scopes, " "))
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("client_secret", p.cfg.ClientSecret)

	tReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tReq.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(tReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tokResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return nil, fmt.Errorf("decode token: %w; body=%s", err, string(body))
	}
	if tokResp.AccessToken == "" {
		return nil, fmt.Errorf("teams token exchange: %s %s", tokResp.Error, tokResp.ErrorDesc)
	}

	// Step 2: Graph /me for the canonical profile.
	uReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, teamsGraphMeURL, nil)
	uReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	uReq.Header.Set("Accept", "application/json")
	uResp, err := p.httpClient.Do(uReq)
	if err != nil {
		return nil, err
	}
	defer uResp.Body.Close()
	ub, _ := io.ReadAll(uResp.Body)

	var me struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
		Mail              string `json:"mail"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		MobilePhone       string `json:"mobilePhone"`
	}
	if err := json.Unmarshal(ub, &me); err != nil {
		return nil, fmt.Errorf("decode /me: %w; body=%s", err, string(ub))
	}
	if me.ID == "" {
		return nil, fmt.Errorf("graph /me missing id; body=%s", string(ub))
	}

	// Microsoft sometimes returns the work email under userPrincipalName
	// instead of mail for unconfigured tenants. Prefer mail when present.
	email := me.Mail
	if email == "" {
		email = me.UserPrincipalName
	}
	// userPrincipalName makes a more human username than the opaque OID.
	username := me.UserPrincipalName
	if username == "" {
		username = me.ID
	}

	raw := map[string]any{}
	_ = json.Unmarshal(ub, &raw)
	return &externalidp.ExternalIdentity{
		ProviderType: externalidp.TypeTeams,
		ProviderID:   p.idp.Code,
		ExternalID:   me.ID,
		Username:     username,
		DisplayName:  firstNonEmpty(me.DisplayName, strings.TrimSpace(me.GivenName+" "+me.Surname), me.UserPrincipalName),
		Email:        email,
		Phone:        me.MobilePhone,
		Raw:          raw,
	}, nil
}

func init() {
	externalidp.DefaultRegistry.Register(externalidp.TypeTeams, newTeams)
}
