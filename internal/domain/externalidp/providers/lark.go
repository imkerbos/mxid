// Package providers contains the per-vendor implementations of the
// externalidp.Provider interface. Each file is self-contained and registers
// its factory into externalidp.DefaultRegistry via init().
package providers

import (
	"bytes"
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

// Lark / Feishu OAuth2 endpoints. Lark.com hosts the international SaaS;
// open.feishu.cn hosts the China deployment. Both speak the same protocol;
// the only difference is the host, so we switch on idp.Type.
const (
	larkAuthURL     = "https://open.larksuite.com/open-apis/authen/v1/index"
	larkTokenURL    = "https://open.larksuite.com/open-apis/authen/v1/oidc/access_token"
	larkUserInfoURL = "https://open.larksuite.com/open-apis/authen/v1/user_info"

	feishuAuthURL     = "https://open.feishu.cn/open-apis/authen/v1/index"
	feishuTokenURL    = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"
	feishuUserInfoURL = "https://open.feishu.cn/open-apis/authen/v1/user_info"

	// Lark/Feishu requires an app_access_token (server-to-server) before
	// invoking the OIDC user_access_token endpoint. The tenant access token
	// expires after ~2h; we fetch fresh on every login for simplicity.
	larkAppTokenURL    = "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal"
	feishuAppTokenURL  = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
)

// LarkConfig is the JSON shape stored in mxid_external_idp.config for
// Lark/Feishu IdPs.
type LarkConfig struct {
	AppID     string   `json:"app_id"`
	AppSecret string   `json:"app_secret"`
	// Scopes is optional — Lark currently ignores the parameter for OIDC
	// flow but we surface it so admins can future-proof.
	Scopes []string `json:"scopes,omitempty"`
}

// lark is the Provider for both Lark (intl) and Feishu (CN). Only the
// endpoint hostnames differ; we pick at construction time.
type lark struct {
	idp        *externalidp.ExternalIDP
	cfg        LarkConfig
	authURL    string
	tokenURL   string
	userURL    string
	appTokenURL string
	httpClient *http.Client
}

func newLark(idp *externalidp.ExternalIDP) (externalidp.Provider, error) {
	var cfg LarkConfig
	if err := json.Unmarshal(idp.Config, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", externalidp.ErrInvalidConfig, err)
	}
	if cfg.AppID == "" || cfg.AppSecret == "" {
		return nil, fmt.Errorf("%w: app_id and app_secret required", externalidp.ErrInvalidConfig)
	}
	p := &lark{
		idp:        idp,
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
	switch idp.Type {
	case externalidp.TypeFeishu:
		p.authURL = feishuAuthURL
		p.tokenURL = feishuTokenURL
		p.userURL = feishuUserInfoURL
		p.appTokenURL = feishuAppTokenURL
	default:
		// Default to Lark (intl). Lark and Feishu share schema so picking the
		// intl host for unspecified deployments is the safer default.
		p.authURL = larkAuthURL
		p.tokenURL = larkTokenURL
		p.userURL = larkUserInfoURL
		p.appTokenURL = larkAppTokenURL
	}
	return p, nil
}

func (p *lark) Type() string { return p.idp.Type }

func (p *lark) Authorize(_ context.Context, req *externalidp.AuthorizeRequest) (*externalidp.AuthorizeResponse, error) {
	// Lark v1 OIDC: GET /authen/v1/index?app_id=...&redirect_uri=...&state=...
	q := url.Values{}
	q.Set("app_id", p.cfg.AppID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("state", req.State)
	return &externalidp.AuthorizeResponse{URL: p.authURL + "?" + q.Encode()}, nil
}

func (p *lark) Exchange(ctx context.Context, req *externalidp.CallbackRequest) (*externalidp.ExternalIdentity, error) {
	// Step 1: tenant access token (server creds → opaque token for outbound calls).
	appToken, err := p.fetchAppToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch app token: %w", err)
	}

	// Step 2: exchange the OAuth code for a user access token + open_id.
	tokenResp, err := p.fetchUserToken(ctx, appToken, req.Code)
	if err != nil {
		return nil, fmt.Errorf("fetch user token: %w", err)
	}

	// Step 3: fetch the full user profile.
	profile, err := p.fetchUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch user info: %w", err)
	}

	// Lark's stable per-tenant id is open_id; user_id rotates if the admin
	// re-installs the app. union_id is stable across the ISV's apps. We
	// pick open_id as the ExternalID — fine for non-ISV deployments.
	identity := &externalidp.ExternalIdentity{
		ProviderType: p.idp.Type,
		ProviderID:   p.idp.Code,
		ExternalID:   profile.OpenID,
		Username:     firstNonEmpty(profile.EnName, profile.Mobile, profile.OpenID),
		DisplayName:  firstNonEmpty(profile.Name, profile.EnName),
		Email:        profile.Email,
		Phone:        profile.Mobile,
		Avatar:       profile.AvatarURL,
		Raw:          map[string]any{},
	}
	// Stash the full profile JSON for admin inspection.
	_ = json.Unmarshal(profile.raw, &identity.Raw)
	return identity, nil
}

/* ─────────────────────────── HTTP helpers ─────────────────────────────── */

type larkAppTokenResp struct {
	Code              int    `json:"code"`
	Msg               string `json:"msg"`
	TenantAccessToken string `json:"tenant_access_token"`
}

func (p *lark) fetchAppToken(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"app_id":     p.cfg.AppID,
		"app_secret": p.cfg.AppSecret,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.appTokenURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out larkAppTokenResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Code != 0 {
		return "", fmt.Errorf("lark app token: code=%d msg=%s", out.Code, out.Msg)
	}
	return out.TenantAccessToken, nil
}

type larkTokenResp struct {
	Code int `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		RefreshToken     string `json:"refresh_token"`
		RefreshExpiresIn int    `json:"refresh_expires_in"`
		TokenType        string `json:"token_type"`
	} `json:"data"`
	AccessToken string `json:"access_token"`
}

func (p *lark) fetchUserToken(ctx context.Context, appToken, code string) (*larkTokenResp, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type": "authorization_code",
		"code":       code,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+appToken)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)

	var out larkTokenResp
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("decode token resp: %w; body=%s", err, string(rb))
	}
	if out.Code != 0 {
		return nil, fmt.Errorf("lark token exchange: code=%d msg=%s", out.Code, out.Msg)
	}
	// Lark wraps in `data`; copy access_token to top-level for caller.
	out.AccessToken = out.Data.AccessToken
	if out.AccessToken == "" {
		return nil, fmt.Errorf("lark token response missing access_token")
	}
	return &out, nil
}

type larkUserInfo struct {
	Name      string `json:"name"`
	EnName    string `json:"en_name"`
	AvatarURL string `json:"avatar_url"`
	Email     string `json:"email"`
	Mobile    string `json:"mobile"`
	OpenID    string `json:"open_id"`
	UnionID   string `json:"union_id"`
	UserID    string `json:"user_id"`
	TenantKey string `json:"tenant_key"`
	raw       []byte
}

func (p *lark) fetchUserInfo(ctx context.Context, userToken string) (*larkUserInfo, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.userURL, nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var wrap struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rb, &wrap); err != nil {
		return nil, fmt.Errorf("decode user info: %w; body=%s", err, string(rb))
	}
	if wrap.Code != 0 {
		return nil, fmt.Errorf("lark user info: code=%d msg=%s", wrap.Code, wrap.Msg)
	}
	var info larkUserInfo
	if err := json.Unmarshal(wrap.Data, &info); err != nil {
		return nil, fmt.Errorf("decode user info data: %w", err)
	}
	info.raw = wrap.Data
	return &info, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	externalidp.DefaultRegistry.Register(externalidp.TypeLark, newLark)
	externalidp.DefaultRegistry.Register(externalidp.TypeFeishu, newLark)
}
