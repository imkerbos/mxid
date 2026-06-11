package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/imkerbos/mxid/internal/domain/externalidp"
)

const (
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubUserURL  = "https://api.github.com/user"
	githubEmailURL = "https://api.github.com/user/emails"
)

// GitHubConfig — fields stored in mxid_external_idp.config for github type.
type GitHubConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes,omitempty"` // default ["read:user","user:email"]
}

type githubProvider struct {
	idp        *externalidp.ExternalIDP
	cfg        GitHubConfig
	httpClient *http.Client
}

func newGitHub(idp *externalidp.ExternalIDP) (externalidp.Provider, error) {
	var cfg GitHubConfig
	if err := json.Unmarshal(idp.Config, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", externalidp.ErrInvalidConfig, err)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client_id and client_secret required", externalidp.ErrInvalidConfig)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"read:user", "user:email"}
	}
	return &githubProvider{
		idp:        idp,
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (p *githubProvider) Type() string { return externalidp.TypeGitHub }

func (p *githubProvider) Authorize(_ context.Context, req *externalidp.AuthorizeRequest) (*externalidp.AuthorizeResponse, error) {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("state", req.State)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	if req.LoginHint != "" {
		q.Set("login", req.LoginHint)
	}
	return &externalidp.AuthorizeResponse{URL: githubAuthURL + "?" + q.Encode()}, nil
}

func (p *githubProvider) Exchange(ctx context.Context, req *externalidp.CallbackRequest) (*externalidp.ExternalIdentity, error) {
	// Step 1: code → access token (POST with Accept: application/json).
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	tReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(form.Encode()))
	tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tReq.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(tReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var tokResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	if tokResp.Error != "" || tokResp.AccessToken == "" {
		return nil, fmt.Errorf("github token: %s %s", tokResp.Error, tokResp.ErrorDesc)
	}

	// Step 2: fetch user profile.
	uReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	uReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	uReq.Header.Set("Accept", "application/vnd.github+json")
	uResp, err := p.httpClient.Do(uReq)
	if err != nil {
		return nil, err
	}
	defer uResp.Body.Close()
	body, _ := io.ReadAll(uResp.Body)
	var user struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("decode user: %w; body=%s", err, string(body))
	}
	if user.ID == 0 {
		return nil, fmt.Errorf("github user response missing id; body=%s", string(body))
	}

	// Step 3: emails endpoint to grab the primary verified email if the
	// profile didn't include one.
	if user.Email == "" {
		eReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, githubEmailURL, nil)
		eReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
		eReq.Header.Set("Accept", "application/vnd.github+json")
		eResp, err := p.httpClient.Do(eReq)
		if err == nil {
			defer eResp.Body.Close()
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if err := json.NewDecoder(eResp.Body).Decode(&emails); err == nil {
				for _, e := range emails {
					if e.Primary && e.Verified {
						user.Email = e.Email
						break
					}
				}
			}
		}
	}

	raw := map[string]any{}
	_ = json.Unmarshal(body, &raw)
	return &externalidp.ExternalIdentity{
		ProviderType: externalidp.TypeGitHub,
		ProviderID:   p.idp.Code,
		ExternalID:   strconv.FormatInt(user.ID, 10),
		Username:     user.Login,
		DisplayName:  firstNonEmpty(user.Name, user.Login),
		Email:        user.Email,
		Avatar:       user.AvatarURL,
		Raw:          raw,
	}, nil
}

// GitHub provider implementation kept but NOT registered with DefaultRegistry —
// only Lark/Feishu and Teams are exposed at the moment. Re-enable by
// uncommenting the init() below.
//
// func init() {
//     externalidp.DefaultRegistry.Register(externalidp.TypeGitHub, newGitHub)
// }
var _ = newGitHub
