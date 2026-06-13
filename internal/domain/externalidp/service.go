package externalidp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/imkerbos/mxid/pkg/tenantscope"
	"github.com/redis/go-redis/v9"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// encPrefix marks an encrypted config secret value. Mirrors setting.Service's
// "enc:" convention. A value lacking this prefix on load is treated as legacy
// plaintext (tolerant read) and re-encrypted on the next Update/save.
const encPrefix = "enc:"

// sensitiveConfigKeys maps an IdP Type → the config JSON sub-keys that hold a
// secret and MUST be AES-encrypted at rest + masked in responses. Keep this
// authoritative: a new secret-bearing provider field MUST be registered here
// or it leaks plaintext into the DB and admin responses.
var sensitiveConfigKeys = map[string][]string{
	TypeGitHub: {"client_secret"},
	TypeTeams:  {"client_secret"},
	TypeLark:   {"app_secret"},
	TypeFeishu: {"app_secret"},
	TypeOIDC:   {"client_secret"},
}

// SecretConfigKeys returns the secret sub-keys for a provider type (used by
// handlers to mask responses and preserve ciphertext on empty-secret updates).
func SecretConfigKeys(idpType string) []string { return sensitiveConfigKeys[idpType] }

// MaskedIDP is the response shape for admin List/Get/Create/Update. It embeds
// the row but replaces the raw Config with a copy whose secret sub-keys are
// stripped, and surfaces a per-key "<key>_set" boolean so the admin UI can tell
// whether a secret is configured without ever receiving the plaintext or
// ciphertext.
type MaskedIDP struct {
	*ExternalIDP
	Config     map[string]any  `json:"config"`
	SecretSet  map[string]bool `json:"secret_set"`
}

// MarshalJSON flattens MaskedIDP so the masked Config and SecretSet override the
// embedded row's fields in the JSON output.
func (m MaskedIDP) MarshalJSON() ([]byte, error) {
	type alias ExternalIDP
	base, err := json.Marshal((*alias)(m.ExternalIDP))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(base, &out); err != nil {
		return nil, err
	}
	out["config"] = m.Config
	out["secret_set"] = m.SecretSet
	return json.Marshal(out)
}

// Mask returns a MaskedIDP safe to serialize to the admin browser: the secret
// config sub-keys are removed and replaced by a "<key>_set" sentinel. Never
// returns plaintext OR ciphertext for a secret.
func Mask(idp *ExternalIDP) *MaskedIDP {
	cfg := map[string]any{}
	if len(idp.Config) > 0 {
		_ = json.Unmarshal(idp.Config, &cfg)
	}
	setMap := map[string]bool{}
	for _, k := range sensitiveConfigKeys[idp.Type] {
		v, ok := cfg[k].(string)
		setMap[k] = ok && v != ""
		delete(cfg, k)
	}
	return &MaskedIDP{ExternalIDP: idp, Config: cfg, SecretSet: setMap}
}

// MaskList masks a slice of IdPs for the admin list response.
func MaskList(idps []*ExternalIDP) []*MaskedIDP {
	out := make([]*MaskedIDP, 0, len(idps))
	for _, idp := range idps {
		out = append(out, Mask(idp))
	}
	return out
}

// Service errors.
var (
	ErrIDPNotFound    = errors.New("external idp not found")
	ErrIDPDisabled    = errors.New("external idp is disabled")
	ErrIDPCodeExists  = errors.New("idp code already exists")
)

// Service orchestrates CRUD for external IdPs plus the per-login state cache.
//
// State cache: each Authorize() call mints a random opaque token, persists
// (idp_id, redirect_uri) under it in Redis with a short TTL, and embeds the
// token as the `state` query parameter. Callback handler retrieves+deletes
// the entry to defeat CSRF.
type Service struct {
	repo      Repository
	registry  *Registry
	idGen     *snowflake.Generator
	rdb       *redis.Client
	eventBus  *event.Bus
	masterKey *crypto.MasterKey
}

// NewService builds a Service. registry defaults to DefaultRegistry.
func NewService(repo Repository, idGen *snowflake.Generator, rdb *redis.Client, registry *Registry, eventBus *event.Bus, masterKey *crypto.MasterKey) *Service {
	if registry == nil {
		registry = DefaultRegistry
	}
	return &Service{repo: repo, registry: registry, idGen: idGen, rdb: rdb, eventBus: eventBus, masterKey: masterKey}
}

/* ──────────────── Config secret crypto ──────────────── */

// encryptConfig returns a copy of the raw config JSON with its registered
// secret sub-keys AES-encrypted (prefixed with encPrefix). Already-encrypted
// values are left untouched so re-saving is idempotent. Mirrors
// setting.Service.encryptSensitive.
func (s *Service) encryptConfig(idpType string, raw []byte) ([]byte, error) {
	keys := sensitiveConfigKeys[idpType]
	if len(keys) == 0 || len(raw) == 0 {
		return raw, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	mutated := false
	for _, k := range keys {
		v, ok := m[k].(string)
		if !ok || v == "" {
			continue
		}
		if strings.HasPrefix(v, encPrefix) {
			continue // already ciphertext
		}
		if s.masterKey == nil {
			// Fail closed on write: never persist a fresh plaintext secret when
			// the key is misconfigured.
			return nil, fmt.Errorf("encrypt config %s.%s: master key not configured", idpType, k)
		}
		enc, err := s.masterKey.Encrypt([]byte(v))
		if err != nil {
			return nil, fmt.Errorf("encrypt config %s.%s: %w", idpType, k, err)
		}
		m[k] = encPrefix + enc
		mutated = true
	}
	if !mutated {
		return raw, nil
	}
	return json.Marshal(m)
}

// decryptConfig returns a copy of the raw config JSON with its registered
// secret sub-keys decrypted to plaintext. Tolerant read: a value lacking the
// encPrefix is treated as legacy plaintext and passed through unchanged (it
// gets encrypted on the next Update/save). Mirrors app_cert's Encrypted-flag
// dual-read.
func (s *Service) decryptConfig(idpType string, raw []byte) ([]byte, error) {
	keys := sensitiveConfigKeys[idpType]
	if len(keys) == 0 || len(raw) == 0 {
		return raw, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	mutated := false
	for _, k := range keys {
		v, ok := m[k].(string)
		if !ok || v == "" {
			continue
		}
		if !strings.HasPrefix(v, encPrefix) {
			continue // legacy plaintext — tolerant pass-through
		}
		if s.masterKey == nil {
			return nil, fmt.Errorf("decrypt config %s.%s: master key not configured", idpType, k)
		}
		plain, err := s.masterKey.Decrypt(strings.TrimPrefix(v, encPrefix))
		if err != nil {
			return nil, fmt.Errorf("decrypt config %s.%s: %w", idpType, k, err)
		}
		m[k] = string(plain)
		mutated = true
	}
	if !mutated {
		return raw, nil
	}
	return json.Marshal(m)
}

// buildDecrypted clones the IdP row, decrypts its config secrets in place, and
// builds the provider from the plaintext config. Used by login paths that
// genuinely need the secret. The stored row's ciphertext is never mutated.
func (s *Service) buildDecrypted(idp *ExternalIDP) (Provider, error) {
	dec, err := s.decryptConfig(idp.Type, idp.Config)
	if err != nil {
		return nil, err
	}
	clone := *idp
	clone.Config = datatypes.JSON(dec)
	return s.registry.Build(&clone)
}

// publish emits an external-IdP config event. Actor / IP are denormalized
// downstream from the request-scoped auditctx.
func (s *Service) publish(ctx context.Context, eventType string, idp *ExternalIDP) {
	if s.eventBus == nil {
		return
	}
	s.eventBus.Publish(ctx, event.Event{
		Type:    eventType,
		Payload: map[string]any{"id": idp.ID, "name": idp.Name, "type": idp.Type},
	})
}

/* ──────────────────────── CRUD ──────────────────────── */

// CreateRequest carries fields for POST /external-idps.
type CreateRequest struct {
	Type         string         `json:"type" binding:"required"`
	Name         string         `json:"name" binding:"required,max=128"`
	Code         string         `json:"code" binding:"required,max=64"`
	Icon         *string        `json:"icon"`
	Description  *string        `json:"description"`
	Config       map[string]any `json:"config" binding:"required"`
	AutoCreate   *bool          `json:"auto_create"`
	DefaultOrgID *int64         `json:"default_org_id,string,omitempty"`
	SortOrder    int            `json:"sort_order"`
}

// UpdateRequest carries fields for PUT /external-idps/:id.
type UpdateRequest struct {
	Name         *string        `json:"name"`
	Icon         *string        `json:"icon"`
	Description  *string        `json:"description"`
	Config       map[string]any `json:"config"`
	Status       *int           `json:"status"`
	AutoCreate   *bool          `json:"auto_create"`
	DefaultOrgID *int64         `json:"default_org_id,string,omitempty"`
	SortOrder    *int           `json:"sort_order"`
}

// Create persists a new IdP row. Validates the type is registered and the
// config compiles into a Provider so admins get immediate feedback on bad
// credentials instead of discovering at first login.
func (s *Service) Create(ctx context.Context, tenantID int64, req *CreateRequest) (*ExternalIDP, error) {
	if _, err := s.repo.GetByCode(ctx, tenantID, req.Code); err == nil {
		return nil, ErrIDPCodeExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("check code: %w", err)
	}

	cfgRaw, err := json.Marshal(req.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	autoCreate := true
	if req.AutoCreate != nil {
		autoCreate = *req.AutoCreate
	}

	idp := &ExternalIDP{
		ID:           s.idGen.Generate(),
		TenantID:     tenantID,
		Type:         req.Type,
		Name:         req.Name,
		Code:         req.Code,
		Icon:         req.Icon,
		Description:  req.Description,
		Config:       datatypes.JSON(cfgRaw),
		Status:       StatusEnabled,
		AutoCreate:   autoCreate,
		DefaultOrgID: req.DefaultOrgID,
		SortOrder:    req.SortOrder,
	}

	// Sanity-build the provider from the plaintext config so misconfigured
	// rows never land in DB.
	if _, err := s.registry.Build(idp); err != nil {
		return nil, fmt.Errorf("provider validation failed: %w", err)
	}

	// Encrypt secret config sub-keys at rest before persisting.
	enc, err := s.encryptConfig(idp.Type, idp.Config)
	if err != nil {
		return nil, err
	}
	idp.Config = datatypes.JSON(enc)

	if err := s.repo.Create(ctx, idp); err != nil {
		return nil, err
	}
	s.publish(ctx, event.IDPCreated, idp)
	return idp, nil
}

// Update applies a patch to an existing IdP.
func (s *Service) Update(ctx context.Context, id int64, req *UpdateRequest) (*ExternalIDP, error) {
	idp, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrIDPNotFound
		}
		return nil, err
	}
	if req.Name != nil {
		idp.Name = *req.Name
	}
	if req.Icon != nil {
		idp.Icon = req.Icon
	}
	if req.Description != nil {
		idp.Description = req.Description
	}
	// idpType is the effective provider type for crypto-key lookup (Type is
	// immutable on Update, so the stored row's Type is authoritative).
	idpType := idp.Type
	// storedConfig is the existing at-rest (encrypted) config, used to preserve
	// secret sub-keys the admin left blank/masked in the PUT body.
	storedConfig := append(datatypes.JSON(nil), idp.Config...)
	if req.Config != nil {
		merged, err := s.preserveSecrets(idpType, storedConfig, req.Config)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(merged)
		if err != nil {
			return nil, fmt.Errorf("marshal config: %w", err)
		}
		idp.Config = datatypes.JSON(raw)
	}
	if req.Status != nil {
		idp.Status = *req.Status
	}
	if req.AutoCreate != nil {
		idp.AutoCreate = *req.AutoCreate
	}
	if req.DefaultOrgID != nil {
		idp.DefaultOrgID = req.DefaultOrgID
	}
	if req.SortOrder != nil {
		idp.SortOrder = *req.SortOrder
	}

	if req.Config != nil {
		// Validate against a fully-decrypted view (preserved sub-keys may still
		// be ciphertext from the stored row).
		if _, err := s.buildDecrypted(idp); err != nil {
			return nil, fmt.Errorf("provider validation failed: %w", err)
		}
		// Encrypt fresh plaintext secrets at rest; already-encrypted preserved
		// values are left untouched (encryptConfig is idempotent).
		enc, err := s.encryptConfig(idpType, idp.Config)
		if err != nil {
			return nil, err
		}
		idp.Config = datatypes.JSON(enc)
	}
	if err := s.repo.Update(ctx, idp); err != nil {
		return nil, err
	}
	s.publish(ctx, event.IDPUpdated, idp)
	return idp, nil
}

// preserveSecrets merges the incoming PUT config with the stored (encrypted)
// config: for each registered secret sub-key, if the incoming value is empty or
// the masked sentinel, the stored ciphertext is carried over; otherwise the new
// plaintext is kept. Non-secret keys come entirely from the incoming config.
func (s *Service) preserveSecrets(idpType string, stored []byte, incoming map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(incoming))
	for k, v := range incoming {
		out[k] = v
	}
	keys := sensitiveConfigKeys[idpType]
	if len(keys) == 0 {
		return out, nil
	}
	var storedMap map[string]any
	if len(stored) > 0 {
		if err := json.Unmarshal(stored, &storedMap); err != nil {
			return nil, fmt.Errorf("decode stored config: %w", err)
		}
	}
	for _, k := range keys {
		v, _ := out[k].(string)
		if v != "" && v != crypto.MaskedSecret {
			continue // admin supplied a fresh secret
		}
		// Preserve the stored value (still ciphertext) verbatim.
		if storedMap != nil {
			if sv, ok := storedMap[k]; ok {
				out[k] = sv
				continue
			}
		}
		// No stored value and none supplied → drop the empty/masked key so it
		// doesn't persist as an empty string.
		delete(out, k)
	}
	return out, nil
}

// Delete removes an IdP. Existing user_identity bindings are left in place
// so admins can audit historical links; new logins via this IdP will fail.
func (s *Service) Delete(ctx context.Context, id int64) error {
	// Load before delete so the audit event carries the IdP name/type.
	// Already gone → idempotent success (preserves the prior no-op behavior).
	idp, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.publish(ctx, event.IDPDeleted, idp)
	return nil
}

// Get returns an IdP by ID.
func (s *Service) Get(ctx context.Context, id int64) (*ExternalIDP, error) {
	idp, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrIDPNotFound
		}
		return nil, err
	}
	return idp, nil
}

// List returns IdPs for a tenant.
func (s *Service) List(ctx context.Context, tenantID int64, enabledOnly bool) ([]*ExternalIDP, error) {
	return s.repo.List(ctx, tenantID, enabledOnly)
}

// ListPublic returns the IdPs to expose on the portal login page (status=enabled).
// The Config field is stripped — secrets must never reach the browser.
func (s *Service) ListPublic(ctx context.Context, tenantID int64) ([]*ExternalIDP, error) {
	all, err := s.repo.List(ctx, tenantID, true)
	if err != nil {
		return nil, err
	}
	out := make([]*ExternalIDP, 0, len(all))
	for _, idp := range all {
		clone := *idp
		clone.Config = datatypes.JSON([]byte("{}"))
		out = append(out, &clone)
	}
	return out, nil
}

/* ──────────────────────── Login flow ──────────────────────── */

const (
	statePrefix = "mxid:extidp:state:"
	stateTTL    = 5 * time.Minute
)

type stateEntry struct {
	IdpID       int64  `json:"idp_id"`
	TenantID    int64  `json:"tenant_id"`
	RedirectURI string `json:"redirect_uri"`
	// FinalReturnURL is where the gateway sends the user-agent after the
	// callback fully succeeds (e.g. /portal home page). Optional.
	FinalReturnURL string `json:"final_return_url,omitempty"`
}

// StartLogin generates an authorize URL for the given IdP code. The caller
// (gateway) issues a 302 to the URL; the user authenticates at the IdP and
// is bounced back to redirectURI?code=...&state=...
func (s *Service) StartLogin(ctx context.Context, tenantID int64, code, redirectURI, finalReturnURL string) (string, error) {
	// Pre-session flow: pin the explicit tenant so the IdP-config read is
	// tenant-scoped under the gorm isolation plugin.
	ctx = tenantscope.WithTenant(ctx, tenantID)
	idp, err := s.repo.GetByCode(ctx, tenantID, code)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrIDPNotFound
		}
		return "", err
	}
	if idp.Status != StatusEnabled {
		return "", ErrIDPDisabled
	}

	provider, err := s.buildDecrypted(idp)
	if err != nil {
		return "", err
	}

	state, err := generateState()
	if err != nil {
		return "", err
	}

	entry := stateEntry{
		IdpID:          idp.ID,
		TenantID:       tenantID,
		RedirectURI:    redirectURI,
		FinalReturnURL: finalReturnURL,
	}
	raw, _ := json.Marshal(entry)
	if err := s.rdb.Set(ctx, statePrefix+state, raw, stateTTL).Err(); err != nil {
		return "", fmt.Errorf("persist state: %w", err)
	}

	auth, err := provider.Authorize(ctx, &AuthorizeRequest{State: state, RedirectURI: redirectURI})
	if err != nil {
		return "", err
	}
	return auth.URL, nil
}

// FinishLogin consumes the state token and runs the IdP code exchange.
// Returns the normalised identity AND the persisted IdP row so the caller
// can decide auto-create semantics.
func (s *Service) FinishLogin(ctx context.Context, state, code string) (*ExternalIDP, *ExternalIdentity, string, error) {
	if state == "" || code == "" {
		return nil, nil, "", ErrStateMismatch
	}
	raw, err := s.rdb.GetDel(ctx, statePrefix+state).Result()
	if err != nil {
		return nil, nil, "", ErrStateMismatch
	}
	var entry stateEntry
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		return nil, nil, "", fmt.Errorf("decode state: %w", err)
	}
	// The OAuth callback carries no session; the tenant was captured into the
	// state at StartLogin. Pin it so the IdP-config read is tenant-scoped.
	if entry.TenantID > 0 {
		ctx = tenantscope.WithTenant(ctx, entry.TenantID)
	}
	idp, err := s.repo.GetByID(ctx, entry.IdpID)
	if err != nil {
		return nil, nil, "", err
	}
	provider, err := s.buildDecrypted(idp)
	if err != nil {
		return nil, nil, "", err
	}
	identity, err := provider.Exchange(ctx, &CallbackRequest{
		Code:        code,
		State:       state,
		RedirectURI: entry.RedirectURI,
	})
	if err != nil {
		return nil, nil, "", err
	}
	return idp, identity, entry.FinalReturnURL, nil
}

// generateState mints a 32-byte url-safe random token. The Redis state cache
// then verifies it on callback.
func generateState() (string, error) {
	// crypto/rand via the standard pattern; kept inline to avoid pulling
	// another helper into this package.
	const n = 32
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	// base64-url without padding.
	return strings.TrimRight(base64URL(b), "="), nil
}
