package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/imkerbos/mxid/pkg/dberr"
)

// ExternalLoginInput is the data the external-IdP feature hands to
// ResolveExternalLogin after a successful OAuth exchange. The external IdP
// implementation is EE-only (lives in the mxid-ee module); it reaches this CE
// account-linking entry point through the pkg/ee/registry seam, whose neutral
// registry.ResolverInput is field-identical to this struct.
type ExternalLoginInput struct {
	TenantID     int64
	ProviderType string
	ProviderID   string
	ExternalID   string
	Username     string
	DisplayName  string
	Email        string
	Phone        string
	Avatar       string
	Raw          map[string]any

	// AutoCreate controls behaviour when no binding exists. The caller pulls
	// this from ExternalIDP.AutoCreate.
	AutoCreate bool
	// DefaultOrgID auto-attaches new users to a department; nil = no attach.
	DefaultOrgID *int64
}

// ResolveExternalLogin maps an external identity to a local user ID.
//
//	binding exists       → return its UserID (refresh attributes if missing locally)
//	no binding + auto    → create local user + identity row + (optionally) org rel
//	no binding + !auto   → return ErrExternalUserNotLinked so the caller renders
//	                       a "no account, contact admin" page
//
// Idempotent on repeat logins from the same external user.
func (s *Service) ResolveExternalLogin(ctx context.Context, in *ExternalLoginInput) (*User, error) {
	if in.ExternalID == "" {
		return nil, fmt.Errorf("external id required")
	}

	binding, err := s.repo.GetIdentityByExternal(ctx, in.TenantID, in.ProviderType, in.ProviderID, in.ExternalID)
	if err == nil {
		// Refresh stored attrs opportunistically so console reflects latest IdP state.
		updated := false
		if in.DisplayName != "" && (binding.ExternalName == nil || *binding.ExternalName != in.DisplayName) {
			name := in.DisplayName
			binding.ExternalName = &name
			updated = true
		}
		if len(in.Raw) > 0 {
			if raw, mErr := json.Marshal(in.Raw); mErr == nil {
				s := string(raw)
				binding.Extra = &s
				updated = true
			}
		}
		if updated {
			binding.UpdatedAt = time.Now()
			_ = s.repo.UpdateIdentity(ctx, binding)
		}
		// Fetch the user row.
		u, err := s.repo.GetByID(ctx, binding.UserID)
		if err != nil {
			return nil, fmt.Errorf("get linked user: %w", err)
		}
		return u, nil
	}
	if !dberr.IsNotFound(err) {
		return nil, fmt.Errorf("lookup identity: %w", err)
	}

	if !in.AutoCreate {
		return nil, ErrExternalUserNotLinked
	}

	// Auto-provision a local user. Username collisions get a `-N` suffix so
	// the operation is best-effort idempotent.
	username := pickUsername(in)
	finalUsername, err := s.allocUsername(ctx, in.TenantID, username)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user := &User{
		ID:        s.idGen.Generate(),
		TenantID:  in.TenantID,
		Username:  finalUsername,
		Status:    StatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if in.Email != "" {
		// Only set email if not already used; otherwise leave blank.
		if _, err := s.repo.GetByEmail(ctx, in.TenantID, in.Email); err != nil && dberr.IsNotFound(err) {
			e := in.Email
			user.Email = &e
		}
	}
	if in.Phone != "" {
		if _, err := s.repo.GetByPhone(ctx, in.TenantID, in.Phone); err != nil && dberr.IsNotFound(err) {
			p := in.Phone
			user.Phone = &p
		}
	}
	if in.DisplayName != "" {
		d := in.DisplayName
		user.DisplayName = &d
	}
	if in.Avatar != "" {
		a := in.Avatar
		user.Avatar = &a
	}
	// External users have no local password — set a random hash that won't
	// match anything sane to keep PasswordHash NOT NULL contracts happy.
	random, err := randomDummyHash()
	if err != nil {
		return nil, err
	}
	user.PasswordHash = random

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	// Seed an empty detail row so /users/:id/detail always returns something.
	detail := &UserDetail{
		ID:        s.idGen.Generate(),
		UserID:    user.ID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = s.repo.CreateDetail(ctx, detail)

	// Bind the identity row.
	rawJSON := ""
	if len(in.Raw) > 0 {
		if b, err := json.Marshal(in.Raw); err == nil {
			rawJSON = string(b)
		}
	}
	displayPtr := func() *string {
		if in.DisplayName == "" {
			return nil
		}
		v := in.DisplayName
		return &v
	}()
	extraPtr := func() *string {
		if rawJSON == "" {
			return nil
		}
		return &rawJSON
	}()
	identity := &UserIdentity{
		ID:           s.idGen.Generate(),
		UserID:       user.ID,
		TenantID:     in.TenantID,
		ProviderType: in.ProviderType,
		ProviderID:   in.ProviderID,
		ExternalID:   in.ExternalID,
		ExternalName: displayPtr,
		Extra:        extraPtr,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.repo.CreateIdentity(ctx, identity); err != nil {
		return nil, fmt.Errorf("create identity: %w", err)
	}

	return user, nil
}

// ErrExternalUserNotLinked is returned when no local binding exists and the
// IdP has auto_create disabled.
var ErrExternalUserNotLinked = errors.New("no local account linked to this external identity")

// pickUsername chooses the best candidate username from the external profile.
// Falls back through username → email local part → provider-prefixed externalID.
func pickUsername(in *ExternalLoginInput) string {
	u := strings.TrimSpace(in.Username)
	if u == "" && in.Email != "" {
		u = strings.SplitN(in.Email, "@", 2)[0]
	}
	if u == "" {
		u = in.ProviderType + "_" + in.ExternalID
	}
	// sanitise: keep alphanumerics, dot, dash, underscore.
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, u)
	if len(out) > 64 {
		out = out[:64]
	}
	if out == "" {
		out = "user"
	}
	return out
}

// allocUsername returns the first variant of base that doesn't already exist.
// Loops with -1, -2, ... up to 999 before giving up.
func (s *Service) allocUsername(ctx context.Context, tenantID int64, base string) (string, error) {
	candidate := base
	for i := 0; i < 1000; i++ {
		_, err := s.repo.GetByUsername(ctx, tenantID, candidate)
		if dberr.IsNotFound(err) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("check username: %w", err)
		}
		candidate = fmt.Sprintf("%s-%d", base, i+1)
	}
	return "", fmt.Errorf("could not allocate unique username")
}

// randomDummyHash mints a bcrypt-shaped string that won't match any real
// password but still satisfies the NOT NULL constraint on password_hash.
func randomDummyHash() (string, error) {
	// We deliberately do NOT use the real crypto.HashPassword (bcrypt rounds
	// take ~100ms — wasted on a string that can never match). Encode 32
	// random bytes and prefix with the bcrypt signature so the column passes
	// any optional shape checks.
	b := make([]byte, 32)
	if _, err := randReadDummy(b); err != nil {
		return "", err
	}
	return crypto.NoLocalPasswordPrefix + fmt.Sprintf("%x", b), nil
}
