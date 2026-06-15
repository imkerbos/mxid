package platformconfig

import (
	"context"
	"encoding/json"
	"fmt"
)

// Service is a thin typed wrapper over the KV repository. Values are stored as
// JSON; callers pass their own structs (e.g. setting.License) to Get/Set.
type Service struct{ repo Repository }

// NewService wires the platform-config service.
func NewService(repo Repository) *Service { return &Service{repo: repo} }

// Get reads key and JSON-decodes it into target. Returns ErrNotFound when the
// key is absent so callers can distinguish "first boot" from a real error.
func (s *Service) Get(ctx context.Context, key string, target any) error {
	row, err := s.repo.Get(ctx, key)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(row.Value, target); err != nil {
		return fmt.Errorf("decode platform config %q: %w", key, err)
	}
	return nil
}

// Set JSON-encodes value and upserts it under key.
func (s *Service) Set(ctx context.Context, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode platform config %q: %w", key, err)
	}
	return s.repo.Upsert(ctx, key, raw)
}
