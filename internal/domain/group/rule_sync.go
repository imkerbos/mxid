package group

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Rule-related service errors.
var (
	ErrRuleNotFound    = errors.New("group has no rule")
	ErrGroupNotDynamic = errors.New("group is not dynamic (set type=2 before attaching a rule)")
	ErrGroupIsDynamic  = errors.New("dynamic groups manage members via rule; manual member ops are disabled")
)

// RuleQueryer abstracts the DB calls the sync engine needs. Implemented by
// the repository — exposed as an interface here so service tests can stub it.
type RuleQueryer interface {
	GetRule(ctx context.Context, groupID int64) (*UserGroupRule, error)
	UpsertRule(ctx context.Context, rule *UserGroupRule) error
	DeleteRule(ctx context.Context, groupID int64) error
	// EvaluateRule runs the compiled rule against mxid_user and returns the
	// matching user IDs. The implementation is in repository_impl.go so the
	// raw SQL stays in one place.
	EvaluateRule(ctx context.Context, tenantID int64, cr *CompiledRule) ([]int64, error)
}

// GetRule returns the rule attached to a group, or ErrRuleNotFound.
func (s *Service) GetRule(ctx context.Context, groupID int64) (*UserGroupRule, error) {
	// Tenant-ownership guard before reading the tenant-less rule row.
	if _, err := s.requireGroup(ctx, groupID); err != nil {
		return nil, err
	}
	r, err := s.repo.GetRule(ctx, groupID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRuleNotFound
		}
		return nil, fmt.Errorf("get rule: %w", err)
	}
	return r, nil
}

// UpsertRule writes (or replaces) a group's rule. The group is also flipped
// to type=dynamic so existing members are no longer manually editable. The
// initial sync runs immediately so the UI sees populated members on save.
func (s *Service) UpsertRule(ctx context.Context, groupID int64, expr *RuleExpr) (*UserGroupRule, error) {
	g, err := s.repo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}

	raw, err := json.Marshal(expr)
	if err != nil {
		return nil, fmt.Errorf("marshal rule: %w", err)
	}

	rule := &UserGroupRule{
		ID:      s.idGen.Generate(),
		GroupID: groupID,
		Expr:    datatypes.JSON(raw),
		Status:  RuleEnabled,
	}
	if err := s.repo.UpsertRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("upsert rule: %w", err)
	}

	if g.Type != TypeDynamic {
		g.Type = TypeDynamic
		if err := s.repo.Update(ctx, g); err != nil {
			return nil, fmt.Errorf("flip group to dynamic: %w", err)
		}
	}

	// First sync inline so the UI sees populated members immediately.
	if _, err := s.SyncRule(ctx, groupID); err != nil {
		// Sync failure does not roll back the rule — operator can fix the
		// rule and retry. Surface the error to the caller.
		return rule, fmt.Errorf("initial sync: %w", err)
	}
	return s.repo.GetRule(ctx, groupID)
}

// DeleteRule removes a group's rule and flips it back to type=static.
// Existing members are kept so the operator can prune manually if desired.
func (s *Service) DeleteRule(ctx context.Context, groupID int64) error {
	g, err := s.repo.GetByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("get group: %w", err)
	}
	if err := s.repo.DeleteRule(ctx, groupID); err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if g.Type != TypeStatic {
		g.Type = TypeStatic
		if err := s.repo.Update(ctx, g); err != nil {
			return fmt.Errorf("flip group to static: %w", err)
		}
	}
	return nil
}

// SyncReport summarises one sync cycle.
type SyncReport struct {
	GroupID int64 `json:"group_id,string"`
	Added   int   `json:"added"`
	Removed int   `json:"removed"`
}

// SyncRule recomputes the membership of a dynamic group from its rule.
//
// Algorithm:
//  1. Resolve the matching user IDs via EvaluateRule (parameterised SQL).
//  2. Diff against the current members.
//  3. INSERT additions in batch (ON CONFLICT skip), DELETE removals.
//  4. Update last_sync_* fields on the rule row.
//
// Errors during compile/evaluate are persisted to last_sync_error so the UI
// can show the operator what's wrong without re-running.
func (s *Service) SyncRule(ctx context.Context, groupID int64) (*SyncReport, error) {
	// Tenant-ownership guard at the very top — before the rule row is read, so a
	// cross-tenant groupID cannot disclose another tenant's rule expression.
	g, err := s.requireGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	rule, err := s.repo.GetRule(ctx, groupID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRuleNotFound
		}
		return nil, fmt.Errorf("get rule: %w", err)
	}
	if rule.Status != RuleEnabled {
		return &SyncReport{GroupID: groupID}, nil
	}

	expr, err := ValidateRule([]byte(rule.Expr))
	if err != nil {
		_ = s.repo.MarkRuleSync(ctx, groupID, 0, 0, err.Error())
		return nil, fmt.Errorf("validate rule: %w", err)
	}
	compiled, err := Compile(expr)
	if err != nil {
		_ = s.repo.MarkRuleSync(ctx, groupID, 0, 0, err.Error())
		return nil, fmt.Errorf("compile rule: %w", err)
	}

	matched, err := s.repo.EvaluateRule(ctx, g.TenantID, compiled)
	if err != nil {
		_ = s.repo.MarkRuleSync(ctx, groupID, 0, 0, err.Error())
		return nil, fmt.Errorf("evaluate rule: %w", err)
	}

	current, err := s.repo.AllMemberIDs(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("list current members: %w", err)
	}

	toAdd, toRemove := diffMembers(matched, current)

	if len(toAdd) > 0 {
		members := make([]*UserGroupMember, 0, len(toAdd))
		for _, uid := range toAdd {
			members = append(members, &UserGroupMember{
				ID:      s.idGen.Generate(),
				GroupID: groupID,
				UserID:  uid,
			})
		}
		if _, err := s.repo.AddMembers(ctx, groupID, members); err != nil {
			_ = s.repo.MarkRuleSync(ctx, groupID, 0, 0, err.Error())
			return nil, fmt.Errorf("add members: %w", err)
		}
	}
	if len(toRemove) > 0 {
		if _, err := s.repo.RemoveMembers(ctx, groupID, toRemove); err != nil {
			_ = s.repo.MarkRuleSync(ctx, groupID, len(toAdd), 0, err.Error())
			return nil, fmt.Errorf("remove members: %w", err)
		}
	}

	if err := s.repo.MarkRuleSync(ctx, groupID, len(toAdd), len(toRemove), ""); err != nil {
		return nil, fmt.Errorf("mark sync: %w", err)
	}

	return &SyncReport{
		GroupID: groupID,
		Added:   len(toAdd),
		Removed: len(toRemove),
	}, nil
}

// diffMembers returns (additions, removals) for matched vs current sets.
func diffMembers(matched, current []int64) (toAdd, toRemove []int64) {
	matchedSet := make(map[int64]struct{}, len(matched))
	currentSet := make(map[int64]struct{}, len(current))
	for _, id := range matched {
		matchedSet[id] = struct{}{}
	}
	for _, id := range current {
		currentSet[id] = struct{}{}
	}
	for _, id := range matched {
		if _, ok := currentSet[id]; !ok {
			toAdd = append(toAdd, id)
		}
	}
	for _, id := range current {
		if _, ok := matchedSet[id]; !ok {
			toRemove = append(toRemove, id)
		}
	}
	return toAdd, toRemove
}

// buildEvaluateSQL composes the SELECT statement from a CompiledRule. Kept on
// the service side (vs the repo) so tests can assert on the generated SQL
// without spinning up a database.
//
// Selects mxid_user.id filtered by the rule, scoped to tenant + not-deleted.
// Joins are added only when the rule references their columns.
func buildEvaluateSQL(cr *CompiledRule) string {
	var joins strings.Builder
	// org_id conditions always need the user-org join.
	if len(cr.JoinOrgFor) > 0 {
		joins.WriteString(" LEFT JOIN mxid_user_org uo ON uo.user_id = u.id ")
	}
	if cr.JoinDetail {
		joins.WriteString(" LEFT JOIN mxid_user_detail d ON d.user_id = u.id ")
	}

	q := "SELECT DISTINCT u.id FROM mxid_user u" + joins.String() +
		" WHERE u.tenant_id = ? AND u.deleted_at IS NULL AND (" + cr.WhereSQL + ")"
	return q
}
