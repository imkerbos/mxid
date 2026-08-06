package group

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/event"
	"go.uber.org/zap"
)

// The background sweeper must not write audit entries; an operator-triggered
// sync must.
//
// The audit log answers "who did what". The sweeper runs every 30 minutes over
// every dynamic group, and almost every pass moves nobody — so publishing from
// there files a steady stream of actor-less "rule synced" rows that bury the
// entries a reviewer is actually looking for. It is the same failure as having
// no audit at all, arrived at from the opposite direction.
//
// This was introduced and caught in the same session: adding the audit events
// made ResyncTenantDynamicGroups start publishing, and the dev database filled
// with rows reading `added: 0, removed: 0` and no actor.
func TestSweeperSyncDoesNotPublishWhileOperatorSyncDoes(t *testing.T) {
	repo := &recordingRuleRepo{}
	bus := event.NewBus(zap.NewNop())

	// Publish is asynchronous, so events arrive on a channel rather than in a
	// slice the test can read straight after the call.
	got := make(chan string, 8)
	for _, evt := range []string{event.GroupRuleSynced, event.GroupRuleUpdated, event.GroupRuleDeleted} {
		e := evt
		bus.Subscribe(e, func(context.Context, event.Event) { got <- e })
	}
	// drain waits briefly for one event. An empty string means none arrived,
	// which for the sweeper is the assertion, not a timeout failure.
	drain := func() string {
		select {
		case e := <-got:
			return e
		case <-time.After(250 * time.Millisecond):
			return ""
		}
	}

	svc := NewService(repo, nil, bus, zap.NewNop())
	ctx := context.Background()

	// The sweeper's path.
	if _, err := svc.syncRule(ctx, 1); err != nil {
		t.Fatalf("syncRule: %v", err)
	}
	if e := drain(); e != "" {
		t.Fatalf("the sweeper published %q — every dynamic group, every 30 minutes, "+
			"with no actor: that is noise the audit log cannot absorb", e)
	}

	// The operator's path.
	if _, err := svc.SyncRule(ctx, 1); err != nil {
		t.Fatalf("SyncRule: %v", err)
	}
	if e := drain(); e != event.GroupRuleSynced {
		t.Fatalf("operator-triggered sync published %q, want %q — a manual resync "+
			"is a deliberate act and has to be answerable for", e, event.GroupRuleSynced)
	}
	if e := drain(); e != "" {
		t.Fatalf("operator-triggered sync published a second event %q — one action, "+
			"one entry", e)
	}
}

// The contract above is only useful if the sweeper actually calls the quiet
// variant. This drives ResyncTenantDynamicGroups itself, which is the function
// the 30-minute worker runs — so switching it back to the publishing SyncRule
// fails here even though the contract test still passes.
func TestResyncTenantDynamicGroupsIsSilent(t *testing.T) {
	repo := &recordingRuleRepo{}
	bus := event.NewBus(zap.NewNop())
	got := make(chan string, 8)
	for _, evt := range []string{event.GroupRuleSynced, event.GroupRuleUpdated, event.GroupRuleDeleted} {
		e := evt
		bus.Subscribe(e, func(context.Context, event.Event) { got <- e })
	}

	svc := NewService(repo, nil, bus, zap.NewNop())
	svc.ResyncTenantDynamicGroups(context.Background(), 100)

	select {
	case e := <-got:
		t.Fatalf("the 30-minute reconcile published %q. It runs over every dynamic "+
			"group on every tick and belongs to no operator, so each pass would "+
			"file rows that push real entries off the first page of the audit log.", e)
	case <-time.After(250 * time.Millisecond):
	}
}

// recordingRuleRepo is the smallest Repository that lets SyncRule run: one
// dynamic group, a rule matching nobody, no members.
type recordingRuleRepo struct {
	Repository
}

func (r *recordingRuleRepo) GetByID(context.Context, int64) (*UserGroup, error) {
	return &UserGroup{ID: 1, TenantID: 100, Name: "扫描组", Code: "sweep", Type: TypeDynamic}, nil
}

func (r *recordingRuleRepo) GetRule(context.Context, int64) (*UserGroupRule, error) {
	return &UserGroupRule{
		ID:      9,
		GroupID: 1,
		Expr:    []byte(`{"op":"and","conditions":[{"field":"email","cmp":"contains","value":"@nobody.invalid"}]}`),
		Status:  RuleEnabled,
	}, nil
}

func (r *recordingRuleRepo) EvaluateRule(context.Context, int64, *CompiledRule) ([]int64, error) {
	return nil, nil
}

func (r *recordingRuleRepo) AllMemberIDs(context.Context, int64) ([]int64, error) { return nil, nil }

func (r *recordingRuleRepo) ListDynamicGroupIDs(context.Context, int64) ([]int64, error) {
	return []int64{1}, nil
}

func (r *recordingRuleRepo) MarkRuleSync(context.Context, int64, int, int, string) error { return nil }
