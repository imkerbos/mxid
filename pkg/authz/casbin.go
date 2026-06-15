package authz

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

// CasbinModel is the RBAC-with-domains model that backs the role→permission
// decision. We feed it policies and only ask "does role R hold permission P
// in tenant T".
//
// Shape rationale:
//   - request:  sub=role-subject, dom=tenant, obj=permission code.
//   - p policy: a role grants a permission code within a tenant domain.
//   - g grouping: role inheritance within a domain (role -> parent role).
//     This is OPTIONAL — the builtin roles are flat, but the model supports
//     a future role hierarchy without a schema change.
//   - matcher:  permission match is EXACT string equality, with a single
//     widening escape hatch: a p rule whose obj == "*" grants everything in
//     its domain (used to express super_admin without enumerating the
//     catalog). NO keyMatch / glob — we never widen "user.read" into a
//     prefix family.
//
// Subject→role and membership/org-ancestry inheritance is NOT expressed
// here; that edge is resolved by EffectiveBindingsForUser (the Go side),
// which hands us the concrete role subjects to Enforce against. This keeps
// instance-scope (org ltree / group id / kind) checks in Go where the ltree
// lives, while Casbin owns the role→perm catalog decision. See
// CasbinEngine.RoleHasPermission.
const CasbinModel = `
[request_definition]
r = sub, dom, obj

[policy_definition]
p = sub, dom, obj

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && (r.obj == p.obj || p.obj == "*")
`

// roleSubject renders a role's stable Casbin subject id. Roles live in the
// "role" namespace so they can never collide with a tenant/permission token.
func roleSubject(roleID int64) string {
	return "role:" + strconv.FormatInt(roleID, 10)
}

// superAdminRole is the synthetic role granted the domain wildcard. We map
// the is_super_admin flag onto a binding referencing this role so the same
// Enforce path answers both ordinary roles and super admins.
const superAdminRole = "role:super_admin"

// tenantDomain renders the Casbin domain token for a tenant.
func tenantDomain(tenantID int64) string {
	return "t:" + strconv.FormatInt(tenantID, 10)
}

// RolePolicy is one role→permission grant within a tenant. The sync layer
// builds these from mxid_role_permission joined to mxid_permission.
type RolePolicy struct {
	TenantID   int64
	RoleID     int64
	Permission string // permission code, or "*" for a wildcard role
}

// CasbinEngine wraps a Casbin enforcer holding the current role→permission
// catalog. Policies live in memory (the enforcer is the hot path); the
// casbin_rule table is not used as the source of truth — mxid_role* tables
// are. Rebuild on the same events that invalidate the binding cache.
type CasbinEngine struct {
	mu sync.RWMutex
	e  *casbin.SyncedEnforcer

	// adapter persists the active policy set to the existing casbin_rule
	// table so peer pods and restarts share state. nil → pure in-memory
	// (tests, or deployments that don't want the table).
	adapter persist.Adapter
}

// NewCasbinEngine builds an in-memory enforcer from the model with an empty
// policy set. Call ReplacePolicies (or Sync) to load state. Used by tests and
// the differential harness; production wires NewCasbinEngineWithDB.
func NewCasbinEngine() (*CasbinEngine, error) {
	e, err := newSyncedEnforcer()
	if err != nil {
		return nil, err
	}
	return &CasbinEngine{e: e}, nil
}

// NewCasbinEngineWithDB builds the enforcer and attaches a gorm-adapter bound
// to the existing casbin_rule table (migration 000006). ReplacePolicies then
// mirrors the active set into that table. The table is a cache/broadcast of
// the mxid_role* source of truth — Sync always rebuilds it from the DB.
func NewCasbinEngineWithDB(db *gorm.DB) (*CasbinEngine, error) {
	e, err := newSyncedEnforcer()
	if err != nil {
		return nil, err
	}
	adapter, err := gormadapter.NewAdapterByDBUseTableName(db, "", "casbin_rule")
	if err != nil {
		return nil, fmt.Errorf("authz: new casbin gorm adapter: %w", err)
	}
	return &CasbinEngine{e: e, adapter: adapter}, nil
}

func newSyncedEnforcer() (*casbin.SyncedEnforcer, error) {
	m, err := model.NewModelFromString(CasbinModel)
	if err != nil {
		return nil, fmt.Errorf("authz: parse casbin model: %w", err)
	}
	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("authz: new casbin enforcer: %w", err)
	}
	// We rebuild the whole policy set on each Sync and persist explicitly via
	// SavePolicy, so per-mutation auto-save must stay off.
	e.EnableAutoSave(false)
	return e, nil
}

// ReplacePolicies atomically rebuilds the enforcer's policy set from the
// supplied role→permission grants and the set of super-admin tenant domains.
//
// For every (tenant) seen we ensure the super_admin role holds the "*"
// wildcard, and we always add a grouping edge g(role, role, dom) so that the
// matcher's g(r.sub, p.sub, r.dom) reflexively matches a role against its
// own policies (Casbin's g treats a node as related to itself only if such
// an edge exists; we add it explicitly to avoid relying on implicit self).
func (c *CasbinEngine) ReplacePolicies(policies []RolePolicy, superAdminTenants []int64) error {
	m, err := model.NewModelFromString(CasbinModel)
	if err != nil {
		return fmt.Errorf("authz: parse casbin model: %w", err)
	}
	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return fmt.Errorf("authz: new casbin enforcer: %w", err)
	}
	e.EnableAutoSave(false)

	// Track which (role,dom) self-edges we've added.
	selfEdge := map[string]struct{}{}
	addSelf := func(sub, dom string) error {
		k := sub + "\x00" + dom
		if _, ok := selfEdge[k]; ok {
			return nil
		}
		selfEdge[k] = struct{}{}
		if _, err := e.AddNamedGroupingPolicy("g", sub, sub, dom); err != nil {
			return err
		}
		return nil
	}

	for _, p := range policies {
		if p.Permission == "" {
			continue
		}
		dom := tenantDomain(p.TenantID)
		sub := roleSubject(p.RoleID)
		if err := addSelf(sub, dom); err != nil {
			return fmt.Errorf("authz: add role self-edge: %w", err)
		}
		if _, err := e.AddPolicy(sub, dom, p.Permission); err != nil {
			return fmt.Errorf("authz: add casbin policy: %w", err)
		}
	}

	for _, tid := range superAdminTenants {
		dom := tenantDomain(tid)
		if err := addSelf(superAdminRole, dom); err != nil {
			return fmt.Errorf("authz: add super_admin self-edge: %w", err)
		}
		if _, err := e.AddPolicy(superAdminRole, dom, "*"); err != nil {
			return fmt.Errorf("authz: add super_admin policy: %w", err)
		}
	}

	// Persist the rebuilt set to casbin_rule so peers/restarts converge. The
	// adapter is attached to the new enforcer too, but we keep auto-save off
	// and call SavePolicy once for the whole set (one transaction, no churn).
	if c.adapter != nil {
		e.SetAdapter(c.adapter)
		if err := e.SavePolicy(); err != nil {
			return fmt.Errorf("authz: persist casbin policies: %w", err)
		}
	}

	c.mu.Lock()
	c.e = e
	c.mu.Unlock()
	return nil
}

// RoleHasPermission reports whether the given role subject holds perm in the
// tenant domain. Fail-closed: any enforcer error denies.
func (c *CasbinEngine) RoleHasPermission(tenantID int64, roleSub, perm string) bool {
	c.mu.RLock()
	e := c.e
	c.mu.RUnlock()
	if e == nil {
		return false
	}
	ok, err := e.Enforce(roleSub, tenantDomain(tenantID), perm)
	if err != nil {
		return false
	}
	return ok
}

// PolicyLoader yields the full role→permission catalog plus the set of
// tenants that currently have at least one super-admin, so the engine can be
// rebuilt to mirror DB state. Implemented by the cmd/server adapter against
// mxid_role_permission / mxid_permission / mxid_user.
type PolicyLoader interface {
	// LoadPolicies returns every role→permission grant across all tenants and
	// the tenant ids that have a super admin. Errors must NOT be swallowed —
	// the engine refuses to swap in a partial policy set.
	LoadPolicies(ctx context.Context) (policies []RolePolicy, superAdminTenants []int64, err error)
}

// Sync rebuilds the enforcer's policy set from the loader. On loader error
// the existing policy set is left untouched (we never degrade to an empty,
// deny-everything enforcer on a transient DB blip — fail-closed at the Check
// boundary handles genuine outages, while a stale-but-correct policy set is
// safer than wiping grants).
func (c *CasbinEngine) Sync(ctx context.Context, loader PolicyLoader) error {
	policies, superTenants, err := loader.LoadPolicies(ctx)
	if err != nil {
		return fmt.Errorf("authz: load casbin policies: %w", err)
	}
	return c.ReplacePolicies(policies, superTenants)
}
