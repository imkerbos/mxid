package tenantscope_test

// Companion guard to raw_guard_test.go, covering the OTHER way a query escapes
// the tenantscope plugin.
//
// The plugin keys off the MODEL TYPE: it injects `tenant_id = ?` only when the
// destination struct implements TenantScoped(). A query built with
// `db.Table("mxid_user")` scanning into an anonymous or local struct has no such
// type, so the plugin sees nothing to scope and the statement goes out bare —
// no Raw/Exec involved, so raw_guard_test.go does not see it either.
//
// That is exactly how the label resolvers in app/adapters_oidc.go became a
// cross-tenant oracle: any id from anywhere resolved to a name. The bug is
// invisible on a single-tenant deployment, which is why it needs a guard rather
// than a code review.
//
// Unlike the raw guard, this one inspects the STATEMENT rather than a window of
// surrounding lines. A window is fine for Raw/Exec, where the SQL often lives in
// a const above the call, but it is useless here: .Table() counts cluster
// together, so a bare one sitting between two scoped ones would find a
// neighbour's `tenant_id = ?` and pass. Verified — the window version failed to
// flag a predicate deliberately deleted from dashboard.fillCounts.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// tableScannedDirs — the roots where a tenant-scoped .Table() query could live.
// app/ is included because the adapter god file is where the resolvers sit.
var tableScannedDirs = []string{
	"internal/domain",
	"internal/repository",
	"internal/gateway",
	"app",
}

// tableEvidenceTokens are accepted as proof the call is scoped, in addition to
// the raw guard's tenantPredicateTokens. scopeToTenant is the app/ helper that
// appends the predicate when the request carries a tenant.
var tableEvidenceTokens = []string{"scopeToTenant("}

// allowedTableCalls lists .Table() lookups that legitimately carry no tenant
// predicate. Key is "<module-relative-path>:<table>", value is the reason.
//
// Keyed by table rather than by line: a line-numbered allowlist goes stale the
// moment anything above it moves, and the failure mode is worse than a false
// alarm — the stale entry can drift onto a *different* call and exempt it
// silently. (This test caught itself doing exactly that.)
var allowedTableCalls = map[string]string{
	// mxid_tenant IS the tenant registry — scoping it by tenant_id is circular.
	"app/adapters_user.go:mxid_tenant": "the tenant registry itself; it has no tenant_id column",
	// Junction tables with no tenant_id column. Both are keyed by ids that were
	// resolved under the caller's tenant before the lookup runs.
	"app/adapters_oidc.go:mxid_user_group_member": "junction table, no tenant_id column; scoped by user_id",
	"app/adapters_oidc.go:mxid_role_binding":      "no tenant_id column; scoped by subject, tenant carried via the joined role",

	// Tables with no tenant_id column at all. Each is a child or junction row
	// reached through a parent id the caller cannot forge.
	"internal/domain/app/repository_impl.go:mxid_app_group_rel": "junction, no tenant_id; subquery keyed by group_id",
	"internal/domain/approle/repository.go:mxid_app_group_rel":  "junction, no tenant_id; keyed by group_id",
	"app/adapters_portal.go:mxid_app_group_rel":                 "junction, no tenant_id; keyed by group_id",
	"app/run.go:mxid_user_detail":                               "child table, no tenant_id; keyed by the session's own user_id",

	// Has a tenant_id, but is reached only by the authenticated user's own id,
	// which the request cannot choose.
	"app/adapters_conditionalaccess.go:mxid_login_record": "scoped by the session's own user_id",

	// Deliberately cross-tenant: this builds the global Casbin policy set and
	// its whole job is to enumerate which tenants hold a super admin.
	"app/adapters_authz.go:mxid_user": "cross-tenant by design; plucks tenant_id across all tenants for the Casbin domain list",

	// id -> name lookups whose ids come from rows already loaded under the
	// caller's tenant (access requests / eligibilities), so an arbitrary id
	// cannot be injected the way it could through an access-policy row.
	"internal/domain/access/repository.go:mxid_user": "ids come from tenant-scoped access requests, not from the request body",

	// The subtree walk is guarded one layer up: Service.GetMembers calls
	// requireOrg(ctx, orgID) first, and org/child_guard_test.go asserts a
	// cross-tenant orgID returns ErrOrgNotFound before the repo is reached.
	"internal/domain/org/repository_impl.go:mxid_organization": "guarded by Service.GetMembers -> requireOrg; see org/child_guard_test.go",
}

// tableName pulls the literal out of a .Table("name") call.
//
// The leading dot is optional on purpose: gofmt breaks long chains so the call
// lands at the start of a continuation line as `Table("x").`, with the dot left
// on the line above. Requiring the dot made this guard blind to exactly those —
// it reported green while missing an unscoped lookup on mxid_app_group_rel.
var tableName = regexp.MustCompile(`(?:\.|^\s*)Table\("([A-Za-z0-9_]+)"`)

// tableNonLiteral matches a .Table() call whose argument is NOT a string
// literal — `.Table(table)`, `.Table(m.name)`, `.Table(fmt.Sprintf(...))`.
//
// tableName above only sees literals, so a variable table name was invisible to
// this guard: it passed silently, and neither the tenant scoping nor the
// identifier itself was checked. Nothing in the tree does this today, and the
// only near-miss (access.batchNames) takes a table name from its callers, all
// of which pass constants — so this exists to keep it that way rather than to
// fix a live defect.
//
// A dynamic table name is also the one shape where GORM offers no escaping: the
// value is interpolated into the statement as an identifier.
var tableNonLiteral = regexp.MustCompile(`(?:\.|^\s*)Table\(\s*[^")\s]`)

// tableNonLiteralAllowed lists functions that legitimately take a table name as
// a parameter, keyed by "file:identifier-of-the-enclosing-declaration". Each
// entry must state why every caller is safe.
var tableNonLiteralAllowed = map[string]string{
	// batchNames(ctx, table, ids, filterDeleted) resolves display names for a
	// mixed bag of subject tables. Every call site in the package passes a
	// constant ("mxid_role", "mxid_app_role", "mxid_app", "mxid_user_group",
	// "mxid_organization"), so no caller-controlled value reaches it.
	"internal/domain/access/repository.go": "batchNames: all callers pass string constants",
}

// maxStatementLines bounds the forward walk that reassembles a chained
// statement, so a malformed file cannot make the guard run away.
const maxStatementLines = 20

func TestNoUnscopedTableQueries(t *testing.T) {
	root := moduleRootTS(t)

	for _, d := range tableScannedDirs {
		dir := filepath.Join(root, d)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)

			lines, readErr := readLines(path)
			if readErr != nil {
				return readErr
			}
			for i, line := range lines {
				// A non-literal table name is checked first: tableName cannot
				// see it, so without this the call would pass unexamined.
				if tableNonLiteral.MatchString(line) {
					if _, ok := tableNonLiteralAllowed[rel]; !ok {
						t.Errorf("%s:%d: .Table() called with a non-literal table name:\n\t%s\n"+
							"A dynamic table name is interpolated as an identifier with no escaping, and this "+
							"guard cannot verify its tenant scoping. Use a string literal, or add an entry to "+
							"tableNonLiteralAllowed stating why every caller is safe.", rel, i+1, strings.TrimSpace(line))
					}
					continue
				}
				m := tableName.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				lineNo := i + 1
				if _, ok := allowedTableCalls[rel+":"+m[1]]; ok {
					continue
				}
				if statementHasEvidence(lines, i) {
					continue
				}
				t.Errorf("%s:%d builds a .Table() query with no tenant predicate. "+
					".Table() scanning into an anonymous struct is invisible to the tenantscope plugin "+
					"(the plugin keys off the model type), so the statement runs unscoped across tenants. "+
					"Add an explicit `tenant_id = ?` clause, or if the table has no tenant column add "+
					"%q to allowedTableCalls in table_guard_test.go with a justification.",
					rel, lineNo, rel+":"+m[1])
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", dir, walkErr)
		}
	}
}

// statementHasEvidence reassembles the chained statement beginning at the
// .Table() line and looks for a tenant predicate in THAT text only.
//
// Reassembly relies on gofmt: in a formatted method chain every continued line
// ends with an open delimiter or a dot, and the final line of the statement does
// not. That is enough to find the end without parsing Go.
func statementHasEvidence(lines []string, idx int) bool {
	var b strings.Builder
	for j := idx; j < len(lines) && j < idx+maxStatementLines; j++ {
		b.WriteString(lines[j])
		b.WriteByte('\n')
		if !continuesStatement(lines[j]) {
			break
		}
	}
	stmt := b.String()
	return containsAny(stmt, tenantPredicateTokens) || containsAny(stmt, tableEvidenceTokens)
}

// continuesStatement reports whether a gofmt-ed line is mid-expression, i.e. the
// next line belongs to the same statement.
func continuesStatement(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") {
		return true
	}
	switch trimmed[len(trimmed)-1] {
	case '.', ',', '(', '+':
		return true
	}
	return false
}
