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

// allowedTableCalls lists .Table() call sites that legitimately carry no tenant
// predicate. Key is "<module-relative-path>:<line>", value is the reason.
var allowedTableCalls = map[string]string{
	// mxid_tenant IS the tenant table — scoping it by tenant_id is circular.
	"app/adapters_user.go:41": "mxid_tenant is the tenant registry itself; it has no tenant_id column",
	// Junction tables with no tenant_id column. Both are keyed by ids that were
	// resolved under the caller's tenant before the lookup runs.
	"app/adapters_oidc.go:91":  "mxid_user_group_member junction has no tenant_id column; scoped by user_id",
	"app/adapters_oidc.go:110": "mxid_role_binding has no tenant_id column; scoped by subject; tenant carried via the joined role",
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
				if !strings.Contains(line, `.Table("`) {
					continue
				}
				lineNo := i + 1
				if _, ok := allowedTableCalls[rel+":"+itoa(lineNo)]; ok {
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
					rel, lineNo, rel+":"+itoa(lineNo))
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
