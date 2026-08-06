package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every event named in the schema allow-list must actually be subscribed to.
//
// schema.go declaring an event says "when this happens, record these fields".
// It is not what makes the recording happen — RegisterHandlers is. The two
// drifted for the whole user-group domain: group.created, group.updated,
// group.deleted, group.member_added and group.member_removed each had an
// allow-list, the domain published all five, and nothing subscribed. The writes
// still reached the audit log, but only as the api.* catch-all rows, which the
// audit page hides by default. An operator asking "who added this person to the
// admins group" — the question group membership exists to answer, because it
// grants application access — found an empty page.
//
// Nothing failed. That is the point of this test: a missing subscription has no
// symptom at build time, no symptom at run time, and no symptom in the audit UI
// beyond an absence nobody can distinguish from "it never happened".
func TestEverySchemaEventIsSubscribed(t *testing.T) {
	subscribed := parseSubscribedEvents(t, "service.go")
	declared := parseSchemaEvents(t, "schema.go")

	var missing []string
	for _, ev := range declared {
		if !subscribed[ev] {
			missing = append(missing, ev)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("schema.go declares an audit allow-list for these events, but "+
			"RegisterHandlers never subscribes to them — they are published and "+
			"silently dropped, leaving only the hidden api.* catch-all row:\n  %s\n\n"+
			"Add s.eventBus.Subscribe(event.X, …) in RegisterHandlers, or remove "+
			"the schema entry if the event is genuinely not audited.",
			strings.Join(missing, "\n  "))
	}
}

// parseSubscribedEvents collects the event.X selectors passed as the first
// argument to s.eventBus.Subscribe.
func parseSubscribedEvents(t *testing.T, file string) map[string]bool {
	t.Helper()
	f := parseFile(t, file)
	found := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Subscribe" {
			return true
		}
		if name := eventConstName(call.Args[0]); name != "" {
			found[name] = true
		}
		return true
	})
	if len(found) == 0 {
		t.Fatal("parsed no Subscribe calls from service.go — the test's parser is " +
			"broken, which would make it pass against anything")
	}
	return found
}

// parseSchemaEvents collects the event.X selectors used as map keys in schema.go.
func parseSchemaEvents(t *testing.T, file string) []string {
	t.Helper()
	f := parseFile(t, file)
	var events []string
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if name := eventConstName(kv.Key); name != "" {
			events = append(events, name)
		}
		return true
	})
	if len(events) == 0 {
		t.Fatal("parsed no event keys from schema.go — the test's parser is broken")
	}
	return events
}

// eventConstName returns "X" for an expression of the form event.X.
func eventConstName(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "event" {
		return ""
	}
	return sel.Sel.Name
}

func parseFile(t *testing.T, name string) *ast.File {
	t.Helper()
	path := filepath.Join(".", name)
	src, err := os.ReadFile(path) //nolint:gosec // reading our own package
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}
