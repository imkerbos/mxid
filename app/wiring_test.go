package app

// package app is the composition root: it has no logic of its own, so it has no
// tests of its own, so a field left out of an adapter literal compiles fine and
// nil-derefs on the first request that reaches it. exhaustruct exists to catch
// exactly that — but only for the types listed in .golangci.yml, and that list
// is hand-maintained.
//
// This test closes the loop: it parses the package, finds every struct that
// looks like dependency wiring, and fails when one is not covered. Otherwise the
// list quietly falls behind the package and the linter reports success over a
// shrinking fraction of it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// notWiring lists struct types in this package that are deliberately outside
// the exhaustruct list, with the reason. Everything else must be covered.
var notWiring = map[string]string{
	// GORM scan targets. Never built from a composite literal (declared as
	// `var row nameCodeRow` and filled by Scan), so exhaustruct never fires and
	// listing them would only imply a guarantee that is not there.
	"nameCodeRow": "gorm scan target, never composite-literal constructed",
	"userNameRow": "gorm scan target, never composite-literal constructed",
}

func TestExhaustructCoversEveryWiringStruct(t *testing.T) {
	root := moduleRoot(t)
	covered := exhaustructTypes(t, filepath.Join(root, ".golangci.yml"))

	for path, file := range parseAppFiles(t, root) {
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			name := ts.Name.Name
			if _, exempt := notWiring[name]; exempt {
				if covered[name] {
					t.Errorf("%s is listed in .golangci.yml exhaustruct AND in notWiring — "+
						"pick one", name)
				}
				return true
			}
			if !isWiringStruct(st) {
				return true
			}
			if !covered[name] {
				t.Errorf("%s (%s) is a dependency-wiring struct but is not in the "+
					"exhaustruct include list in .golangci.yml. Leaving a field out of its "+
					"literal would compile and nil-deref at runtime, and package app has no "+
					"test that would catch it. Add "+
					"'github.com/imkerbos/mxid/app\\.%s$' to that list, or add %s to "+
					"notWiring in this file with a reason.",
					name, filepath.Base(path), name, name)
			}
			return true
		})
	}
}

// Stale entries are the other failure direction: a renamed or deleted adapter
// leaves a pattern that silently matches nothing, and the list looks healthier
// than it is.
func TestExhaustructListHasNoStaleEntries(t *testing.T) {
	root := moduleRoot(t)
	covered := exhaustructTypes(t, filepath.Join(root, ".golangci.yml"))

	declared := map[string]bool{}
	for _, file := range parseAppFiles(t, root) {
		ast.Inspect(file, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok {
				if _, isStruct := ts.Type.(*ast.StructType); isStruct {
					declared[ts.Name.Name] = true
				}
			}
			return true
		})
	}

	for name := range covered {
		if !declared[name] {
			t.Errorf("the exhaustruct include list names app.%s, which no longer exists. "+
				"The pattern matches nothing, so it enforces nothing — remove it.", name)
		}
	}
}

// parseAppFiles parses the non-test sources of package app, keyed by path.
// parser.ParseDir would be the obvious call but it is deprecated and ignores
// build tags; globbing and parsing each file is both current and sufficient
// here, since package app is a single directory with no tagged variants.
func parseAppFiles(t *testing.T, root string) map[string]*ast.File {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "app", "*.go"))
	if err != nil {
		t.Fatalf("glob app: %v", err)
	}
	fset := token.NewFileSet()
	out := make(map[string]*ast.File, len(paths))
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		out[p] = f
	}
	if len(out) == 0 {
		t.Fatal("parsed no files in package app — the guard is checking nothing")
	}
	return out
}

// isWiringStruct reports whether every field is a dependency handle: a pointer,
// an interface-ish named type, a func, a map or a slice. A struct carrying plain
// scalars is data (a payload, a scan row), and a zero value there is a legitimate
// state rather than a missing wire.
//
// scimDeprovisionPayload is the deliberate exception: it is scalar data, but
// every field is required, and omitting one produces a deprovision request the
// downstream connector cannot match to an account. It is listed explicitly in
// .golangci.yml rather than detected here.
func isWiringStruct(st *ast.StructType) bool {
	if st.Fields == nil || len(st.Fields.List) == 0 {
		return false
	}
	for _, f := range st.Fields.List {
		switch t := f.Type.(type) {
		case *ast.StarExpr, *ast.FuncType, *ast.MapType, *ast.ChanType:
			continue
		case *ast.SelectorExpr, *ast.Ident:
			// A named type with no pointer: an interface (outbox.Repository,
			// httpDoer) or a small value type. Treat a lower-case local name or
			// a qualified name as a dependency; a builtin scalar is data.
			if isScalar(t) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isScalar(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	if !ok {
		return false // qualified type (pkg.Type) — treat as a dependency
	}
	switch id.Name {
	case "string", "bool", "byte", "rune", "error",
		"int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64",
		"float32", "float64", "any":
		return true
	}
	return false
}

// exhaustructTypes reads the bare type names out of the include patterns.
var includePattern = regexp.MustCompile(`github\.com/imkerbos/mxid/app\\\.([A-Za-z0-9_]+)\$`)

func exhaustructTypes(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	out := map[string]bool{}
	for _, m := range includePattern.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("parsed no exhaustruct include patterns — the config format changed and " +
			"this guard is no longer checking anything")
	}
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod from %s", dir)
		}
		dir = parent
	}
}
