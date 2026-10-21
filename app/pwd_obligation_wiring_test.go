package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The forced-password-change obligation is decided in two places: the session
// decider marks a session at login, and the gate's MustChange callback
// re-checks on every request and clears the mark once the debt is settled.
// They must give the same answer.
//
// They did not. The decider learned about password expiry and the gate's half
// did not, so an expired password marked the session and the very next request
// un-marked it — the user sailed past a gate that believed nothing was owed.
// Both unit tests and a reading of either half looked fine; only driving a real
// login showed it.
//
// Both now call pwdChangeOwed. This asserts the source says so, because a
// behavioural test of one half cannot see that the other drifted.
func TestPwdObligation_BothHalvesShareOneAnswer(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatalf("parse run.go: %v", err)
	}

	// Find the two call sites by the function they are passed to, then assert
	// each one's body mentions pwdChangeOwed.
	checked := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
				sel.Sel.Name == "SetPwdChangeDecider" && len(call.Args) == 1 {
				checked["decider"] = callsHelper(fset, call.Args[0])
			}
		}
		// The gate is built as authn.PwdGateDeps{..., MustChange: func(...)}.
		if lit, ok := n.(*ast.CompositeLit); ok {
			if sel, ok := lit.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "PwdGateDeps" {
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "MustChange" {
						checked["gate"] = callsHelper(fset, kv.Value)
					}
				}
			}
		}
		return true
	})

	for _, half := range []string{"decider", "gate"} {
		got, present := checked[half]
		if !present {
			t.Fatalf("could not find the %s half in run.go — did the wiring move?", half)
		}
		if !got {
			t.Errorf("the %s half does not call pwdChangeOwed: the two halves of the password obligation can disagree again, and the symptom is a gate that marks a session and then immediately clears the mark", half)
		}
	}
}

// callsHelper reports whether the expression's source text mentions the shared
// helper. Rendering the node back to source is enough here and keeps the test
// from caring how the call is nested.
func callsHelper(fset *token.FileSet, n ast.Node) bool {
	var sb strings.Builder
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok {
			sb.WriteString(id.Name)
			sb.WriteString(" ")
		}
		return true
	})
	return strings.Contains(sb.String(), "pwdChangeOwed")
}
