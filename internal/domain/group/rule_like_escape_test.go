package group

import (
	"strings"
	"testing"
)

// A wildcard typed into a rule value must be matched literally.
//
// This is not a search-quality question. Dynamic-group membership grants
// application access, so a rule value containing `%` widens the match set and
// enrols people the rule was written to exclude. `_` is the more dangerous of
// the two because it reads as an ordinary character in a username or a
// department code — "dept_eng" looks exact and matches "deptXeng" too.
func TestCompileEscapesLikeWildcardsInRuleValues(t *testing.T) {
	for _, cmp := range []string{"contains", "startswith", "endswith"} {
		t.Run(cmp, func(t *testing.T) {
			compiled, err := Compile(&RuleExpr{
				Op:         "and",
				Conditions: []RuleCondition{{Field: "email", Cmp: cmp, Value: "a%b_c"}},
			})
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if !strings.Contains(compiled.WhereSQL, `ESCAPE '\'`) {
				t.Errorf("SQL has no ESCAPE clause, so the escapes in the argument "+
					"are not interpreted: %s", compiled.WhereSQL)
			}
			arg, ok := compiled.Args[0].(string)
			if !ok {
				t.Fatalf("arg 0 is %T, want string", compiled.Args[0])
			}
			if !strings.Contains(arg, `a\%b\_c`) {
				t.Errorf("arg = %q — the user's %% and _ must be escaped so they "+
					"match literally and cannot widen the group", arg)
			}
		})
	}
}

func TestCompileKeepsTheCallersOwnWildcards(t *testing.T) {
	// `contains` means the caller wraps the value in its own wildcards; escaping
	// must not neuter those or the comparison stops being a substring match.
	compiled, err := Compile(&RuleExpr{
		Op:         "and",
		Conditions: []RuleCondition{{Field: "email", Cmp: "contains", Value: "mxid"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := compiled.Args[0].(string); got != "%mxid%" {
		t.Fatalf("arg = %q, want %q", got, "%mxid%")
	}
}

func TestCompileExactComparisonsNeedNoEscape(t *testing.T) {
	// eq/ne do not use LIKE, so a % in the value is already literal there and
	// must be passed through untouched.
	compiled, err := Compile(&RuleExpr{
		Op:         "and",
		Conditions: []RuleCondition{{Field: "email", Cmp: "eq", Value: "100%@mxid.io"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := compiled.Args[0]; got != "100%@mxid.io" {
		t.Fatalf("arg = %v, want the value unchanged", got)
	}
}
