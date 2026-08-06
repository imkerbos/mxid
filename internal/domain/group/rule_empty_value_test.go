package group

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// An empty comparison value must be refused.
//
// `email contains ""` is true for every user who has an email at all, so a rule
// left blank does not fail — it succeeds, reports a normal sync, and produces a
// group containing nearly everyone. Group membership grants app access, so the
// blank box is an over-grant that announces itself as success. On a live tenant
// this enrolled 13 of 14 users.
func TestValidateRuleRejectsEmptyStringValue(t *testing.T) {
	for _, cmp := range []string{"eq", "ne", "contains", "startswith", "endswith"} {
		t.Run(cmp, func(t *testing.T) {
			raw := mustJSON(t, map[string]any{
				"op": "and",
				"conditions": []any{
					map[string]any{"field": "email", "cmp": cmp, "value": ""},
				},
			})
			_, err := ValidateRule(raw)
			if err == nil {
				t.Fatalf("ValidateRule accepted an empty value for %q — a blank box "+
					"silently matches nearly every user", cmp)
			}
			if !errors.Is(err, ErrRuleInvalidValue) {
				t.Fatalf("error does not wrap ErrRuleInvalidValue: %v", err)
			}
			if !strings.Contains(err.Error(), "empty") {
				t.Errorf("message should say the value is empty, got: %v", err)
			}
		})
	}
}

func TestValidateRuleRejectsWhitespaceOnlyValue(t *testing.T) {
	raw := mustJSON(t, map[string]any{
		"op": "and",
		"conditions": []any{
			map[string]any{"field": "email", "cmp": "contains", "value": "   "},
		},
	})
	if _, err := ValidateRule(raw); err == nil {
		t.Fatal("ValidateRule accepted a whitespace-only value — it matches the " +
			"same set as an empty one for every practical purpose")
	}
}

func TestValidateRuleStillAcceptsRealValues(t *testing.T) {
	raw := mustJSON(t, map[string]any{
		"op": "and",
		"conditions": []any{
			map[string]any{"field": "email", "cmp": "contains", "value": "@mxid.io"},
			map[string]any{"field": "status", "cmp": "eq", "value": 1},
		},
	})
	expr, err := ValidateRule(raw)
	if err != nil {
		t.Fatalf("ValidateRule rejected a valid rule: %v", err)
	}
	if len(expr.Conditions) != 2 {
		t.Fatalf("conditions = %d, want 2", len(expr.Conditions))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
