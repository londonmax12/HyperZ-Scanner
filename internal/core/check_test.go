package core

import (
	"context"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

type stubCheck struct {
	name  string
	level Level
}

func (s stubCheck) Name() string  { return s.name }
func (s stubCheck) Level() Level  { return s.level }
func (s stubCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, _ page.Page) ([]Finding, error) {
	return nil, nil
}

func TestFilterByNameAllowAndDeny(t *testing.T) {
	all := []Check{
		stubCheck{name: "reflected-xss", level: LevelDefault},
		stubCheck{name: "stored-xss", level: LevelDefault},
		stubCheck{name: "sqli-time", level: LevelAggressive},
		stubCheck{name: "sqli-boolean", level: LevelAggressive},
		stubCheck{name: "request-smuggling", level: LevelAggressive},
		stubCheck{name: "cmd-injection-blind", level: LevelAggressive},
	}

	cases := []struct {
		name    string
		enable  []string
		disable []string
		want    []string
	}{
		{
			name:    "empty allow leaves all in",
			disable: []string{"request-smuggling"},
			want:    []string{"reflected-xss", "stored-xss", "sqli-time", "sqli-boolean", "cmd-injection-blind"},
		},
		{
			name:   "glob enable narrows",
			enable: []string{"sqli-*"},
			want:   []string{"sqli-time", "sqli-boolean"},
		},
		{
			name:    "glob disable subtracts",
			disable: []string{"*-blind"},
			want:    []string{"reflected-xss", "stored-xss", "sqli-time", "sqli-boolean", "request-smuggling"},
		},
		{
			name:    "literal name disable",
			disable: []string{"reflected-xss"},
			want:    []string{"stored-xss", "sqli-time", "sqli-boolean", "request-smuggling", "cmd-injection-blind"},
		},
		{
			name:    "enable then disable",
			enable:  []string{"*xss"},
			disable: []string{"stored-*"},
			want:    []string{"reflected-xss"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, unmatched := FilterByName(all, tc.enable, tc.disable)
			gotNames := make([]string, 0, len(kept))
			for _, c := range kept {
				gotNames = append(gotNames, c.Name())
			}
			sort.Strings(gotNames)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if len(gotNames) != len(want) {
				t.Fatalf("kept = %v, want %v", gotNames, want)
			}
			for i := range gotNames {
				if gotNames[i] != want[i] {
					t.Errorf("kept[%d] = %q, want %q", i, gotNames[i], want[i])
				}
			}
			if len(unmatched) != 0 {
				t.Errorf("unmatched = %v, want none for known patterns", unmatched)
			}
		})
	}
}

func TestFilterByNameUnmatched(t *testing.T) {
	all := []Check{
		stubCheck{name: "reflected-xss", level: LevelDefault},
	}
	_, unmatched := FilterByName(all, []string{"does-not-exist"}, []string{"also-missing"})
	got := map[string]bool{}
	for _, p := range unmatched {
		got[p] = true
	}
	if !got["does-not-exist"] || !got["also-missing"] {
		t.Errorf("unmatched = %v, want both patterns reported", unmatched)
	}
}

// TestFilterByNameDisableEvaluatedIndependentOfEnable guards against
// the original implementation, where a disable pattern matched only
// when a check survived the enable filter long enough to reach the
// disable check. With a narrow --enable list, a disable typo would
// have flagged a perfectly-valid pattern as "no match".
func TestFilterByNameDisableEvaluatedIndependentOfEnable(t *testing.T) {
	all := []Check{
		stubCheck{name: "reflected-xss"},
		stubCheck{name: "stored-xss"},
		stubCheck{name: "request-smuggling"},
	}
	_, unmatched := FilterByName(all,
		[]string{"reflected-xss"},
		[]string{"request-smuggling"})
	for _, p := range unmatched {
		if p == "request-smuggling" {
			t.Errorf("disable pattern %q should match against full catalog, not just enable-filtered set", p)
		}
	}
}
