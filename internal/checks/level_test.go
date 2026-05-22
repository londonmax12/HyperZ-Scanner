package checks

import (
	"context"
	"testing"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

type fakeCheck struct {
	name  string
	level Level
}

func (f fakeCheck) Name() string { return f.name }
func (f fakeCheck) Level() Level { return f.level }
func (fakeCheck) Run(context.Context, *httpclient.Client, *scope.Scope, page.Page) ([]Finding, error) {
	return nil, nil
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    Level
		wantErr bool
	}{
		{"passive", LevelPassive, false},
		{"default", LevelDefault, false},
		{"aggressive", LevelAggressive, false},
		{"", 0, true},
		{"PASSIVE", 0, true},
		{"active", 0, true}, // old name removed; must not silently accept it
		{"both", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseLevel(%q) err = nil, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevel(%q) unexpected err: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		in   Level
		want string
	}{
		{LevelPassive, "passive"},
		{LevelDefault, "default"},
		{LevelAggressive, "aggressive"},
		{Level(99), "level(99)"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", int(tt.in), got, tt.want)
		}
	}
}

func TestFilterPassiveKeepsOnlyPassive(t *testing.T) {
	all := []Check{
		fakeCheck{name: "p1", level: LevelPassive},
		fakeCheck{name: "d1", level: LevelDefault},
		fakeCheck{name: "p2", level: LevelPassive},
		fakeCheck{name: "a1", level: LevelAggressive},
	}
	got := Filter(all, LevelPassive)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	for _, c := range got {
		if c.Level() != LevelPassive {
			t.Errorf("got non-passive check %q in passive filter", c.Name())
		}
	}
}

// Filter is documented as "every check at or below the requested level",
// so default includes passive but excludes aggressive.
func TestFilterDefaultIncludesPassive(t *testing.T) {
	all := []Check{
		fakeCheck{name: "p1", level: LevelPassive},
		fakeCheck{name: "d1", level: LevelDefault},
		fakeCheck{name: "a1", level: LevelAggressive},
	}
	got := Filter(all, LevelDefault)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2 (passive + default)", len(got))
	}
	for _, c := range got {
		if c.Level() > LevelDefault {
			t.Errorf("got check %q above LevelDefault in default filter", c.Name())
		}
	}
}

func TestFilterAggressiveKeepsAll(t *testing.T) {
	all := []Check{
		fakeCheck{name: "p1", level: LevelPassive},
		fakeCheck{name: "d1", level: LevelDefault},
		fakeCheck{name: "a1", level: LevelAggressive},
	}
	got := Filter(all, LevelAggressive)
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
}

func TestSecurityHeadersIsPassive(t *testing.T) {
	if got := (SecurityHeaders{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want %v", got, LevelPassive)
	}
}
