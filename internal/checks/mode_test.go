package checks

import (
	"context"
	"testing"

	"github.com/londonball/hyperz/internal/httpclient"
)

type fakeCheck struct {
	name string
	mode Mode
}

func (f fakeCheck) Name() string { return f.name }
func (f fakeCheck) Mode() Mode   { return f.mode }
func (fakeCheck) Run(context.Context, *httpclient.Client, string) ([]Finding, error) {
	return nil, nil
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"passive", ModePassive, false},
		{"active", ModeActive, false},
		{"", "", true},
		{"PASSIVE", "", true},
		{"both", "", true},
	}
	for _, tt := range tests {
		got, err := ParseMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseMode(%q) err = nil, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMode(%q) unexpected err: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFilterPassiveKeepsOnlyPassive(t *testing.T) {
	all := []Check{
		fakeCheck{name: "p1", mode: ModePassive},
		fakeCheck{name: "a1", mode: ModeActive},
		fakeCheck{name: "p2", mode: ModePassive},
	}
	got := Filter(all, ModePassive)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	for _, c := range got {
		if c.Mode() != ModePassive {
			t.Errorf("got non-passive check %q in passive filter", c.Name())
		}
	}
}

func TestFilterActiveKeepsAll(t *testing.T) {
	all := []Check{
		fakeCheck{name: "p1", mode: ModePassive},
		fakeCheck{name: "a1", mode: ModeActive},
	}
	got := Filter(all, ModeActive)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
}

func TestSecurityHeadersIsPassive(t *testing.T) {
	if got := (SecurityHeaders{}).Mode(); got != ModePassive {
		t.Fatalf("Mode = %q, want %q", got, ModePassive)
	}
}
