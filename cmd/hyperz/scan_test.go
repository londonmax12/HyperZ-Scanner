package main

import (
	"testing"

	"github.com/londonmax12/hyperz/internal/core"
)

func TestParseFailOnSeverityNames(t *testing.T) {
	cases := []struct {
		in        string
		wantRank  int
		wantOn    bool
		wantError bool
	}{
		{"info", core.SeverityRank(core.SeverityInfo), true, false},
		{"low", core.SeverityRank(core.SeverityLow), true, false},
		{"medium", core.SeverityRank(core.SeverityMedium), true, false},
		{"high", core.SeverityRank(core.SeverityHigh), true, false},
		{"critical", core.SeverityRank(core.SeverityCritical), true, false},
		{"NONE", 0, false, false},
		{"none", 0, false, false},
		{"warning", 0, false, true},
		{"", 0, false, true},
	}
	for _, tc := range cases {
		rank, on, err := parseFailOn(tc.in)
		if tc.wantError {
			if err == nil {
				t.Errorf("parseFailOn(%q) err = nil, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseFailOn(%q) unexpected err: %v", tc.in, err)
			continue
		}
		if on != tc.wantOn {
			t.Errorf("parseFailOn(%q) enabled = %v, want %v", tc.in, on, tc.wantOn)
		}
		if rank != tc.wantRank {
			t.Errorf("parseFailOn(%q) rank = %d, want %d", tc.in, rank, tc.wantRank)
		}
	}
}
