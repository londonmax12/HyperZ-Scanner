package main

import (
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
)

func TestParseFailOnSeverityNames(t *testing.T) {
	cases := []struct {
		in        string
		wantRank  int
		wantOn    bool
		wantError bool
	}{
		{"info", checks.SeverityRank(checks.SeverityInfo), true, false},
		{"low", checks.SeverityRank(checks.SeverityLow), true, false},
		{"medium", checks.SeverityRank(checks.SeverityMedium), true, false},
		{"high", checks.SeverityRank(checks.SeverityHigh), true, false},
		{"critical", checks.SeverityRank(checks.SeverityCritical), true, false},
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
