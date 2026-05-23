package checks

import (
	"strings"
	"testing"
	"time"
)

func TestSimilarityIdentical(t *testing.T) {
	if got := Similarity([]byte("hello world"), []byte("hello world")); got != 1 {
		t.Errorf("Similarity(identical) = %f, want 1", got)
	}
}

func TestSimilarityEmptyBoth(t *testing.T) {
	if got := Similarity(nil, nil); got != 1 {
		t.Errorf("Similarity(nil,nil) = %f, want 1", got)
	}
}

func TestSimilarityOneEmpty(t *testing.T) {
	if got := Similarity(nil, []byte("x")); got != 0 {
		t.Errorf("Similarity(nil,'x') = %f, want 0", got)
	}
	if got := Similarity([]byte("x"), nil); got != 0 {
		t.Errorf("Similarity('x',nil) = %f, want 0", got)
	}
}

func TestSimilarityCompletelyDifferent(t *testing.T) {
	if got := Similarity([]byte("aaaa"), []byte("bbbb")); got > 0.5 {
		t.Errorf("Similarity(differ) = %f, want < 0.5", got)
	}
}

func TestSimilarityTemplateShape(t *testing.T) {
	// Two pages that share a long header and footer but differ in the
	// middle - the canonical boolean-SQLi shape. Similarity should be
	// high but not 1.
	pre := strings.Repeat("HEADER ", 50)
	post := strings.Repeat(" FOOTER", 50)
	a := []byte(pre + "row=Alice" + post)
	b := []byte(pre + "row=Bob" + post)
	got := Similarity(a, b)
	if got <= 0.9 {
		t.Errorf("Similarity(template-with-row-diff) = %f, want > 0.9", got)
	}
	if got >= 1.0 {
		t.Errorf("Similarity(template-with-row-diff) = %f, want < 1 (not identical)", got)
	}
}

func TestBooleanCompareVulnerable(t *testing.T) {
	baseline := Snapshot{Status: 200, Body: []byte("<p>welcome user 1</p>")}
	truthy := Snapshot{Status: 200, Body: []byte("<p>welcome user 1</p>")} // identical to baseline
	falsy := Snapshot{Status: 200, Body: []byte("<p>no such user</p>")}
	got := BooleanCompare(baseline, truthy, falsy)
	if got.Decision != BoolVulnerable {
		t.Fatalf("Decision = %q, want %q (detail=%q)", got.Decision, BoolVulnerable, got.Detail)
	}
	if got.TruthySim < got.FalsySim {
		t.Errorf("Truthy should be more similar than Falsy: %f vs %f", got.TruthySim, got.FalsySim)
	}
}

func TestBooleanCompareNoSignal(t *testing.T) {
	// Both probes look identical to baseline - the parameter is inert.
	baseline := Snapshot{Status: 200, Body: []byte("<p>welcome</p>")}
	truthy := Snapshot{Status: 200, Body: []byte("<p>welcome</p>")}
	falsy := Snapshot{Status: 200, Body: []byte("<p>welcome</p>")}
	got := BooleanCompare(baseline, truthy, falsy)
	if got.Decision != BoolNoSignal {
		t.Errorf("Decision = %q, want %q", got.Decision, BoolNoSignal)
	}
}

func TestBooleanCompareIndeterminate(t *testing.T) {
	// Truthy differs from baseline; falsy matches it. That's the inverse
	// of the SQLi pattern - probably input filtering, not injection.
	baseline := Snapshot{Status: 200, Body: []byte("<p>welcome</p>")}
	truthy := Snapshot{Status: 500, Body: []byte("server error")}
	falsy := Snapshot{Status: 200, Body: []byte("<p>welcome</p>")}
	got := BooleanCompare(baseline, truthy, falsy)
	if got.Decision != BoolIndeterminate {
		t.Errorf("Decision = %q, want %q", got.Decision, BoolIndeterminate)
	}
}

func TestBooleanCompareStatusDivergence(t *testing.T) {
	// Bodies are similar but statuses differ - status mismatch alone
	// should classify as "differs from baseline."
	baseline := Snapshot{Status: 200, Body: []byte("welcome")}
	truthy := Snapshot{Status: 200, Body: []byte("welcome")}
	falsy := Snapshot{Status: 500, Body: []byte("welcome")} // same body, different status
	got := BooleanCompare(baseline, truthy, falsy)
	if got.Decision != BoolVulnerable {
		t.Errorf("Decision = %q, want %q (status-only divergence on falsy)", got.Decision, BoolVulnerable)
	}
}

func TestBooleanCompareDetailNonEmpty(t *testing.T) {
	// Every verdict must carry a rationale - findings render Detail and
	// an empty string is useless to the reader.
	cases := []struct {
		name                       string
		baseline, truthy, falsy    Snapshot
		want                       BooleanDecision
	}{
		{"vulnerable",
			Snapshot{Status: 200, Body: []byte("a")},
			Snapshot{Status: 200, Body: []byte("a")},
			Snapshot{Status: 500, Body: []byte("b")},
			BoolVulnerable},
		{"no-signal",
			Snapshot{Status: 200, Body: []byte("a")},
			Snapshot{Status: 200, Body: []byte("a")},
			Snapshot{Status: 200, Body: []byte("a")},
			BoolNoSignal},
		{"indeterminate",
			Snapshot{Status: 200, Body: []byte("a")},
			Snapshot{Status: 500, Body: []byte("b")},
			Snapshot{Status: 200, Body: []byte("a")},
			BoolIndeterminate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BooleanCompare(tc.baseline, tc.truthy, tc.falsy)
			if got.Decision != tc.want {
				t.Errorf("Decision = %q, want %q", got.Decision, tc.want)
			}
			if got.Detail == "" {
				t.Errorf("empty Detail for %q", tc.want)
			}
		})
	}
}

func TestTimingCompareCrossesThreshold(t *testing.T) {
	// Baseline ~50ms, sleepFor 2s, probe took 1.9s - well past 70% of 2s.
	got := TimingCompare(50*time.Millisecond, 1900*time.Millisecond, 2*time.Second, 0.3)
	if !got.Vulnerable {
		t.Errorf("Vulnerable = false; want true. detail=%q", got.Detail)
	}
	if got.Margin <= 0 {
		t.Errorf("Margin = %v, want positive", got.Margin)
	}
}

func TestTimingCompareBelowThreshold(t *testing.T) {
	// Probe only slightly slower than baseline; nowhere near 70% of 2s.
	got := TimingCompare(50*time.Millisecond, 150*time.Millisecond, 2*time.Second, 0.3)
	if got.Vulnerable {
		t.Errorf("Vulnerable = true; want false")
	}
	if got.Margin >= 0 {
		t.Errorf("Margin = %v, want negative (short of threshold)", got.Margin)
	}
}

func TestTimingCompareMarginClamping(t *testing.T) {
	// margin > 1 must clamp to 1, making the threshold = baseline. Any
	// probe at or above baseline then counts as vulnerable.
	got := TimingCompare(100*time.Millisecond, 100*time.Millisecond, 2*time.Second, 5.0)
	if !got.Vulnerable {
		t.Errorf("margin>1 should clamp; probe==baseline must be vulnerable. detail=%q", got.Detail)
	}
}

func TestTimingCompareInvalidSleep(t *testing.T) {
	got := TimingCompare(0, time.Second, 0, 0.3)
	if got.Vulnerable {
		t.Errorf("Vulnerable = true on sleepFor<=0; want false")
	}
	if got.Detail == "" {
		t.Errorf("expected Detail explaining the bad input")
	}
}

func TestTimingCompareDetailNonEmpty(t *testing.T) {
	// Both branches (above/below threshold) must produce a rationale.
	below := TimingCompare(50*time.Millisecond, 60*time.Millisecond, 2*time.Second, 0.3)
	if below.Detail == "" {
		t.Errorf("below-threshold result missing Detail")
	}
	above := TimingCompare(50*time.Millisecond, 5*time.Second, 2*time.Second, 0.3)
	if above.Detail == "" {
		t.Errorf("above-threshold result missing Detail")
	}
}
