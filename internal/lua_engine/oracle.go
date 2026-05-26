package lua_engine

import (
	"fmt"
	"time"
)

// Snapshot is the per-response data the oracles compare. Status is the HTTP
// status code; Body is the captured response body (already length-bounded by
// the caller); Latency is the observed wall-clock duration of the request
// (set to 0 when only the boolean oracle is needed).
//
// The struct stays narrow on purpose: every additional field is one more
// thing a probe has to capture in lockstep across baseline / truthy / falsy
// branches.
type Snapshot struct {
	Status  int
	Body    []byte
	Latency time.Duration
}

// SimilarityThreshold is the default Similarity floor above which two
// responses are treated as "the same page" for boolean SQLi inference. The
// 0.97 figure matches the long-standing sqlmap default; raise it for noisier
// targets, lower it when the app's templates rotate per-request CSRF tokens.
const SimilarityThreshold = 0.97

// Similarity returns a 0..1 score: 1 when a and b are identical, 0 when they
// have nothing in common. Two signals combine:
//
//   - length ratio: min(|a|,|b|) / max(|a|,|b|) - weight 0.25
//   - shared-edge ratio: (common-prefix + common-suffix bytes) / max length,
//     capped at min length so prefix and suffix can't double-count - weight 0.75
//
// The prefix/suffix term carries the bulk of the weight so the metric
// works well on templated pages where the differing content sits in the
// middle (the canonical SQLi-boolean shape: identical header + nav,
// different row body, identical footer). Length ratio is kept as a
// minor signal so two same-length but content-different responses
// score below the matching threshold rather than at 0.5.
//
// Empty inputs: Similarity(nil, nil) == 1; Similarity(nil, non-empty) == 0.
func Similarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	la, lb := len(a), len(b)
	mn := la
	mx := lb
	if mn > mx {
		mn, mx = mx, mn
	}
	lenRatio := float64(mn) / float64(mx)

	pre := 0
	for pre < mn && a[pre] == b[pre] {
		pre++
	}
	// Compute suffix independently of prefix and cap the combined edge
	// count at mn afterwards. Computing them separately matters: for
	// identical strings the prefix already covers everything, but the
	// suffix walk still confirms the trailing bytes match, and capping at
	// mn keeps double-counting from inflating the score past 1.
	suf := 0
	for suf < mn && a[la-1-suf] == b[lb-1-suf] {
		suf++
	}
	common := pre + suf
	if common > mn {
		common = mn
	}
	edgeRatio := float64(common) / float64(mx)
	return 0.25*lenRatio + 0.75*edgeRatio
}

// BooleanDecision is the verdict BooleanCompare returns.
type BooleanDecision string

const (
	// BoolVulnerable: truthy ~ baseline AND falsy != baseline. The
	// parameter behaved like a SQL boolean - high-confidence SQLi.
	BoolVulnerable BooleanDecision = "vulnerable"
	// BoolNoSignal: truthy and falsy both behave like baseline (or both
	// behave the same as each other). The parameter is either not
	// reached by the query, or the app is robust to the injection.
	BoolNoSignal BooleanDecision = "no-signal"
	// BoolIndeterminate: truthy and falsy diverge from baseline in ways
	// that don't match the expected pattern (e.g. truthy != baseline
	// but falsy ~ baseline, or both diverge non-symmetrically). Could
	// be SQLi with a different parse shape, or a generic input filter.
	// Caller should not report a finding without further evidence.
	BoolIndeterminate BooleanDecision = "indeterminate"
)

// BooleanResult is BooleanCompare's verdict plus the similarity scores that
// produced it, so a finding can show the reader how close each branch came
// and a noisy target can be debugged without re-running the probe.
type BooleanResult struct {
	Decision  BooleanDecision
	TruthySim float64
	FalsySim  float64
	Detail    string
}

// BooleanCompare reports whether a truthy/falsy snapshot pair is consistent
// with the parameter being SQL-injectable.
//
// Caller is responsible for stripping the canary out of the bodies before
// passing them in: if the probe payloads themselves embed a unique marker,
// every response carrying the echo would automatically diverge from the
// baseline and produce a false positive. The oracle assumes the inputs are
// already comparable.
//
// Decisions use SimilarityThreshold as the cutoff in both directions:
// "looks like baseline" means similarity >= threshold AND same status code;
// "differs from baseline" means similarity < threshold OR different status.
func BooleanCompare(baseline, truthy, falsy Snapshot) BooleanResult {
	truthySim := Similarity(baseline.Body, truthy.Body)
	falsySim := Similarity(baseline.Body, falsy.Body)
	truthyMatches := truthy.Status == baseline.Status && truthySim >= SimilarityThreshold
	falsyMatches := falsy.Status == baseline.Status && falsySim >= SimilarityThreshold

	res := BooleanResult{TruthySim: truthySim, FalsySim: falsySim}
	switch {
	case truthyMatches && !falsyMatches:
		res.Decision = BoolVulnerable
		res.Detail = fmt.Sprintf(
			"truthy probe matched baseline (sim=%.3f, status=%d); falsy probe diverged (sim=%.3f, status=%d)",
			truthySim, truthy.Status, falsySim, falsy.Status)
	case truthyMatches && falsyMatches:
		res.Decision = BoolNoSignal
		res.Detail = fmt.Sprintf(
			"both probes matched baseline (truthy sim=%.3f, falsy sim=%.3f); parameter is inert",
			truthySim, falsySim)
	default:
		res.Decision = BoolIndeterminate
		res.Detail = fmt.Sprintf(
			"asymmetric divergence (truthy sim=%.3f status=%d, falsy sim=%.3f status=%d); not the boolean-SQLi pattern",
			truthySim, truthy.Status, falsySim, falsy.Status)
	}
	return res
}

// TimingResult is TimingCompare's verdict plus the numbers behind it. Margin
// is by how much the probe exceeded the required threshold; a positive
// value confirms the sleep landed.
type TimingResult struct {
	Vulnerable bool
	Threshold  time.Duration
	Margin     time.Duration
	Detail     string
}

// TimingCompare reports whether probe latency rose by enough above baseline
// latency to be consistent with a sleep injection of sleepFor seconds.
//
// margin (0..1) is how much of sleepFor the probe is permitted to "lose" to
// jitter, scheduling, and partial sleeps - pass 0.3 to require at least 70%
// of the requested sleep. margin outside [0,1] is clamped to that range.
// sleepFor must be positive; non-positive returns a Vulnerable=false result
// with a Detail explaining the caller bug.
//
// Single-probe oracles are inherently noisy on the internet. A caller doing
// remote scans should issue the probe at least twice and only treat a
// finding as solid when both attempts cross the threshold.
func TimingCompare(baseline, probe, sleepFor time.Duration, margin float64) TimingResult {
	if sleepFor <= 0 {
		return TimingResult{
			Detail: "sleepFor must be positive; TimingCompare cannot assess",
		}
	}
	if margin < 0 {
		margin = 0
	}
	if margin > 1 {
		margin = 1
	}
	required := time.Duration(float64(sleepFor) * (1 - margin))
	threshold := baseline + required
	res := TimingResult{
		Threshold: threshold,
		Margin:    probe - threshold,
	}
	if probe >= threshold {
		res.Vulnerable = true
		res.Detail = fmt.Sprintf(
			"probe %s exceeded baseline+%s by %s (sleepFor=%s, margin=%.2f)",
			probe, required, res.Margin, sleepFor, margin)
	} else {
		res.Detail = fmt.Sprintf(
			"probe %s did not reach baseline+%s (short by %s; sleepFor=%s, margin=%.2f)",
			probe, required, -res.Margin, sleepFor, margin)
	}
	return res
}
