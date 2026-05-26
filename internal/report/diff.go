package report

import (
	"sort"

	"github.com/londonmax12/hyperz/internal/core"
)

// Tap forwards findings from in to a new channel, invoking observe on each
// finding before forwarding. It exists so the scan command can sample
// findings (e.g. to compute the worst severity for the --fail-on gate)
// without inserting a goroutine-based aggregator at every call site.
// observe must not block - it runs inline with the forwarding loop.
func Tap(in <-chan core.Finding, observe func(core.Finding)) <-chan core.Finding {
	out := make(chan core.Finding, cap(in))
	go func() {
		defer close(out)
		for f := range in {
			if observe != nil {
				observe(f)
			}
			out <- f
		}
	}()
	return out
}

// Diff status values written to Finding.DiffStatus. Kept as plain strings so
// the JSON/CSV/SARIF wire forms stay human-readable.
const (
	DiffStatusNew        = "new"
	DiffStatusPersisting = "persisting"
	DiffStatusResolved   = "resolved"
)

// DiffCounts is the per-status tally a diff overlay produces. Populated as
// findings flow through Diff; readable only after the overlay output channel
// has closed.
type DiffCounts struct {
	New        int `json:"new"`
	Persisting int `json:"persisting"`
	Resolved   int `json:"resolved"`
}

// Total returns the sum across all three buckets.
func (c DiffCounts) Total() int { return c.New + c.Persisting + c.Resolved }

// Diff annotates each finding from in with a DiffStatus relative to
// baseline, then emits resolved findings (baseline entries the current scan
// didn't reproduce) once in closes. counts is populated as findings flow
// through and is safe to read after the returned channel closes.
//
// Findings without a DedupeKey always get DiffStatusNew - they can't be
// reliably matched against a baseline. Baseline entries without a key are
// stored in Baseline.NoKey and never emit as "resolved" for the same reason.
//
// Callers that need to know the diff counters during scan reporting should
// pass in a freshly allocated *DiffCounts so the scan command can read it
// after the reporter completes.
func Diff(in <-chan core.Finding, baseline *Baseline, counts *DiffCounts) <-chan core.Finding {
	out := make(chan core.Finding, cap(in))
	if counts == nil {
		counts = &DiffCounts{}
	}
	go func() {
		defer close(out)
		// remaining starts as a copy of baseline keys; each match removes
		// from it so what's left at the end is the resolved set.
		var remaining map[string]core.Finding
		if baseline != nil {
			remaining = make(map[string]core.Finding, len(baseline.Keys))
			for k, v := range baseline.Keys {
				remaining[k] = v
			}
		}
		for f := range in {
			if f.DedupeKey != "" {
				if _, ok := remaining[f.DedupeKey]; ok {
					delete(remaining, f.DedupeKey)
					f.DiffStatus = DiffStatusPersisting
					counts.Persisting++
				} else {
					f.DiffStatus = DiffStatusNew
					counts.New++
				}
			} else {
				f.DiffStatus = DiffStatusNew
				counts.New++
			}
			out <- f
		}
		// Emit one synthetic finding per baseline entry that wasn't matched
		// in this run. Sort by key for stable test output and so report
		// readers see resolved entries in a consistent order.
		keys := make([]string, 0, len(remaining))
		for k := range remaining {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f := remaining[k]
			f.DiffStatus = DiffStatusResolved
			counts.Resolved++
			out <- f
		}
	}()
	return out
}

