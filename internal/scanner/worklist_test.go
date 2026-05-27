package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// drainPending pops up to want targets at any tier, completing each
// via Done so quiescence semantics still work for callers that pushed
// and immediately want to inspect what landed. Stops when a Pop would
// block (no items + not yet drained).
func drainPending(t *testing.T, w *worklist, want int) []target.Target {
	t.Helper()
	var out []target.Target
	for len(out) < want {
		// Use a fresh ctx with a short deadline so a test bug does not
		// hang forever; Pop returns ok=false on ctx cancel.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		got, tier, ok := w.Pop(ctx)
		cancel()
		if !ok {
			return out
		}
		out = append(out, got)
		w.Done(tier)
	}
	return out
}

func TestWorklistPushDedupes(t *testing.T) {
	w := newWorklist(nil, 0)

	ctx := context.Background()
	a := target.Page("https://example.com/x", "crawler")
	b := target.Page("https://example.com/x", "check:other") // same canonical key

	if !w.Push(ctx, a, core.TierFingerprint) {
		t.Fatalf("first Push should accept")
	}
	if w.Push(ctx, b, core.TierFingerprint) {
		t.Fatalf("duplicate Push at same tier must be rejected")
	}

	got := drainPending(t, w, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1 target through the queue, got %d", len(got))
	}
}

// TestWorklistPushAcceptsSameTargetAtNextTier pins the new
// tier-aware dedup: the same canonical key pushed at a DIFFERENT
// tier is accepted (this is the worker-driven tier advance path).
// The previous dedup keyed only on canonicalKey would have rejected
// the second push and stalled tier ordering.
func TestWorklistPushAcceptsSameTargetAtNextTier(t *testing.T) {
	w := newWorklist(nil, 0)
	ctx := context.Background()
	a := target.Page("https://example.com/x", "crawler")

	if !w.Push(ctx, a, core.TierFingerprint) {
		t.Fatalf("first Push at TierFingerprint should accept")
	}
	if !w.Push(ctx, a, core.TierPassive) {
		t.Fatalf("re-push at TierPassive must accept (tier advance path)")
	}
	if !w.Push(ctx, a, core.TierDiscovery) {
		t.Fatalf("re-push at TierDiscovery must accept (tier advance path)")
	}
	if !w.Push(ctx, a, core.TierActive) {
		t.Fatalf("re-push at TierActive must accept (tier advance path)")
	}
}

func TestWorklistPushDropsAfterClose(t *testing.T) {
	w := newWorklist(nil, 0)
	w.Close()

	if w.Push(context.Background(), target.Page("https://example.com/", "crawler"), core.TierFingerprint) {
		t.Fatalf("Push after Close must return false")
	}
}

func TestWorklistPushDropsAfterCtxCancel(t *testing.T) {
	w := newWorklist(nil, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if w.Push(ctx, target.Page("https://example.com/", "crawler"), core.TierFingerprint) {
		t.Fatalf("Push with already-canceled ctx must return false")
	}
}

func TestWorklistScopeRejectsOutOfScope(t *testing.T) {
	sc, err := scope.New(scope.Config{Hosts: []string{"example.com"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	w := newWorklist(sc, 0)

	ctx := context.Background()
	if !w.Push(ctx, target.Page("https://example.com/in", "crawler"), core.TierFingerprint) {
		t.Fatalf("in-scope Push should accept")
	}
	if w.Push(ctx, target.Page("https://other.example.org/out", "crawler"), core.TierFingerprint) {
		t.Fatalf("out-of-scope Push must be rejected")
	}

	got := drainPending(t, w, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1 target through the queue, got %d", len(got))
	}
}

func TestWorklistScopeNilIsPermissive(t *testing.T) {
	w := newWorklist(nil, 0)

	if !w.Push(context.Background(), target.Page("https://any.example.org/x", "crawler"), core.TierFingerprint) {
		t.Fatalf("nil scope must accept every URL")
	}
}

func TestWorklistHostBudgetCaps(t *testing.T) {
	w := newWorklist(nil, 0)
	w.withHostBudget(2)

	ctx := context.Background()
	if !w.Push(ctx, target.Page("https://example.com/a", "crawler"), core.TierFingerprint) {
		t.Fatalf("first Push under budget should accept")
	}
	if !w.Push(ctx, target.Page("https://example.com/b", "crawler"), core.TierFingerprint) {
		t.Fatalf("second Push under budget should accept")
	}
	if w.Push(ctx, target.Page("https://example.com/c", "crawler"), core.TierFingerprint) {
		t.Fatalf("third Push must be rejected (budget exhausted)")
	}

	// A different host shares no budget.
	if !w.Push(ctx, target.Page("https://other.example.org/a", "crawler"), core.TierFingerprint) {
		t.Fatalf("Push to a different host must accept under its own budget")
	}
}

// TestWorklistHostBudgetIgnoresTierReadvances pins that the per-host
// budget counts unique TARGETS, not unique (target, tier) pairs. The
// worker re-pushes a target as it advances through tiers; those
// re-pushes must not consume budget or else a budget of 2 would
// reject the 3rd tier advance of the second target.
func TestWorklistHostBudgetIgnoresTierReadvances(t *testing.T) {
	w := newWorklist(nil, 0)
	w.withHostBudget(2)

	ctx := context.Background()
	a := target.Page("https://example.com/a", "crawler")
	b := target.Page("https://example.com/b", "crawler")

	if !w.Push(ctx, a, core.TierFingerprint) {
		t.Fatalf("a@fingerprint must accept (budget 1/2)")
	}
	if !w.Push(ctx, b, core.TierFingerprint) {
		t.Fatalf("b@fingerprint must accept (budget 2/2)")
	}
	// Worker advances a through every tier - must NOT trip the budget.
	for _, tier := range []core.Tier{core.TierPassive, core.TierDiscovery, core.TierActive} {
		if !w.Push(ctx, a, tier) {
			t.Errorf("a@%s rejected; tier advances must not consume budget", tier)
		}
		if !w.Push(ctx, b, tier) {
			t.Errorf("b@%s rejected; tier advances must not consume budget", tier)
		}
	}
	// A third unique target must still be budget-rejected.
	if w.Push(ctx, target.Page("https://example.com/c", "crawler"), core.TierFingerprint) {
		t.Fatalf("c@fingerprint must be rejected; budget should still cap unique targets at 2")
	}
}

// TestWorklistPopReturnsLowestTierFirst pins soft-priority semantics:
// when multiple tier bands have items, Pop returns from the lowest
// non-empty band first. This is the heart of cross-target tier
// ordering - tier-1 work everywhere drains before tier-2 work.
func TestWorklistPopReturnsLowestTierFirst(t *testing.T) {
	w := newWorklist(nil, 0)
	ctx := context.Background()

	// Push higher tiers first so FIFO-within-tier would NOT
	// deliver them first; only tier priority would.
	if !w.Push(ctx, target.Page("https://example.com/active", "crawler"), core.TierActive) {
		t.Fatalf("Push active failed")
	}
	if !w.Push(ctx, target.Page("https://example.com/discovery", "crawler"), core.TierDiscovery) {
		t.Fatalf("Push discovery failed")
	}
	if !w.Push(ctx, target.Page("https://example.com/passive", "crawler"), core.TierPassive) {
		t.Fatalf("Push passive failed")
	}
	if !w.Push(ctx, target.Page("https://example.com/fingerprint", "crawler"), core.TierFingerprint) {
		t.Fatalf("Push fingerprint failed")
	}

	wantTierOrder := []core.Tier{
		core.TierFingerprint,
		core.TierPassive,
		core.TierDiscovery,
		core.TierActive,
	}
	for i, wantTier := range wantTierOrder {
		got, tier, ok := w.Pop(ctx)
		if !ok {
			t.Fatalf("Pop %d failed", i)
		}
		if tier != wantTier {
			t.Errorf("Pop %d: tier = %v, want %v (URL=%s)", i, tier, wantTier, got.URL)
		}
		w.Done(tier)
	}
}

func TestWorklistCloseUnblocksReceivers(t *testing.T) {
	w := newWorklist(nil, 0)

	done := make(chan struct{})
	go func() {
		_, _, _ = w.Pop(context.Background())
		close(done)
	}()

	w.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Close did not unblock Pop within 1s")
	}
}

func TestWorklistSourceDoneAndDrainedExits(t *testing.T) {
	// Push two items, complete both via Pop+Done, then SourceDone -
	// the next Pop must return (zero, 0, false) because the queue is
	// drained AND no more pushes will arrive.
	w := newWorklist(nil, 0)
	ctx := context.Background()
	w.Push(ctx, target.Page("https://example.com/a", "crawler"), core.TierFingerprint)
	w.Push(ctx, target.Page("https://example.com/b", "crawler"), core.TierFingerprint)

	for i := 0; i < 2; i++ {
		_, tier, ok := w.Pop(ctx)
		if !ok {
			t.Fatalf("Pop %d should succeed", i)
		}
		w.Done(tier)
	}
	w.SourceDone()

	done := make(chan bool, 1)
	go func() {
		_, _, ok := w.Pop(ctx)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatalf("Pop after drain+SourceDone must return false")
		}
	case <-time.After(time.Second):
		t.Fatalf("Pop did not unblock on quiescence within 1s")
	}
}

func TestWorklistPopReturnsPushedTargetsInOrder(t *testing.T) {
	w := newWorklist(nil, 0)

	urls := []string{
		"https://example.com/a",
		"https://example.com/b",
		"https://example.com/c",
	}
	ctx := context.Background()
	for _, u := range urls {
		if !w.Push(ctx, target.Page(u, "crawler"), core.TierFingerprint) {
			t.Fatalf("Push %q failed", u)
		}
	}

	got := drainPending(t, w, len(urls))
	if len(got) != len(urls) {
		t.Fatalf("expected %d targets, got %d", len(urls), len(got))
	}
	for i, u := range urls {
		if got[i].URL != u {
			t.Errorf("target %d URL = %q, want %q", i, got[i].URL, u)
		}
	}
}
