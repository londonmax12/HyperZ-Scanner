package scanner

import (
	"context"
	"net/url"
	"sync"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// worklist is the dispatch queue feeding scanTier. It dedupes targets
// per (canonical key, tier) pair, enforces scope, applies the per-host
// budget, and terminates on quiescence (input source done + zero
// in-flight at any tier) so checks that emit discoveries mid-scan
// still get drained.
//
// Tier model: every Target is queued at one of the four core.Tier
// bands. Pop returns from the lowest non-empty band that is also
// barrier-eligible. The previous design ordered tiers inside scanOne;
// that gave only per-target ordering and let a target X reach its
// active tier while a target Y queued behind it had not yet seen its
// fingerprint or passive checks. Now the worker pops ONE tier at a
// time per target and re-pushes the same target at the next tier when
// the dispatch completes, so a freshly-discovered target re-enters at
// TierFingerprint and traverses every tier even when other targets
// are already mid-active.
//
// Barrier semantics: Pop at tier N only returns when every lower tier
// has pendingByTier == 0 (queued AND in-flight). So a tier-N dispatch
// across the whole queue cannot begin while ANY tier-(N-1) work is
// outstanding anywhere. A worker that wakes with no eligible tier
// goes back to cond.Wait; Done broadcasts so blocked workers re-check
// after each completion. This is a real cross-target barrier, not a
// scheduling hint - the original promise from the Tier docstring in
// core ("every TierFingerprint check on a host's targets runs before
// any TierPassive check on the same targets") is now realized.
//
// The cancellation contract from project_scanner_cancel_contract is
// preserved by construction: the worklist mediates which targets reach
// scanTier, never which findings reach `out`. scanTier's send loop
// still does not select on ctx.Done; in-flight findings flush even
// when the queue has stopped accepting new pushes.
type worklist struct {
	mu    sync.Mutex
	cond  *sync.Cond
	items map[core.Tier][]target.Target
	// seen is keyed by (canonical key + ":" + tier label) so the same
	// target can be queued at every tier in turn (the worker re-pushes
	// it as each tier completes) while still dedupe-rejecting a
	// duplicate push at the SAME tier.
	seen  map[string]struct{}
	scope *scope.Scope

	// pendingByTier is queued + in-flight per tier. A successful Push
	// increments pendingByTier[t]; Done(t) decrements it. The scan is
	// drained when sourceDone is true AND every tier's count is zero.
	pendingByTier map[core.Tier]int

	// sourceDone signals that the external producer (the crawler's
	// pages channel reader) has finished pushing. After this, the only
	// remaining pushes are from in-flight checks emitting discoveries
	// and from workers advancing targets to their next tier.
	sourceDone bool

	// closed is a hard-stop flag set by Close. Pop returns ("", 0,
	// false) immediately while closed is true; Push is rejected.
	// Independent of sourceDone / pending so test paths that want
	// immediate termination do not have to thread the soft path.
	closed bool

	// budgetPerHost caps total accepted UNIQUE targets per host across
	// the scan. Tier re-pushes do not consume budget; only the first
	// push for a given canonical key on a host counts. Zero (the
	// default) disables the cap.
	budgetPerHost int
	hostCount     map[string]int
}

// tierBands is the iteration order Pop uses to find the lowest
// non-empty tier. Aligned with core's tierOrder so the worklist and
// scanner agree on which direction "increasing tier" runs.
var tierBands = []core.Tier{
	core.TierFingerprint,
	core.TierPassive,
	core.TierDiscovery,
	core.TierActive,
}

// newWorklist constructs a worklist with the given scope (nil means
// permissive). The second argument exists for the previous
// channel-based implementation's buffer sizing; the slice+cond design
// has no buffer to size, so the argument is accepted for source
// compatibility with callers that still pass it but is ignored.
func newWorklist(sc *scope.Scope, _ int) *worklist {
	w := &worklist{
		items:         map[core.Tier][]target.Target{},
		seen:          map[string]struct{}{},
		hostCount:     map[string]int{},
		pendingByTier: map[core.Tier]int{},
		scope:         sc,
	}
	w.cond = sync.NewCond(&w.mu)
	return w
}

// withHostBudget caps total accepted pushes per host. A non-positive
// value disables the cap (the default).
func (w *worklist) withHostBudget(n int) {
	if n > 0 {
		w.budgetPerHost = n
	}
}

// Push enqueues t at tier and increments pendingByTier[tier]. Returns
// false (without enqueuing) when t is dropped because:
//
//   - ctx already cancelled at call time
//   - the worklist is closed
//   - the (canonical key, tier) pair was already pushed (dedupe)
//   - t.URL fails scope
//   - this is the first time t is seen on its host AND the per-host
//     budget for that host is exhausted (only first-tier pushes
//     consume budget)
//
// A successful Push signals one waiting popper.
func (w *worklist) Push(ctx context.Context, t target.Target, tier core.Tier) bool {
	if ctx.Err() != nil {
		return false
	}
	if !w.scopeAllows(t) {
		return false
	}
	key := t.CanonicalKey()
	if key == "" {
		return false
	}
	host := t.Host()
	seenKey := key + ":" + tier.String()

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	if _, dup := w.seen[seenKey]; dup {
		return false
	}
	// Budget caps unique TARGETS per host - tier re-pushes of an
	// already-accepted target do not consume budget. Detect "first time
	// for this canonical key" by checking whether ANY seen[key:*] entry
	// exists; if none, this push is the budget-counted entry.
	firstTimeForKey := !w.seenAnyTier(key)
	if firstTimeForKey && w.budgetPerHost > 0 && host != "" && w.hostCount[host] >= w.budgetPerHost {
		return false
	}
	w.seen[seenKey] = struct{}{}
	if firstTimeForKey && host != "" {
		w.hostCount[host]++
	}
	w.items[tier] = append(w.items[tier], t)
	w.pendingByTier[tier]++
	w.cond.Signal()
	return true
}

// seenAnyTier reports whether any seen entry exists for canonical key
// k across any tier. Used by Push to decide whether the incoming push
// is the first time this target has been queued at all (which counts
// against the per-host budget) or a worker-driven tier re-push
// (which does not).
//
// Linear over tierBands - cheap, since the band count is fixed at 4.
func (w *worklist) seenAnyTier(k string) bool {
	for _, tier := range tierBands {
		if _, ok := w.seen[k+":"+tier.String()]; ok {
			return true
		}
	}
	return false
}

// Pop blocks until either an item is available or the queue declares
// itself drained. Returns (target, tier, true) on success; tier is
// the band the target was queued at, which the worker hands to
// scanTier so only that tier's checks run. Returns (zero, 0, false)
// when no further items will arrive (drained, hard-closed, or ctx
// cancelled).
//
// Tier priority WITH barrier: the lowest non-empty tier wins, but a
// tier is only pop-eligible when every lower tier has pendingByTier
// == 0 (queued and in-flight). So tier-N work across the whole queue
// drains entirely - including the last in-flight tier-N dispatch -
// before any tier-(N+1) item is handed out. Items within the same
// tier are FIFO.
//
// If no eligible tier has items but lower-tier work is in flight, Pop
// blocks on cond.Wait until Done broadcasts after each dispatch
// completes. Worst case: every worker idles waiting for the last
// in-flight lower-tier dispatch on another worker; once it Done()s,
// every blocked Pop re-checks and a higher tier becomes eligible.
//
// The caller MUST call Done(tier) after the dispatch completes, so
// the worklist can decrement pendingByTier, recognize tier transitions,
// and recognize quiescence.
//
// Pop installs a one-shot watcher goroutine to translate ctx cancel
// into a cond broadcast, so cond.Wait wakes on cancellation. The
// watcher exits via close(stopWatcher) on every return path, so it
// does not leak when Pop returns quickly (the common case where an
// item was already pending).
func (w *worklist) Pop(ctx context.Context) (target.Target, core.Tier, bool) {
	stopWatcher := make(chan struct{})
	defer close(stopWatcher)
	go func() {
		select {
		case <-ctx.Done():
			w.cancelWaiting()
		case <-stopWatcher:
		}
	}()

	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		if w.closed {
			return target.Target{}, 0, false
		}
		if ctx.Err() != nil {
			return target.Target{}, 0, false
		}
		lowerPending := 0
		for _, tier := range tierBands {
			if lowerPending == 0 && len(w.items[tier]) > 0 {
				t := w.items[tier][0]
				w.items[tier] = w.items[tier][1:]
				return t, tier, true
			}
			// Carry forward the count so the next tier band sees
			// whether ANY lower tier still has outstanding work
			// (queued or in-flight) and is therefore ineligible.
			lowerPending += w.pendingByTier[tier]
		}
		if w.sourceDone && w.totalPending() == 0 {
			return target.Target{}, 0, false
		}
		w.cond.Wait()
	}
}

// Done decrements the pending count for the given tier after a worker
// finishes dispatching at it. Always broadcasts: a Done() at tier N
// may have just zeroed pendingByTier[N], which makes tier-(N+1)
// barrier-eligible for any popper currently blocked on cond.Wait. The
// broadcast keeps barrier transitions promptly visible at the cost of
// occasional spurious wakeups that re-Wait when no eligible tier
// exists yet. A separate broadcast on full quiescence (sourceDone +
// totalPending == 0) is redundant under always-broadcast but the
// totalPending check is cheap and the broadcast cost is negligible
// for the queue depth this code sees.
func (w *worklist) Done(tier core.Tier) {
	w.mu.Lock()
	w.pendingByTier[tier]--
	w.cond.Broadcast()
	w.mu.Unlock()
}

// totalPending sums pendingByTier across every band. The caller must
// hold w.mu.
func (w *worklist) totalPending() int {
	total := 0
	for _, n := range w.pendingByTier {
		total += n
	}
	return total
}

// SourceDone marks the external producer as finished. After this
// call, the queue will close itself (signal all poppers to exit) as
// soon as totalPending reaches zero. Idempotent.
func (w *worklist) SourceDone() {
	w.mu.Lock()
	if w.sourceDone {
		w.mu.Unlock()
		return
	}
	w.sourceDone = true
	if w.totalPending() == 0 {
		w.cond.Broadcast()
	}
	w.mu.Unlock()
}

// Close is the hard-stop path: subsequent Push calls return false,
// Pop returns (zero, 0, false), and every waiting popper wakes. Used
// when ctx cancels or when tests want immediate termination.
// Idempotent.
func (w *worklist) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()
	w.cond.Broadcast()
}

// cancelWaiting wakes every popper currently blocked on cond.Wait so
// they can re-check ctx.Err() and exit. Called by the small ctx
// watcher goroutine ScanAll launches so a cancellation propagates
// from ctx through to the workers without each popper installing
// its own select.
func (w *worklist) cancelWaiting() {
	w.mu.Lock()
	w.cond.Broadcast()
	w.mu.Unlock()
}

// scopeAllows reports whether t.URL is in scope. A nil scope is
// permissive, mirroring scope.Scope's documented contract. An
// unparseable URL fails scope: pushing a malformed discovery URL
// would otherwise pollute the dedupe set with an entry no worker can
// act on.
func (w *worklist) scopeAllows(t target.Target) bool {
	if w.scope == nil {
		return true
	}
	if t.URL == "" {
		return false
	}
	u, err := url.Parse(t.URL)
	if err != nil || u.Host == "" {
		return false
	}
	return w.scope.Allows(u)
}
