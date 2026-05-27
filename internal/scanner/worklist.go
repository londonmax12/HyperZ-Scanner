package scanner

import (
	"context"
	"net/url"
	"sync"

	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// worklist is the dispatch queue feeding scanOne. It dedupes targets
// by canonical key, enforces scope, applies the per-host budget, and
// terminates on quiescence (input source done + zero in-flight work)
// so checks that emit discoveries mid-scan still get drained.
//
// PR 1 used a buffered channel; that broke down once discovery
// emission landed because a check's Push could race the producer
// goroutine's queue.Close(). The current implementation is a
// slice+cond queue with explicit in-flight tracking: Push increments
// pending, Pop hands an item to a worker, Done decrements after the
// worker finishes dispatching that target, and the queue declares
// itself drained when SourceDone has been signalled AND pending hits
// zero. Workers waiting on cond.Wait wake on Push, Done, SourceDone,
// Close, or ctx-cancel (via cancelWaiting from a small watcher
// goroutine ScanAll launches).
//
// The cancellation contract from project_scanner_cancel_contract is
// preserved by construction: the worklist mediates which targets reach
// scanOne, never which findings reach `out`. scanOne's send loop still
// does not select on ctx.Done; in-flight findings flush even when the
// queue has stopped accepting new pushes.
type worklist struct {
	mu    sync.Mutex
	cond  *sync.Cond
	items []target.Target
	seen  map[string]struct{}
	scope *scope.Scope

	// pending is queued + in-flight: incremented by a successful Push,
	// decremented by Done. When pending == 0 AND sourceDone == true,
	// no more work can ever arrive and Pop returns ("", false) so
	// workers exit.
	pending int

	// sourceDone signals that the external producer (the crawler's
	// pages channel reader) has finished pushing. After this, the only
	// remaining pushes are from in-flight checks emitting discoveries.
	sourceDone bool

	// closed is a hard-stop flag set by Close. Pop returns ("", false)
	// immediately while closed is true; Push is rejected. Independent
	// of sourceDone / pending so test paths that want immediate
	// termination do not have to thread the soft path.
	closed bool

	// budgetPerHost caps total accepted pushes per host across the
	// scan. Zero (the default) means unlimited. Activated by
	// withHostBudget; the Scanner threads its WithHostBudget option
	// through.
	budgetPerHost int
	hostCount     map[string]int
}

// newWorklist constructs a worklist with the given scope (nil means
// permissive). The second argument exists for the previous
// channel-based implementation's buffer sizing; the slice+cond design
// has no buffer to size, so the argument is accepted for source
// compatibility with callers that still pass it but is ignored.
func newWorklist(sc *scope.Scope, _ int) *worklist {
	w := &worklist{
		seen:      map[string]struct{}{},
		hostCount: map[string]int{},
		scope:     sc,
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

// Push enqueues t and increments the pending count. Returns false
// (without enqueuing) when t is dropped because:
//
//   - ctx already cancelled at call time
//   - the worklist is closed
//   - the canonical key was already pushed (dedupe)
//   - t.URL fails scope
//   - the per-host budget for t's host is exhausted
//
// A successful Push signals one waiting popper.
func (w *worklist) Push(ctx context.Context, t target.Target) bool {
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

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	if _, dup := w.seen[key]; dup {
		return false
	}
	if w.budgetPerHost > 0 && host != "" && w.hostCount[host] >= w.budgetPerHost {
		return false
	}
	w.seen[key] = struct{}{}
	if host != "" {
		w.hostCount[host]++
	}
	w.items = append(w.items, t)
	w.pending++
	w.cond.Signal()
	return true
}

// Pop blocks until either an item is available or the queue declares
// itself drained. Returns (target, true) on success, (zero, false)
// when no further items will arrive (drained, hard-closed, or ctx
// cancelled).
//
// The caller MUST call Done after the dispatch for the returned
// target completes, so the worklist can decrement pending and
// recognize quiescence.
//
// Pop installs a one-shot watcher goroutine to translate ctx cancel
// into a cond broadcast, so cond.Wait wakes on cancellation. The
// watcher exits via the close(stopWatcher) call on every return path,
// so it does not leak when Pop returns quickly (the common case where
// an item was already pending).
func (w *worklist) Pop(ctx context.Context) (target.Target, bool) {
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
			return target.Target{}, false
		}
		if ctx.Err() != nil {
			return target.Target{}, false
		}
		if len(w.items) > 0 {
			t := w.items[0]
			w.items = w.items[1:]
			return t, true
		}
		if w.sourceDone && w.pending == 0 {
			return target.Target{}, false
		}
		w.cond.Wait()
	}
}

// Done decrements the pending count after a worker finishes
// dispatching the target Pop handed it. When pending reaches zero
// after SourceDone has been signalled, every waiting popper is woken
// so they can return (zero, false) and exit.
func (w *worklist) Done() {
	w.mu.Lock()
	w.pending--
	if w.pending == 0 && w.sourceDone {
		w.cond.Broadcast()
	}
	w.mu.Unlock()
}

// SourceDone marks the external producer as finished. After this
// call, the queue will close itself (signal all poppers to exit) as
// soon as pending reaches zero. Idempotent.
func (w *worklist) SourceDone() {
	w.mu.Lock()
	if w.sourceDone {
		w.mu.Unlock()
		return
	}
	w.sourceDone = true
	if w.pending == 0 {
		w.cond.Broadcast()
	}
	w.mu.Unlock()
}

// Close is the hard-stop path: subsequent Push calls return false,
// Pop returns (zero, false), and every waiting popper wakes. Used
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
