package scanner

import (
	"context"
	"net/url"
	"sync"

	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// worklist is the dispatch queue feeding scanOne. It dedupes targets,
// enforces scope, and respects ctx cancellation: post-cancel pushes are
// soft-dropped and the worklist channel closes so workers exit on the
// channel-closed path rather than via a separate cancellation select.
//
// PR 1 ships a single-tier streaming queue: pushes are forwarded to the
// out channel as fast as workers pull, preserving the pre-worklist
// channel-fanout behavior. Tier ordering, per-tier draining, and the
// per-host budget knob are scaffolded here (Tier field on push, a
// budgetPerHost setting, host-count bookkeeping) but PR 1 dispatches a
// single tier and leaves the budget at its unlimited default.
//
// The cancellation contract from project_scanner_cancel_contract is
// preserved by construction: the worklist mediates which targets reach
// scanOne, never which findings reach `out`. scanOne's send loop still
// does not select on ctx.Done; in-flight findings flush even when the
// queue has stopped accepting new pushes.
type worklist struct {
	mu     sync.Mutex
	seen   map[string]struct{}
	scope  *scope.Scope
	out    chan target.Target
	closed bool

	// budgetPerHost caps total targets queued per host across the scan.
	// Zero (the default) means unlimited; PR 1 ships this default so
	// behavior matches the pre-worklist single-tier dispatch. Later PRs
	// tune it once discovery emissions can balloon a host's queue depth.
	budgetPerHost int
	hostCount     map[string]int

	// stopped signals "drop further pushes silently" once Close is
	// called or ctx cancels at the producer. Workers still drain
	// in-channel items; close on `out` is what tells them to exit.
	stopped bool
}

// newWorklist constructs a worklist with the given scope (nil means
// permissive) and channel buffer size. A non-positive bufSize defaults
// to 1 so the producer never spins synchronously on every push.
func newWorklist(sc *scope.Scope, bufSize int) *worklist {
	if bufSize <= 0 {
		bufSize = 1
	}
	return &worklist{
		seen:      map[string]struct{}{},
		hostCount: map[string]int{},
		scope:     sc,
		out:       make(chan target.Target, bufSize),
	}
}

// withHostBudget caps total queued targets per host. A non-positive
// value disables the cap (the default). Set this once after newWorklist
// and before the first Push; the worklist does not synchronize against
// in-flight reads of the field.
func (w *worklist) withHostBudget(n int) {
	if n > 0 {
		w.budgetPerHost = n
	}
}

// Push enqueues t for dispatch. Returns false (and does not enqueue)
// when t is dropped for any of these reasons:
//
//   - ctx already canceled at call time
//   - the worklist has been closed or stopped
//   - t.URL fails scope (a nil scope is permissive, matching scope.Scope's
//     contract; PR 1 only ever pushes crawler-origin targets so scope
//     filtering is in practice dormant)
//   - the canonical key was already pushed (dedupe)
//   - the per-host budget for this host is exhausted
//
// On a clean push the send blocks until a worker picks up the target
// or ctx cancels mid-send; the ctx-cancel branch returns false so the
// caller knows the push did not land. The dispatcher is the caller, not
// scanOne, so this select-on-ctx.Done does not violate the finding-
// flush contract on the out channel.
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

	w.mu.Lock()
	if w.stopped || w.closed {
		w.mu.Unlock()
		return false
	}
	if _, dup := w.seen[key]; dup {
		w.mu.Unlock()
		return false
	}
	host := t.Host()
	if w.budgetPerHost > 0 && host != "" && w.hostCount[host] >= w.budgetPerHost {
		w.mu.Unlock()
		return false
	}
	w.seen[key] = struct{}{}
	if host != "" {
		w.hostCount[host]++
	}
	w.mu.Unlock()

	select {
	case w.out <- t:
		return true
	case <-ctx.Done():
		return false
	}
}

// Out returns the channel workers pull from. Closed via Close once
// the producer is done; workers ranging over Out exit naturally on
// channel close.
func (w *worklist) Out() <-chan target.Target { return w.out }

// Close signals "no more pushes will arrive". Subsequent Push calls
// return false silently and the out channel is closed so workers ranging
// over Out exit. Idempotent: a second Close is a no-op rather than
// closing the channel twice.
func (w *worklist) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.stopped = true
	w.mu.Unlock()
	close(w.out)
}

// scopeAllows reports whether t.URL is in scope. A nil scope is
// permissive, mirroring scope.Scope's documented contract and the
// pre-worklist behavior where the scanner did not filter incoming pages
// against scope. The caller (Push) treats a parse failure as a scope
// failure so a malformed discovery URL is dropped rather than collapsing
// to an empty canonical key.
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
