package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// drainAvailable pulls every target the worklist has emitted so far,
// without blocking. Stops when the channel has no item ready or has been
// closed. Used by tests that want to assert "exactly N targets reached
// workers" without dictating order or waiting for Close.
func drainAvailable(w *worklist) []target.Target {
	var out []target.Target
	for {
		select {
		case t, ok := <-w.Out():
			if !ok {
				return out
			}
			out = append(out, t)
		default:
			return out
		}
	}
}

func TestWorklistPushDedupes(t *testing.T) {
	w := newWorklist(nil, 8)
	defer w.Close()

	ctx := context.Background()
	a := target.Page("https://example.com/x", "crawler")
	b := target.Page("https://example.com/x", "check:other") // same canonical key

	if !w.Push(ctx, a) {
		t.Fatalf("first Push should accept")
	}
	if w.Push(ctx, b) {
		t.Fatalf("duplicate Push must be rejected")
	}

	got := drainAvailable(w)
	if len(got) != 1 {
		t.Fatalf("expected 1 target through the queue, got %d", len(got))
	}
}

func TestWorklistPushDropsAfterClose(t *testing.T) {
	w := newWorklist(nil, 1)
	w.Close()

	if w.Push(context.Background(), target.Page("https://example.com/", "crawler")) {
		t.Fatalf("Push after Close must return false")
	}
}

func TestWorklistPushDropsAfterCtxCancel(t *testing.T) {
	w := newWorklist(nil, 1)
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if w.Push(ctx, target.Page("https://example.com/", "crawler")) {
		t.Fatalf("Push with already-canceled ctx must return false")
	}
}

func TestWorklistScopeRejectsOutOfScope(t *testing.T) {
	sc, err := scope.New(scope.Config{Hosts: []string{"example.com"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	w := newWorklist(sc, 4)
	defer w.Close()

	ctx := context.Background()
	if !w.Push(ctx, target.Page("https://example.com/in", "crawler")) {
		t.Fatalf("in-scope Push should accept")
	}
	if w.Push(ctx, target.Page("https://other.example.org/out", "crawler")) {
		t.Fatalf("out-of-scope Push must be rejected")
	}

	got := drainAvailable(w)
	if len(got) != 1 {
		t.Fatalf("expected 1 target through the queue, got %d", len(got))
	}
}

func TestWorklistScopeNilIsPermissive(t *testing.T) {
	w := newWorklist(nil, 4)
	defer w.Close()

	if !w.Push(context.Background(), target.Page("https://any.example.org/x", "crawler")) {
		t.Fatalf("nil scope must accept every URL")
	}
}

func TestWorklistHostBudgetCaps(t *testing.T) {
	w := newWorklist(nil, 8)
	w.withHostBudget(2)
	defer w.Close()

	ctx := context.Background()
	if !w.Push(ctx, target.Page("https://example.com/a", "crawler")) {
		t.Fatalf("first Push under budget should accept")
	}
	if !w.Push(ctx, target.Page("https://example.com/b", "crawler")) {
		t.Fatalf("second Push under budget should accept")
	}
	if w.Push(ctx, target.Page("https://example.com/c", "crawler")) {
		t.Fatalf("third Push must be rejected (budget exhausted)")
	}

	// A different host shares no budget.
	if !w.Push(ctx, target.Page("https://other.example.org/a", "crawler")) {
		t.Fatalf("Push to a different host must accept under its own budget")
	}
}

func TestWorklistCloseUnblocksReceivers(t *testing.T) {
	w := newWorklist(nil, 1)

	done := make(chan struct{})
	go func() {
		for range w.Out() {
		}
		close(done)
	}()

	w.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Close did not unblock the receiver within 1s")
	}
}

func TestWorklistOutCarriesPushedTargets(t *testing.T) {
	w := newWorklist(nil, 4)
	defer w.Close()

	urls := []string{
		"https://example.com/a",
		"https://example.com/b",
		"https://example.com/c",
	}
	ctx := context.Background()
	for _, u := range urls {
		if !w.Push(ctx, target.Page(u, "crawler")) {
			t.Fatalf("Push %q failed", u)
		}
	}

	got := drainAvailable(w)
	if len(got) != len(urls) {
		t.Fatalf("expected %d targets, got %d", len(urls), len(got))
	}
	for i, u := range urls {
		if got[i].URL != u {
			t.Errorf("target %d URL = %q, want %q", i, got[i].URL, u)
		}
	}
}
