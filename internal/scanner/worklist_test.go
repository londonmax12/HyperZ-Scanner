package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// drainPending pops up to want targets, completing each one via Done
// so quiescence semantics still work for callers that pushed and
// immediately want to inspect what landed. Stops when a Pop would
// block (no items + not yet drained).
func drainPending(t *testing.T, w *worklist, want int) []target.Target {
	t.Helper()
	var out []target.Target
	for len(out) < want {
		// Use a fresh ctx with a short deadline so a test bug does not
		// hang forever; Pop returns ok=false on ctx cancel.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		got, ok := w.Pop(ctx)
		cancel()
		if !ok {
			return out
		}
		out = append(out, got)
		w.Done()
	}
	return out
}

func TestWorklistPushDedupes(t *testing.T) {
	w := newWorklist(nil, 0)

	ctx := context.Background()
	a := target.Page("https://example.com/x", "crawler")
	b := target.Page("https://example.com/x", "check:other") // same canonical key

	if !w.Push(ctx, a) {
		t.Fatalf("first Push should accept")
	}
	if w.Push(ctx, b) {
		t.Fatalf("duplicate Push must be rejected")
	}

	got := drainPending(t, w, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1 target through the queue, got %d", len(got))
	}
}

func TestWorklistPushDropsAfterClose(t *testing.T) {
	w := newWorklist(nil, 0)
	w.Close()

	if w.Push(context.Background(), target.Page("https://example.com/", "crawler")) {
		t.Fatalf("Push after Close must return false")
	}
}

func TestWorklistPushDropsAfterCtxCancel(t *testing.T) {
	w := newWorklist(nil, 0)

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
	w := newWorklist(sc, 0)

	ctx := context.Background()
	if !w.Push(ctx, target.Page("https://example.com/in", "crawler")) {
		t.Fatalf("in-scope Push should accept")
	}
	if w.Push(ctx, target.Page("https://other.example.org/out", "crawler")) {
		t.Fatalf("out-of-scope Push must be rejected")
	}

	got := drainPending(t, w, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1 target through the queue, got %d", len(got))
	}
}

func TestWorklistScopeNilIsPermissive(t *testing.T) {
	w := newWorklist(nil, 0)

	if !w.Push(context.Background(), target.Page("https://any.example.org/x", "crawler")) {
		t.Fatalf("nil scope must accept every URL")
	}
}

func TestWorklistHostBudgetCaps(t *testing.T) {
	w := newWorklist(nil, 0)
	w.withHostBudget(2)

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
	w := newWorklist(nil, 0)

	done := make(chan struct{})
	go func() {
		_, _ = w.Pop(context.Background())
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
	// the next Pop must return (zero, false) because the queue is
	// drained AND no more pushes will arrive.
	w := newWorklist(nil, 0)
	ctx := context.Background()
	w.Push(ctx, target.Page("https://example.com/a", "crawler"))
	w.Push(ctx, target.Page("https://example.com/b", "crawler"))

	for i := 0; i < 2; i++ {
		_, ok := w.Pop(ctx)
		if !ok {
			t.Fatalf("Pop %d should succeed", i)
		}
		w.Done()
	}
	w.SourceDone()

	done := make(chan bool, 1)
	go func() {
		_, ok := w.Pop(ctx)
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
		if !w.Push(ctx, target.Page(u, "crawler")) {
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
