package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/londonball/hyperz/internal/scope"
)

func writeTempFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestCollectSeedsInlineOnly(t *testing.T) {
	got, err := collectSeeds([]string{"http://a", " http://b ", "", "# skip", "http://c"}, "")
	if err != nil {
		t.Fatalf("collectSeeds: %v", err)
	}
	want := []string{"http://a", "http://b", "http://c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollectSeedsFromFile(t *testing.T) {
	path := writeTempFile(t, "urls.txt", "http://x\n\n# comment\nhttp://y\n  http://z  \n")
	got, err := collectSeeds(nil, path)
	if err != nil {
		t.Fatalf("collectSeeds: %v", err)
	}
	want := []string{"http://x", "http://y", "http://z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollectSeedsCombinesInlineAndFile(t *testing.T) {
	path := writeTempFile(t, "urls.txt", "http://from-file\n")
	got, err := collectSeeds([]string{"http://from-cli"}, path)
	if err != nil {
		t.Fatalf("collectSeeds: %v", err)
	}
	want := []string{"http://from-cli", "http://from-file"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollectSeedsFileMissingErrors(t *testing.T) {
	_, err := collectSeeds(nil, filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFeedDeliversAllURLs(t *testing.T) {
	path := writeTempFile(t, "urls.txt", "http://x\n# skip\n\nhttp://y\n")
	out := make(chan string, 4)
	errCh := make(chan error, 1)
	go func() {
		errCh <- feed(context.Background(), out, []string{"http://a", "", "  http://b"}, path)
		close(out)
	}()
	var got []string
	for u := range out {
		got = append(got, u)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("feed: %v", err)
	}
	want := []string{"http://a", "http://b", "http://x", "http://y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFeedStopsOnContextCancel(t *testing.T) {
	// Unbuffered output channel + canceled ctx → first push must abort.
	out := make(chan string)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := feed(ctx, out, []string{"http://a", "http://b"}, "")
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestFeedMissingFileErrors(t *testing.T) {
	out := make(chan string, 1)
	err := feed(context.Background(), out, nil, filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// drainSeeds runs feedSeeds in a goroutine, closes the output channel when
// feedSeeds returns, and collects the URLs it pushed onto out along with the
// (seed, reason) pairs delivered to the skip handler. Used by the feedSeeds
// scope-gating tests below.
func drainSeeds(ctx context.Context, seeds []string, sc *scope.Scope) ([]string, [][2]string, error) {
	out := make(chan string, len(seeds))
	var skips [][2]string
	errCh := make(chan error, 1)
	go func() {
		errCh <- feedSeeds(ctx, out, seeds, sc, func(seed, reason string) {
			skips = append(skips, [2]string{seed, reason})
		})
		close(out)
	}()
	var got []string
	for u := range out {
		got = append(got, u)
	}
	return got, skips, <-errCh
}

func TestFeedSeedsDropsOutOfScopeURL(t *testing.T) {
	// The headline safety case: --url evil.example --scope-host good.example
	// (no --crawl). Before the gate, the evil host slipped past every active
	// check because the no-crawl path never consulted Scope.Allows.
	sc, err := scope.New(scope.Config{Hosts: []string{"good.example"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	got, skips, err := drainSeeds(context.Background(),
		[]string{"http://evil.example/x", "http://good.example/y"}, sc)
	if err != nil {
		t.Fatalf("feedSeeds: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"http://good.example/y"}) {
		t.Fatalf("delivered %v, want only the in-scope seed", got)
	}
	if len(skips) != 1 || skips[0][0] != "http://evil.example/x" {
		t.Fatalf("skip handler saw %v, want one call for the evil host", skips)
	}
	if !strings.Contains(skips[0][1], "out of scope") {
		t.Errorf("skip reason = %q, want it to mention scope", skips[0][1])
	}
}

func TestFeedSeedsDropsNonHTTPScheme(t *testing.T) {
	got, skips, err := drainSeeds(context.Background(),
		[]string{"ftp://x/y", "javascript:alert(1)", "http://ok"}, nil)
	if err != nil {
		t.Fatalf("feedSeeds: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"http://ok"}) {
		t.Fatalf("delivered %v, want only http://ok", got)
	}
	sort.Slice(skips, func(i, j int) bool { return skips[i][0] < skips[j][0] })
	if len(skips) != 2 {
		t.Fatalf("skip handler saw %v, want 2 calls", skips)
	}
}

func TestFeedSeedsPassesEverythingWithNilScope(t *testing.T) {
	// Nil scope is permissive (it just means "no host/path restrictions"),
	// so every parseable http(s) URL must still flow through.
	got, skips, err := drainSeeds(context.Background(),
		[]string{"http://a", "https://b"}, nil)
	if err != nil {
		t.Fatalf("feedSeeds: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"http://a", "https://b"}) {
		t.Fatalf("delivered %v, want both seeds", got)
	}
	if len(skips) != 0 {
		t.Fatalf("nil scope skipped %v; want nothing skipped", skips)
	}
}

func TestFeedSeedsNilSkipHandlerSafe(t *testing.T) {
	// Calling with a nil skip handler must not panic even when seeds are
	// dropped; the warn-on-skip is best-effort, not load-bearing.
	sc, err := scope.New(scope.Config{Hosts: []string{"good.example"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	out := make(chan string, 2)
	done := make(chan error, 1)
	go func() {
		done <- feedSeeds(context.Background(), out, []string{"http://evil.example/x"}, sc, nil)
		close(out)
	}()
	for range out {
	}
	if err := <-done; err != nil {
		t.Fatalf("feedSeeds: %v", err)
	}
}

func TestOpenInputStdin(t *testing.T) {
	r, closeFn, err := openInput("-")
	if err != nil {
		t.Fatalf("openInput: %v", err)
	}
	defer closeFn()
	if r != os.Stdin {
		t.Fatalf("expected stdin, got %T", r)
	}
}

func TestOpenInputFile(t *testing.T) {
	path := writeTempFile(t, "in.txt", "hello\n")
	r, closeFn, err := openInput(path)
	if err != nil {
		t.Fatalf("openInput: %v", err)
	}
	defer closeFn()
	b, _ := io.ReadAll(r)
	if string(b) != "hello\n" {
		t.Fatalf("got %q, want %q", b, "hello\n")
	}
}

func TestOpenInputMissing(t *testing.T) {
	if _, _, err := openInput(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestOpenOutputStdout(t *testing.T) {
	for _, p := range []string{"", "-"} {
		w, closeFn, err := openOutput(p)
		if err != nil {
			t.Fatalf("openOutput(%q): %v", p, err)
		}
		closeFn()
		if w != os.Stdout {
			t.Fatalf("openOutput(%q) → %T, want os.Stdout", p, w)
		}
	}
}

func TestOpenOutputFileFlushes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	w, closeFn, err := openOutput(path)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}
	bw, ok := w.(*bufio.Writer)
	if !ok {
		t.Fatalf("expected *bufio.Writer, got %T", w)
	}
	if _, err := bw.WriteString("payload"); err != nil {
		t.Fatalf("write: %v", err)
	}
	closeFn() // must flush + close

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readfile: %v", err)
	}
	if !strings.Contains(string(b), "payload") {
		t.Fatalf("file %q, want to contain \"payload\"", b)
	}
}

func TestOpenOutputCreateFailure(t *testing.T) {
	// Path inside a missing directory should fail to create.
	bogus := filepath.Join(t.TempDir(), "missing-dir", "out.txt")
	if _, _, err := openOutput(bogus); err == nil {
		t.Fatal("expected error for unreachable path")
	}
}
