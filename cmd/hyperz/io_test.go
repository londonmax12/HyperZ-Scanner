package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
