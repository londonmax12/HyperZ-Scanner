package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/londonball/hyperz/internal/scope"
)

// collectSeeds reads CLI URLs and an optional URL file into a slice. Used by
// the crawl path, which needs the full seed list before workers start.
func collectSeeds(urls []string, urlsFile string) ([]string, error) {
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			return
		}
		out = append(out, u)
	}
	for _, u := range urls {
		add(u)
	}
	if urlsFile == "" {
		return out, nil
	}
	r, closeFn, err := openInput(urlsFile)
	if err != nil {
		return nil, fmt.Errorf("open urls-file: %w", err)
	}
	defer closeFn()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		add(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read urls-file: %w", err)
	}
	return out, nil
}

// feedSeeds streams a pre-collected seed list onto out, honoring ctx
// cancellation. Used by the no-crawl path now that the scope builder needs
// the seed list up front.
//
// Seeds that fail to parse, carry a non-http(s) scheme, or fall outside sc
// are dropped before they reach the scanner. This matches the crawl path
// (which gates every URL through Scope.Allows before submitting): without
// the gate, `--url evil.example --scope-host good.example` would scan
// evil.example, defeating the scope flag for active checks.
//
// onSkip, when non-nil, fires once per dropped seed with the reason so the
// caller can surface a warning. A nil sc means "no scope restriction" and
// passes every parseable http(s) URL through.
func feedSeeds(ctx context.Context, out chan<- string, seeds []string, sc *scope.Scope, onSkip func(seed, reason string)) error {
	skip := func(seed, reason string) {
		if onSkip != nil {
			onSkip(seed, reason)
		}
	}
	for _, s := range seeds {
		u, err := url.Parse(s)
		if err != nil {
			skip(s, "unparseable URL: "+err.Error())
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			skip(s, "non-http(s) scheme: "+u.Scheme)
			continue
		}
		if !sc.Allows(u) {
			skip(s, "out of scope")
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- s:
		}
	}
	return nil
}

func feed(ctx context.Context, out chan<- string, urls []string, urlsFile string) error {
	push := func(u string) bool {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case out <- u:
			return true
		}
	}
	for _, u := range urls {
		if !push(u) {
			return ctx.Err()
		}
	}
	if urlsFile == "" {
		return nil
	}
	r, closeFn, err := openInput(urlsFile)
	if err != nil {
		return fmt.Errorf("open urls-file: %w", err)
	}
	defer closeFn()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if !push(sc.Text()) {
			return ctx.Err()
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read urls-file: %w", err)
	}
	return nil
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	bw := bufio.NewWriter(f)
	return bw, func() { bw.Flush(); f.Close() }, nil
}
