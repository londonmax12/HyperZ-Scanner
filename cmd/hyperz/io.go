package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

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
