package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/httpclient"
)

type Scanner struct {
	client      *httpclient.Client
	checks      []checks.Check
	concurrency int
	onError     func(target, check string, err error)
}

type Option func(*Scanner)

func WithConcurrency(n int) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.concurrency = n
		}
	}
}

func WithErrorHandler(fn func(target, check string, err error)) Option {
	return func(s *Scanner) { s.onError = fn }
}

func New(client *httpclient.Client, c []checks.Check, opts ...Option) *Scanner {
	s := &Scanner{client: client, checks: c, concurrency: 8}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ScanAll consumes targets from `targets` and emits findings on `out` until
// targets is closed and all in-flight work drains. It closes `out` on return.
func (s *Scanner) ScanAll(ctx context.Context, targets <-chan string, out chan<- checks.Finding) error {
	defer close(out)

	var wg sync.WaitGroup
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case target, ok := <-targets:
					if !ok {
						return
					}
					s.scanOne(ctx, target, out)
				}
			}
		}()
	}
	wg.Wait()
	return ctx.Err()
}

func (s *Scanner) scanOne(ctx context.Context, target string, out chan<- checks.Finding) {
	var wg sync.WaitGroup
	for _, c := range s.checks {
		if ctx.Err() != nil {
			return
		}
		wg.Add(1)
		go func(c checks.Check) {
			defer wg.Done()
			found, err := c.Run(ctx, s.client, target)
			if err != nil {
				if s.onError != nil {
					s.onError(target, c.Name(), err)
				}
				return
			}
			for _, f := range found {
				select {
				case <-ctx.Done():
					return
				case out <- f:
				}
			}
		}(c)
	}
	wg.Wait()
}

// Scan is a convenience wrapper for the single-target case. It collects all
// findings into a slice before returning.
func (s *Scanner) Scan(ctx context.Context, target string) ([]checks.Finding, error) {
	targets := make(chan string, 1)
	targets <- target
	close(targets)

	out := make(chan checks.Finding, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- s.ScanAll(ctx, targets, out) }()

	var all []checks.Finding
	for f := range out {
		all = append(all, f)
	}
	if err := <-errCh; err != nil {
		return all, fmt.Errorf("scan: %w", err)
	}
	return all, nil
}
