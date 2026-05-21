package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/fingerprint"
	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/scope"
)

type Scanner struct {
	client      *httpclient.Client
	checks      []checks.Check
	scope       *scope.Scope
	detector    *fingerprint.Detector
	concurrency int
	onError     func(target, check string, err error)
	onSkip      func(target, check, reason string)
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

// WithScope sets the scan scope handed to each check. A nil scope (the
// default) means checks run unconstrained — fine for ad-hoc single-target
// scans, not for active probes against untrusted infrastructure.
func WithScope(sc *scope.Scope) Option {
	return func(s *Scanner) { s.scope = sc }
}

// WithFingerprint enables stack detection. A check that implements
// fingerprint.StackGated is asked whether it applies to the detected
// stack; if it returns false, the check is skipped for that target.
// Checks without StackGated always run.
//
// Detection failures are soft — when Detect returns an error the
// scanner skips gating for that target and runs every check, so a flaky
// fingerprint request can't silently disable findings.
func WithFingerprint(d *fingerprint.Detector) Option {
	return func(s *Scanner) { s.detector = d }
}

// WithSkipHandler installs a callback fired each time a stack-gated check
// is skipped. Useful for surfacing "[skip] xss/example.com: no PHP detected"
// lines in CLI output.
func WithSkipHandler(fn func(target, check, reason string)) Option {
	return func(s *Scanner) { s.onSkip = fn }
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
	stack := s.fingerprint(ctx, target)

	var wg sync.WaitGroup
	for _, c := range s.checks {
		if ctx.Err() != nil {
			return
		}
		if !s.applies(c, stack, target) {
			continue
		}
		wg.Add(1)
		go func(c checks.Check) {
			defer wg.Done()
			found, err := c.Run(ctx, s.client, s.scope, target)
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

// fingerprint resolves the stack for target, or returns nil when
// fingerprinting is disabled or fails. A nil stack means "skip gating" —
// every check runs, which is the safer default than silently dropping a
// check because we couldn't reach the host.
func (s *Scanner) fingerprint(ctx context.Context, target string) *fingerprint.Stack {
	if s.detector == nil {
		return nil
	}
	stack, err := s.detector.Detect(ctx, target)
	if err != nil {
		if s.onError != nil {
			s.onError(target, "fingerprint", err)
		}
		return nil
	}
	return stack
}

// applies returns true if c should run against target given the detected
// stack. When stack is nil (fingerprinting disabled or failed), every
// check runs. Checks that don't implement StackGated always run.
func (s *Scanner) applies(c checks.Check, stack *fingerprint.Stack, target string) bool {
	if stack == nil {
		return true
	}
	g, ok := c.(fingerprint.StackGated)
	if !ok {
		return true
	}
	if g.AppliesTo(stack) {
		return true
	}
	if s.onSkip != nil {
		s.onSkip(target, c.Name(), "stack does not match ("+stack.Summary()+")")
	}
	return false
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
