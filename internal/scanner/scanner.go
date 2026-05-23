package scanner

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

type Scanner struct {
	client           *httpclient.Client
	checks           []checks.Check
	scope            *scope.Scope
	detector         *fingerprint.Detector
	concurrency      int
	checkConcurrency int
	level            checks.Level
	onError          func(target, check string, err error)
	onSkip           func(target, check, reason string)
}

type Option func(*Scanner)

func WithConcurrency(n int) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.concurrency = n
		}
	}
}

// WithCheckConcurrency caps how many checks run in parallel against a single
// target. 0 (the default) means "no cap" - every applicable check is launched
// at once, which is fine for a handful of passive checks but blows up once
// dozens of active probes ship. Set this to a small number (8-16) to keep
// fanout bounded as the catalog grows.
func WithCheckConcurrency(n int) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.checkConcurrency = n
		}
	}
}

func WithErrorHandler(fn func(target, check string, err error)) Option {
	return func(s *Scanner) { s.onError = fn }
}

// WithScope sets the scan scope handed to each check. A nil scope (the
// default) means checks run unconstrained - fine for ad-hoc single-target
// scans, not for active probes against untrusted infrastructure.
func WithScope(sc *scope.Scope) Option {
	return func(s *Scanner) { s.scope = sc }
}

// WithFingerprint enables stack detection. A check that implements
// fingerprint.StackGated is asked whether it applies to the detected
// stack; if it returns false, the check is skipped for that target.
// Checks without StackGated always run.
//
// Detection failures are soft - when Detect returns an error the
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

// WithLevel records the scan level the caller filtered checks for, so the
// scanner can attach it to each check's ctx via checks.WithLevel. Checks that
// want to scale their behavior (e.g. fewer probes at default, full sweep at
// aggressive) read it via checks.LevelFrom. The default (LevelDefault) is the
// conservative choice when the option isn't set.
func WithLevel(lvl checks.Level) Option {
	return func(s *Scanner) { s.level = lvl }
}

func New(client *httpclient.Client, c []checks.Check, opts ...Option) *Scanner {
	s := &Scanner{client: client, checks: c, concurrency: 8, level: checks.LevelDefault}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ScanAll consumes Pages from `pages` and emits findings on `out` until
// pages is closed and all in-flight work drains. It closes `out` on return.
//
// On ctx cancel, workers stop picking up new pages and scanOne stops
// scheduling new checks, but any check whose Run has already returned will
// have its findings flushed to `out`. The reader of `out` must keep
// draining until close, or those senders will block.
func (s *Scanner) ScanAll(ctx context.Context, pages <-chan page.Page, out chan<- checks.Finding) error {
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
				case p, ok := <-pages:
					if !ok {
						return
					}
					s.scanOne(ctx, p, out)
				}
			}
		}()
	}
	wg.Wait()
	return ctx.Err()
}

// scanOne fingerprints p then runs every applicable check in parallel.
// When a check's Run returns, its findings are sent unconditionally - they
// already exist in memory, so we flush them even if ctx cancels mid-send.
// New checks are not scheduled after ctx cancels (the loop bails on
// ctx.Err()), so the post-cancel send burst is bounded by checks already
// in flight. The caller (the report side) must drain `out` until it closes
// or the senders will deadlock.
func (s *Scanner) scanOne(ctx context.Context, p page.Page, out chan<- checks.Finding) {
	stack := s.fingerprint(ctx, p)
	target := p.URL

	// sem caps in-flight checks per target. A nil sem means no cap.
	var sem chan struct{}
	if s.checkConcurrency > 0 {
		sem = make(chan struct{}, s.checkConcurrency)
	}

	var wg sync.WaitGroup
	for _, c := range s.checks {
		if ctx.Err() != nil {
			break
		}
		if !s.applies(c, stack, target) {
			continue
		}
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
		}
		wg.Add(1)
		go func(c checks.Check) {
			defer wg.Done()
			if sem != nil {
				defer func() { <-sem }()
			}
			// Per-check deadline keeps a pathological Run (regex
			// backtracking, slow body read, weird redirect chain) from
			// pinning its worker slot for the full client Timeout multiplied
			// by however many requests it would otherwise issue.
			runCtx, cancel := context.WithTimeout(ctx, checkBudget(c))
			defer cancel()
			// Sub-probe errors that the check chooses to swallow are still
			// surfaced through this reporter, so a flaky host leaves one
			// onError event per failure even when the check returns findings.
			runCtx = checks.WithLevel(runCtx, s.level)
			if s.onError != nil {
				runCtx = checks.WithReporter(runCtx, func(err error) {
					s.onError(target, c.Name(), err)
				})
			}
			found, err := c.Run(runCtx, s.client, s.scope, p)
			if err != nil {
				// ErrFetchAlreadyFailed means the crawler tried this URL
				// and got nothing - it already reported the failure once
				// via its own onError. Re-reporting per check would turn
				// one dead host into N noisy events with no new signal.
				if errors.Is(err, checks.ErrFetchAlreadyFailed) {
					return
				}
				if s.onError != nil {
					s.onError(target, c.Name(), err)
				}
				return
			}
			for _, f := range found {
				out <- f
			}
		}(c)
	}
	wg.Wait()
}

// checkBudget returns the per-check deadline to apply. A check that
// implements checks.Budgeted may opt up to a longer deadline; non-positive
// returns from Budget reuse DefaultBudget so a misconfigured opt-in can't
// silently disable the deadline.
func checkBudget(c checks.Check) time.Duration {
	if b, ok := c.(checks.Budgeted); ok {
		if d := b.Budget(); d > 0 {
			return d
		}
	}
	return checks.DefaultBudget
}

// fingerprint resolves the stack for p's host, or returns nil when
// fingerprinting is disabled or fails. A nil stack means "skip gating" -
// every check runs, which is the safer default than silently dropping a
// check because we couldn't reach the host.
func (s *Scanner) fingerprint(ctx context.Context, p page.Page) *fingerprint.Stack {
	if s.detector == nil {
		return nil
	}
	stack, err := s.detector.Detect(ctx, p)
	if err != nil {
		if s.onError != nil {
			s.onError(p.URL, "fingerprint", err)
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
