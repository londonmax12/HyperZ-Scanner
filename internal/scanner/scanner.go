package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/londonmax12/hyperz/internal/browser"
	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// phase2BodyCap bounds the re-fetched body the scanner reads during phase 2.
// Sized between the per-check default (64 KiB) and the crawler's 5 MiB cap:
// detect pages that list many stored comments / posts can be long, but we
// only need enough body to find a canary needle, not the full document.
const phase2BodyCap = 512 << 10

type Scanner struct {
	client           *httpclient.Client
	checks           []core.Check
	scope            *scope.Scope
	detector         *fingerprint.Detector
	concurrency      int
	checkConcurrency int
	level            core.Level
	oobServer        oob.Server
	oobWait          time.Duration
	browserPool      browser.Pool
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
// scanner can attach it to each check's ctx via core.WithLevel. Checks that
// want to scale their behavior (e.g. fewer probes at default, full sweep at
// aggressive) read it via core.LevelFrom. The default (LevelDefault) is the
// conservative choice when the option isn't set.
func WithLevel(lvl core.Level) Option {
	return func(s *Scanner) { s.level = lvl }
}

// WithOOB attaches an OOB callback server. Checks that implement
// core.OOBCheck read it via core.OOBFrom to mint canaries during
// the active phase; after phase 1 (and phase 2, when present) drains,
// the scanner waits WithOOBWait and then calls Drain on each OOBCheck.
// Nil server (the default) disables the OOB pipeline entirely - blind
// paths in the catalog become no-ops.
func WithOOB(srv oob.Server) Option {
	return func(s *Scanner) { s.oobServer = srv }
}

// WithOOBWait sets the post-scan delay before draining OOB hits. Late
// callbacks (a target's async fetch queue, a slow DNS resolver round
// trip, a job that runs the smuggled URL after the response) routinely
// arrive seconds after the probe; the wait pulls those in before the
// drain pass closes the findings channel. Defaults to defaultOOBWait
// when unset or non-positive.
func WithOOBWait(d time.Duration) Option {
	return func(s *Scanner) {
		if d > 0 {
			s.oobWait = d
		}
	}
}

// WithBrowser attaches a headless-browser pool. Checks that need runtime
// JS execution (dom-xss, future client-side prototype-pollution chains)
// read it via core.BrowserFrom. Nil pool (the default) disables the
// JS pipeline entirely - runtime-execution paths in the catalog become
// no-ops, matching the contract those checks expose. The scanner does
// not Close the pool; lifetime belongs to the caller that built it.
func WithBrowser(pool browser.Pool) Option {
	return func(s *Scanner) { s.browserPool = pool }
}

// defaultOOBWait is the post-scan delay applied when --oob is on but
// --oob-wait was not set. Tuned around blind SSRF / blind XXE response
// latencies on real targets: most callbacks land within a few seconds
// of the probe, but async fetchers (webhook queues, fetch jobs that
// run on a cron) commonly delay tens of seconds. 10s balances catching
// the long tail against keeping scan wall-clock low.
const defaultOOBWait = 10 * time.Second

func New(client *httpclient.Client, c []core.Check, opts ...Option) *Scanner {
	s := &Scanner{client: client, checks: c, concurrency: 8, level: core.LevelDefault, oobWait: defaultOOBWait}
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
//
// When the registered check set includes any TwoPhaseCheck, ScanAll runs a
// second pass after the main `pages` channel drains: every in-scope URL the
// scanner saw during phase 1 is unioned with each TwoPhaseCheck's
// DetectURLs(), re-fetched, and handed to Detect. Phase-2 findings flow
// through the same `out` channel before it is closed. The second pass is
// skipped if ctx is already canceled, but is otherwise unconditional - a
// caller that wants the legacy single-pass behavior should simply register
// no TwoPhaseCheck implementations.
func (s *Scanner) ScanAll(ctx context.Context, pages <-chan page.Page, out chan<- core.Finding) error {
	defer close(out)

	twoPhase := s.twoPhaseChecks()

	// visited retains the in-scope URLs phase 1 saw so phase 2 can re-fetch
	// them. Only populated when at least one TwoPhaseCheck is registered so
	// single-pass scans don't pay for the bookkeeping. The map is mutated
	// from every scan worker so reads/writes are mutex-guarded.
	var visitedMu sync.Mutex
	var visited map[string]struct{}
	if len(twoPhase) > 0 {
		visited = map[string]struct{}{}
	}

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
					if visited != nil {
						if key := visitedKey(p.URL); key != "" && s.scopeAllowsURL(key) {
							visitedMu.Lock()
							visited[key] = struct{}{}
							visitedMu.Unlock()
						}
					}
					s.scanOne(ctx, p, out)
				}
			}
		}()
	}
	wg.Wait()

	if len(twoPhase) > 0 && ctx.Err() == nil {
		s.runPhase2(ctx, twoPhase, visited, out)
	}
	if s.oobServer != nil && ctx.Err() == nil {
		s.runOOBDrain(ctx, out)
	}
	return ctx.Err()
}

// oobChecks returns the subset of registered checks that implement
// OOBCheck. Computed once per ScanAll to keep the drain dispatch
// branch-free.
func (s *Scanner) oobChecks() []core.OOBCheck {
	var out []core.OOBCheck
	for _, c := range s.checks {
		if oc, ok := c.(core.OOBCheck); ok {
			out = append(out, oc)
		}
	}
	return out
}

// runOOBDrain waits the configured oobWait for late callbacks to land,
// then asks every OOBCheck to translate its server-side registrations
// into findings. Findings flow through the same out channel as phase
// 1; the caller (ScanAll) closes it after this returns.
//
// The wait is interruptible: ctx cancel skips both the sleep and the
// drain, since a canceled scan should not produce additional findings.
func (s *Scanner) runOOBDrain(ctx context.Context, out chan<- core.Finding) {
	oobChecks := s.oobChecks()
	if len(oobChecks) == 0 {
		return
	}
	wait := s.oobWait
	if wait <= 0 {
		wait = defaultOOBWait
	}
	select {
	case <-time.After(wait):
	case <-ctx.Done():
		return
	}
	for _, c := range oobChecks {
		if ctx.Err() != nil {
			return
		}
		drainCtx := core.WithLevel(ctx, s.level)
		drainCtx = core.WithOOB(drainCtx, s.oobServer)
		if s.onError != nil {
			drainCtx = core.WithReporter(drainCtx, func(err error) {
				s.onError("oob-drain", c.Name(), err)
			})
		}
		for _, f := range c.Drain(drainCtx) {
			out <- f
		}
	}
}

// twoPhaseChecks returns the subset of registered checks that implement
// TwoPhaseCheck. Computed once per ScanAll so the per-page hot path doesn't
// re-interface-assert N times.
func (s *Scanner) twoPhaseChecks() []core.TwoPhaseCheck {
	var out []core.TwoPhaseCheck
	for _, c := range s.checks {
		if tp, ok := c.(core.TwoPhaseCheck); ok {
			out = append(out, tp)
		}
	}
	return out
}

// runPhase2 fans out the detect pass after phase 1 has fully drained. It
// computes the in-scope URL set (visited union DetectURLs from every
// two-phase check), re-fetches each URL via the same client and rate
// limiter phase 1 uses, then calls Detect on each (check, re-fetched
// page) pair. Findings flow through the same `out` channel; the caller
// (ScanAll) closes it after this returns.
//
// Robots is intentionally not re-checked here: a URL only enters the
// visited set after the crawler already cleared it. Scope is mandatory
// because DetectURLs can surface same-origin pages the operator never
// authorized (an off-path link discovered in a plant response).
func (s *Scanner) runPhase2(ctx context.Context, twoPhase []core.TwoPhaseCheck, visited map[string]struct{}, out chan<- core.Finding) {
	detectSet := make(map[string]struct{}, len(visited))
	for u := range visited {
		detectSet[u] = struct{}{}
	}
	for _, c := range twoPhase {
		for _, raw := range c.DetectURLs() {
			key := visitedKey(raw)
			if key == "" {
				continue
			}
			if !s.scopeAllowsURL(key) {
				continue
			}
			detectSet[key] = struct{}{}
		}
	}
	if len(detectSet) == 0 {
		return
	}

	urls := make([]string, 0, len(detectSet))
	for u := range detectSet {
		urls = append(urls, u)
	}
	// Stable order so re-runs against the same target produce a
	// deterministic request stream - matters for evidence reproducibility
	// and for tests that assert on phase-2 fetch order.
	sort.Strings(urls)

	// One semaphore caps phase-2 fetch parallelism. Reuses the same
	// concurrency knob as phase 1 so an operator who set --concurrency=4
	// isn't surprised by phase 2 fanning out wider.
	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			p, err := s.fetchPhase2(ctx, u)
			if err != nil {
				// ctx cancel mid-fetch is the expected drain path; don't
				// flood onError with one entry per pending URL on a
				// canceled scan.
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return
				}
				if s.onError != nil {
					s.onError(u, "phase-2-fetch", err)
				}
				return
			}
			s.detectOne(ctx, twoPhase, p, out)
		}(u)
	}
	wg.Wait()
}

// detectOne fingerprints the re-fetched p then dispatches Detect across
// every applicable two-phase check. Mirrors scanOne's structure (per-check
// budget, level/stack/reporter context, ErrFetchAlreadyFailed suppression,
// flush-on-cancel send loop) so phase 2 inherits the same operator-visible
// contract as phase 1.
func (s *Scanner) detectOne(ctx context.Context, twoPhase []core.TwoPhaseCheck, p page.Page, out chan<- core.Finding) {
	stack := s.fingerprint(ctx, p)
	target := p.URL

	var sem chan struct{}
	if s.checkConcurrency > 0 {
		sem = make(chan struct{}, s.checkConcurrency)
	}

	var wg sync.WaitGroup
	for _, c := range twoPhase {
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
		go func(c core.TwoPhaseCheck) {
			defer wg.Done()
			if sem != nil {
				defer func() { <-sem }()
			}
			runCtx, cancel := context.WithTimeout(ctx, checkBudget(c))
			defer cancel()
			runCtx = core.WithLevel(runCtx, s.level)
			runCtx = core.WithStack(runCtx, stack)
			runCtx = core.WithOOB(runCtx, s.oobServer)
			runCtx = core.WithBrowser(runCtx, s.browserPool)
			if s.onError != nil {
				runCtx = core.WithReporter(runCtx, func(err error) {
					s.onError(target, c.Name(), err)
				})
			}
			found, err := c.Detect(runCtx, s.client, s.scope, p)
			if err != nil {
				if errors.Is(err, core.ErrFetchAlreadyFailed) {
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

// fetchPhase2 issues a GET for rawurl and packages the response into a
// page.Page. The body is read up to phase2BodyCap; truncation is silent
// because Detect implementations search for short canary needles that
// land near the start of any storage UI long before that cap. Fetched is
// set so checks that gate on "did anyone try this URL" can read the
// usual signal.
func (s *Scanner) fetchPhase2(ctx context.Context, rawurl string) (page.Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return page.Page{}, err
	}
	resp, err := s.client.Do(ctx, req)
	if err != nil {
		return page.Page{}, err
	}
	defer resp.Body.Close()
	body, _, _ := httpclient.ReadBodyCapped(resp, phase2BodyCap)
	return page.Page{
		URL:     rawurl,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    body,
		Fetched: true,
	}, nil
}

// visitedKey returns the canonical form of rawurl used to dedupe the
// phase-2 detect set: the URL with its fragment stripped (anchors don't
// alter what the server returns). An unparseable or schemeless URL
// returns "" so callers can drop it without poisoning the set.
func visitedKey(rawurl string) string {
	if rawurl == "" {
		return ""
	}
	u, err := url.Parse(rawurl)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

// scopeAllowsURL is a string-input wrapper around scope.Allows so the
// phase-2 pipeline can filter without each callsite re-parsing rawurl.
// A nil scope (the unconstrained default) permits everything, matching
// the contract in core.Check.Run.
func (s *Scanner) scopeAllowsURL(rawurl string) bool {
	if s.scope == nil {
		return true
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	return s.scope.Allows(u)
}

// scanOne fingerprints p then runs every applicable check in parallel.
// When a check's Run returns, its findings are sent unconditionally - they
// already exist in memory, so we flush them even if ctx cancels mid-send.
// New checks are not scheduled after ctx cancels (the loop bails on
// ctx.Err()), so the post-cancel send burst is bounded by checks already
// in flight. The caller (the report side) must drain `out` until it closes
// or the senders will deadlock.
//
// A check that implements TwoPhaseCheck has its Plant method invoked here
// in place of Run - the scanner reserves Run for the legacy single-phase
// contract and uses Plant during phase 1 so the check can carry private
// state into Detect.
func (s *Scanner) scanOne(ctx context.Context, p page.Page, out chan<- core.Finding) {
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
		go func(c core.Check) {
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
			runCtx = core.WithLevel(runCtx, s.level)
			runCtx = core.WithStack(runCtx, stack)
			runCtx = core.WithOOB(runCtx, s.oobServer)
			runCtx = core.WithBrowser(runCtx, s.browserPool)
			if s.onError != nil {
				runCtx = core.WithReporter(runCtx, func(err error) {
					s.onError(target, c.Name(), err)
				})
			}
			// A two-phase check receives Plant during phase 1; its Run
			// is reserved for callers that intentionally drive it
			// single-phase (e.g. dry runs without phase-2 wiring) and
			// would otherwise double-fire findings here.
			runFn := c.Run
			if tp, ok := c.(core.TwoPhaseCheck); ok {
				runFn = tp.Plant
			}
			found, err := runFn(runCtx, s.client, s.scope, p)
			if err != nil {
				// ErrFetchAlreadyFailed means the crawler tried this URL
				// and got nothing - it already reported the failure once
				// via its own onError. Re-reporting per check would turn
				// one dead host into N noisy events with no new signal.
				if errors.Is(err, core.ErrFetchAlreadyFailed) {
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
// implements core.Budgeted may opt up to a longer deadline; non-positive
// returns from Budget reuse DefaultBudget so a misconfigured opt-in can't
// silently disable the deadline.
func checkBudget(c core.Check) time.Duration {
	if b, ok := c.(core.Budgeted); ok {
		if d := b.Budget(); d > 0 {
			return d
		}
	}
	return core.DefaultBudget
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
func (s *Scanner) applies(c core.Check, stack *fingerprint.Stack, target string) bool {
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
