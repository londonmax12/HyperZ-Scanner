package scanner

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/londonmax12/hyperz/internal/browser"
	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
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
	hostBudget       int
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

// WithHostBudget caps total scan targets queued per host across the
// scan's lifetime. 0 (the default) means unlimited, which matches the
// pre-worklist behavior - every crawled page enters the queue without
// a host-level ceiling.
//
// The cap is the second-line defense against runaway discovery
// fanout: a self-loop break catches the trivial "check A emits a
// target check A then receives" case, but two distinct checks
// bouncing emissions off each other (A emits X, B emits Y, A emits
// Z, ...) still terminate on the host budget. Pick a value that
// comfortably exceeds a normal crawl's per-host page count - 5000 to
// 10000 is reasonable for most targets - so legitimate large sites
// are not capped while a fractal discovery cycle still hits the
// ceiling within bounded wall-clock.
func WithHostBudget(n int) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.hostBudget = n
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
	hasDeferred := len(twoPhase) > 0
	lastTier := core.TierActive
	if hasDeferred {
		lastTier = core.TierDeferred
	}

	// The worklist mediates dispatch with quiescence-based termination
	// AND cross-target tier ordering: a single producer pushes crawler-
	// origin pages at TierFingerprint, workers Pop the lowest-tier
	// target available and call scanTier (which runs ONLY that tier's
	// checks). After scanTier returns the worker re-pushes the same
	// target at tier+1, walking it through every tier band before
	// retiring it. The per-check Discoverer wired in scanTier pushes
	// any emitted discoveries back onto the queue at TierFingerprint
	// so a freshly-surfaced endpoint re-enters at the lowest tier and
	// still receives fingerprint / passive coverage before any active
	// check fires against it. The queue reports itself drained when
	// the producer signals SourceDone AND every accepted push at every
	// tier has had a matching Done call.
	//
	// TierDeferred is the absorbing point for the legacy two-phase
	// orchestration: when at least one TwoPhaseCheck is registered,
	// every target advances past TierActive to TierDeferred where the
	// worker re-fetches the page (Plant mutations may have rewritten
	// the body) and dispatches each TwoPhaseCheck's Detect. The
	// worklist's barrier guarantees every Plant has completed across
	// every target before the first Detect begins. Same-origin URLs
	// the plant responses surfaced ride a different path: Plant
	// emits them via core.DiscoverAt(ctx, t, TierDeferred), which
	// pushes the new target directly at TierDeferred so it skips
	// the lower tiers (no fresh Plant run, just the Detect re-fetch).
	//
	// pageByKey bridges the worklist's target.Target payload back to
	// the page.Page artifact the crawler captured AND caches the
	// fetched-on-demand page for discovery-origin targets across tier
	// advances. The producer stores the crawler page before pushing;
	// the worker Loads (does NOT delete) on each tier dispatch so
	// tiers 2..N reuse the same page artifact without re-fetching.
	// TierDeferred is the exception: the worker evicts the cache on
	// entry so materialize re-fetches a fresh body. The worker
	// deletes the entry after the final tier drains or when a tier
	// re-push is rejected (cancel / scope / budget) so dropped
	// advances do not leak map slots.
	queue := newWorklist(s.scope, 0)
	queue.withHostBudget(s.hostBudget)
	var pageByKey sync.Map

	go func() {
		defer queue.SourceDone()
		for {
			select {
			case <-ctx.Done():
				return
			case p, ok := <-pages:
				if !ok {
					return
				}
				t := target.Page(p.URL, "crawler")
				key := t.CanonicalKey()
				pageByKey.Store(key, p)
				if !queue.Push(ctx, t, core.TierFingerprint) {
					pageByKey.Delete(key)
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				t, tier, ok := queue.Pop(ctx)
				if !ok {
					return
				}
				// Plant may have mutated the body; force a re-fetch
				// for Detect by evicting the cache on TierDeferred
				// entry. The worklist barrier guarantees TierActive
				// has fully drained globally by the time this fires.
				if tier == core.TierDeferred {
					pageByKey.Delete(t.CanonicalKey())
				}
				p, materialized := s.materializePage(ctx, t, &pageByKey)
				if materialized {
					s.scanTier(ctx, t, tier, p, queue, out)
				}
				// Tier advance: re-push at tier+1 if more tiers remain
				// AND materialization succeeded. The "more tiers remain"
				// cutoff depends on whether the scan has any
				// TwoPhaseCheck registered - lastTier is TierDeferred
				// when one is, TierActive otherwise, so a single-phase
				// scan does not pay for an extra round-trip per target.
				if materialized && tier < lastTier {
					if !queue.Push(ctx, t, tier+1) {
						pageByKey.Delete(t.CanonicalKey())
					}
				} else {
					pageByKey.Delete(t.CanonicalKey())
				}
				queue.Done(tier)
			}
		}()
	}
	wg.Wait()

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

// fetchPhase2 issues a GET for rawurl and packages the response into a
// page.Page. The body is read up to phase2BodyCap; truncation is silent
// because Detect implementations search for short canary needles that
// land near the start of any storage UI long before that cap. Fetched is
// set so checks that gate on "did anyone try this URL" can read the
// usual signal.
//
// Kept after the two-phase fold-in because materializePage reuses it as
// its on-demand fetcher: discovery-origin KindPage / KindParam targets
// and crawler-origin targets at TierDeferred (where the body is
// re-fetched because Plant may have mutated it) both route through
// here.
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

// scanTier dispatches every applicable check at exactly `tier` against
// (t, p) in parallel and waits for the tier to drain before returning.
// The worker loop in ScanAll calls scanTier once per (target, tier)
// Pop and then re-pushes the same target at tier+1, so cross-target
// tier ordering is realized at the queue level: every tier-N item
// queued anywhere drains before workers begin dispatching the same
// target's tier-(N+1) work. Within a tier, checks run in parallel
// capped by checkConcurrency.
//
// When a check's Run returns, its findings are sent unconditionally:
// they already exist in memory, so we flush them even if ctx cancels
// mid-send. New checks are not scheduled after ctx cancels (the tier
// loop bails on ctx.Err()), so the post-cancel send burst is bounded
// by checks already in flight. The caller (the report side) must drain
// `out` until it closes or the senders will deadlock.
//
// A check that implements TwoPhaseCheck has its Plant method invoked
// at its declared tier (TierActive by default) and its Detect method
// invoked at TierDeferred. The scanner reserves Run for the legacy
// single-phase contract; TwoPhaseChecks never see Run during a
// scanner-driven scan.
//
// queue is the worklist the per-check Discoverer pushes into when a
// check surfaces a new scan target via core.Discover. When queue is
// nil (the test-helper path that drives scanTier without ScanAll) the
// discoverer is wired as a no-op so checks running without the
// dispatcher in place do not error out on emission.
func (s *Scanner) scanTier(ctx context.Context, t target.Target, tier core.Tier, p page.Page, queue *worklist, out chan<- core.Finding) {
	stack := s.fingerprint(ctx, p)
	targetURL := p.URL

	// sem caps in-flight checks for this tier dispatch. A nil sem
	// means no cap. Each scanTier call gets its own sem so the bound
	// is per-tier-dispatch, matching the pre-tier per-target behavior.
	var sem chan struct{}
	if s.checkConcurrency > 0 {
		sem = make(chan struct{}, s.checkConcurrency)
	}

	var checks []core.Check
	for _, c := range s.checks {
		// Tier filter goes first: scanTier is called once per (target,
		// tier) Pop, so a check whose tier does not match this Pop is
		// skipped silently. Putting the cheap, side-effect-free tier
		// match ahead of s.applies (which fires onSkip on a miss) also
		// keeps gated-check skip notifications at exactly one per
		// target, not one per tier visit.
		if !checkMatchesTier(c, tier) {
			continue
		}
		if !consumesKind(c, t.Kind) {
			continue
		}
		// Self-loop break is suppressed at TierDeferred: a
		// TwoPhaseCheck legitimately emits at TierDeferred from
		// Plant (TierActive) and consumes at TierDeferred via
		// Detect, which the loop-break heuristic would otherwise
		// flag as a same-check fan-out cycle. TierDeferred is
		// also the last tier, so there is no downstream loop
		// even when a non-two-phase check happens to declare it.
		if tier != core.TierDeferred && isSelfLoop(t, c) {
			continue
		}
		if !s.applies(c, stack, targetURL) {
			continue
		}
		checks = append(checks, c)
	}
	s.runTier(ctx, checks, tier, t, p, stack, sem, queue, out)
}

// checkMatchesTier reports whether c should dispatch when the worker
// has popped a target at the given tier. The normal case is the
// declared-tier match (TierActive by default). TwoPhaseCheck is a
// dual-tier exception: in addition to its declared tier (Plant), it
// also dispatches at TierDeferred (Detect). The runCheck helper picks
// the right entry point based on the dispatch tier.
func checkMatchesTier(c core.Check, tier core.Tier) bool {
	if tier == core.TierDeferred {
		if _, ok := c.(core.TwoPhaseCheck); ok {
			return true
		}
	}
	return checkTier(c) == tier
}

// checkTier returns the dispatch tier for c. Checks that do not
// implement core.Targeted default to TierActive, matching the
// pre-tier behavior where every catalog check ran as one batch at the
// active stage. A Targeted check that returns a tier outside the
// declared range is treated as TierActive so a misconfigured opt-in
// can't silently skip an otherwise-active check.
//
// TwoPhaseCheck is a wrinkle: its declared Tier() is the band where
// Plant runs (TierActive by default), but Detect runs at TierDeferred
// in addition. scanTier handles that with a TierDeferred special-case
// rather than threading it through checkTier, so this function
// continues to report the Plant-side tier.
func checkTier(c core.Check) core.Tier {
	tc, ok := c.(core.Targeted)
	if !ok {
		return core.TierActive
	}
	tier := tc.Tier()
	if tier < core.TierFingerprint || tier > core.TierDeferred {
		return core.TierActive
	}
	return tier
}

// runTier dispatches every check in checks in parallel (capped by sem)
// and waits for the tier to drain before returning. tier is passed
// through to runCheck so the per-check entry point can select Plant
// (lower tiers) vs Detect (TierDeferred) for TwoPhaseCheck.
func (s *Scanner) runTier(ctx context.Context, checks []core.Check, tier core.Tier, t target.Target, p page.Page, stack *fingerprint.Stack, sem chan struct{}, queue *worklist, out chan<- core.Finding) {
	if len(checks) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, c := range checks {
		if ctx.Err() != nil {
			break
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
			s.runCheck(ctx, c, tier, t, p, stack, queue, out)
		}(c)
	}
	wg.Wait()
}

// runCheck wraps a single check's Run / Plant / Detect invocation:
// builds the per-check context (deadline, level/stack/oob/browser/
// target/reporter/discoverer), routes a TwoPhaseCheck to Plant at its
// declared tier and Detect at TierDeferred, suppresses
// ErrFetchAlreadyFailed, surfaces other errors via onError, and
// flushes findings on the out channel. Carries the cancellation-flush
// contract (findings sent unconditionally once the entry point
// returns).
func (s *Scanner) runCheck(ctx context.Context, c core.Check, tier core.Tier, t target.Target, p page.Page, stack *fingerprint.Stack, queue *worklist, out chan<- core.Finding) {
	// Per-check deadline keeps a pathological Run (regex backtracking,
	// slow body read, weird redirect chain) from pinning its worker
	// slot for the full client Timeout multiplied by however many
	// requests it would otherwise issue.
	runCtx, cancel := context.WithTimeout(ctx, checkBudget(c))
	defer cancel()
	runCtx = core.WithLevel(runCtx, s.level)
	runCtx = core.WithStack(runCtx, stack)
	runCtx = core.WithOOB(runCtx, s.oobServer)
	runCtx = core.WithBrowser(runCtx, s.browserPool)
	runCtx = core.WithTarget(runCtx, t)
	targetURL := p.URL
	if s.onError != nil {
		runCtx = core.WithReporter(runCtx, func(err error) {
			s.onError(targetURL, c.Name(), err)
		})
	}
	// Per-check Discoverer: tag Origin with this check's name (so the
	// worklist's self-loop break and the scanOne kind/origin filter
	// both have the data they need) and push to the queue. A nil queue
	// degrades the discoverer to a no-op so test paths that bypass
	// ScanAll do not need to wire a worklist. Discoveries enter at
	// TierFingerprint so the new target walks through every tier
	// band - even when the emitter was an active-tier check, the
	// surface it surfaced still receives fingerprint and passive
	// coverage before the active tier reaches it.
	if queue != nil {
		checkName := c.Name()
		runCtx = core.WithDiscoverer(runCtx, func(disc target.Target, discTier core.Tier) {
			if disc.Origin == "" {
				disc.Origin = "check:" + checkName
			}
			if disc.Parent == "" {
				disc.Parent = t.CanonicalKey()
			}
			queue.Push(ctx, disc, discTier)
		})
	}
	// TwoPhaseCheck dispatch: at TierDeferred call Detect against the
	// freshly-fetched body the worker materialized after evicting the
	// cache; at every other tier call Plant so the check accumulates
	// its private state (canary->plant map, etc.) ahead of the
	// barrier. Run is reserved for callers that intentionally drive a
	// two-phase check single-phase (dry runs without phase-2 wiring)
	// and would otherwise double-fire findings here.
	runFn := c.Run
	if tp, ok := c.(core.TwoPhaseCheck); ok {
		if tier == core.TierDeferred {
			runFn = tp.Detect
		} else {
			runFn = tp.Plant
		}
	}
	found, err := runFn(runCtx, s.client, s.scope, p)
	if err != nil {
		// ErrFetchAlreadyFailed means the crawler tried this URL and
		// got nothing - it already reported the failure once via its
		// own onError. Re-reporting per check would turn one dead host
		// into N noisy events with no new signal.
		if errors.Is(err, core.ErrFetchAlreadyFailed) {
			return
		}
		if s.onError != nil {
			s.onError(targetURL, c.Name(), err)
		}
		return
	}
	for _, f := range found {
		out <- f
	}
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

// materializePage produces the page.Page artifact a worker dispatches
// against t and caches it in pageByKey so subsequent tier advances of
// the same target reuse the artifact rather than re-fetching. The
// worker is responsible for evicting the cache entry after the final
// tier (TierActive) completes; materializePage never evicts.
//
// Cache hit (any Kind): the producer stored the crawler page before
// the first push, or a prior tier dispatch stored a freshly-fetched
// discovery page. Return the cached value.
//
// Cache miss:
//
//   - KindPage / KindParam: GET t.URL via the same fetcher the
//     phase-2 detect pass uses. KindParam consumers read t.Param /
//     t.ParamLocation via core.TargetFrom(ctx) to scope their probes
//     to the named input; the fetched page.Page gives them the host
//     artifact (forms, baseline response) they compare payloads
//     against. The fetched page is Stored so tier advances reuse it.
//     Fetch errors report through onError and the target is skipped.
//   - KindEndpoint: returns a minimal page.Page with only URL
//     populated. The worker does NOT issue the declared method on
//     the check's behalf - the method may be destructive
//     (POST/PUT/DELETE) and the operator did not authorize the
//     worker to invoke it. Endpoint-consuming checks read t.Method,
//     t.ContentType via core.TargetFrom(ctx) and craft their own
//     probes against the URL.
//   - KindHost: also returns a minimal page.Page{URL: t.URL}.
//     KindHost represents a host-scoped scan unit (cert posture,
//     banner sweep, robots / sitemap discovery, vendor fingerprint
//     probes) where the check owns its request shape; pre-fetching
//     the host root would burn a GET the check may not want.
//     Consumers read t.URL (scheme://host) and craft their own
//     probes.
//
// Returns (page, true) on success or (zero, false) when no page can
// be produced.
func (s *Scanner) materializePage(ctx context.Context, t target.Target, pageByKey *sync.Map) (page.Page, bool) {
	if raw, loaded := pageByKey.Load(t.CanonicalKey()); loaded {
		p, _ := raw.(page.Page)
		return p, true
	}
	if t.URL == "" {
		return page.Page{}, false
	}
	switch t.Kind {
	case target.KindPage, target.KindParam:
		p, err := s.fetchPhase2(ctx, t.URL)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return page.Page{}, false
			}
			if s.onError != nil {
				s.onError(t.URL, "discovery-fetch", err)
			}
			return page.Page{}, false
		}
		pageByKey.Store(t.CanonicalKey(), p)
		return p, true
	case target.KindEndpoint, target.KindHost:
		p := page.Page{URL: t.URL}
		pageByKey.Store(t.CanonicalKey(), p)
		return p, true
	}
	return page.Page{}, false
}

// consumesKind reports whether c accepts dispatch against a target of
// kind k. Checks that do not implement core.Targeted default to
// KindPage only, preserving pre-worklist behavior where every check
// ran against every crawled Page. A Targeted check returning an empty
// Consumes list is treated the same as the default (permissive on
// KindPage); a non-empty list is the explicit allow-list.
func consumesKind(c core.Check, k target.Kind) bool {
	tc, ok := c.(core.Targeted)
	if !ok {
		return k == target.KindPage
	}
	kinds := tc.Consumes()
	if len(kinds) == 0 {
		return k == target.KindPage
	}
	for _, kk := range kinds {
		if kk == k {
			return true
		}
	}
	return false
}

// isSelfLoop reports whether dispatching c against t would re-deliver
// to the check that emitted t. The emitting Discoverer tags
// Origin = "check:<name>" before pushing; matching that against the
// dispatch candidate breaks the most common loop (a check whose
// emission lands on its own consume kind). Two distinct checks
// emitting into each other are not blocked here - the worklist's
// per-host budget catches that runaway.
func isSelfLoop(t target.Target, c core.Check) bool {
	return t.Origin != "" && t.Origin == "check:"+c.Name()
}
