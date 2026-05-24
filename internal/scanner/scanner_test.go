package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// stubCheck records every Run invocation and returns a configurable result.
type stubCheck struct {
	name     string
	findings []checks.Finding
	err      error
	delay    time.Duration
	hits     atomic.Int64
}

func (s *stubCheck) Name() string        { return s.name }
func (s *stubCheck) Level() checks.Level { return checks.LevelPassive }
func (s *stubCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]checks.Finding, error) {
	s.hits.Add(1)
	if s.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.delay):
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	out := make([]checks.Finding, len(s.findings))
	for i, f := range s.findings {
		f.Target = p.URL
		out[i] = f
	}
	return out, nil
}

func newNilClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{Timeout: time.Second, UserAgent: "test"})
}

// runOne drives the scanner against a single target via the streaming
// ScanAll API, collecting findings into a slice for assertion convenience.
// Production code uses ScanAll directly; this helper exists so tests don't
// have to reproduce the channel boilerplate.
func runOne(ctx context.Context, s *Scanner, target string) ([]checks.Finding, error) {
	pages := make(chan page.Page, 1)
	pages <- page.FromURL(target)
	close(pages)

	out := make(chan checks.Finding, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- s.ScanAll(ctx, pages, out) }()

	var all []checks.Finding
	for f := range out {
		all = append(all, f)
	}
	return all, <-errCh
}

func TestScanSingleTargetCollectsFindings(t *testing.T) {
	c := &stubCheck{
		name: "stub",
		findings: []checks.Finding{
			{Check: "stub", Severity: checks.SeverityLow, Title: "low"},
			{Check: "stub", Severity: checks.SeverityHigh, Title: "high"},
		},
	}
	s := New(newNilClient(), []checks.Check{c})
	got, err := runOne(context.Background(), s,"http://t")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	for _, f := range got {
		if f.Target != "http://t" {
			t.Errorf("target = %q, want http://t", f.Target)
		}
	}
}

func TestScanAllRunsCheckPerTarget(t *testing.T) {
	c := &stubCheck{name: "stub", findings: []checks.Finding{{Title: "f"}}}
	s := New(newNilClient(), []checks.Check{c}, WithConcurrency(4))

	pages := make(chan page.Page, 3)
	for _, u := range []string{"http://a", "http://b", "http://c"} {
		pages <- page.FromURL(u)
	}
	close(pages)
	out := make(chan checks.Finding, 16)
	if err := s.ScanAll(context.Background(), pages, out); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	var findings []checks.Finding
	for f := range out {
		findings = append(findings, f)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	if c.hits.Load() != 3 {
		t.Fatalf("check hits = %d, want 3", c.hits.Load())
	}
}

func TestScanErrorHandlerInvoked(t *testing.T) {
	wantErr := errors.New("boom")
	c := &stubCheck{name: "stub", err: wantErr}
	var (
		mu      sync.Mutex
		calls   int
		gotTgt  string
		gotName string
	)
	s := New(newNilClient(), []checks.Check{c},
		WithErrorHandler(func(target, check string, err error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			gotTgt = target
			gotName = check
		}),
	)
	findings, err := runOne(context.Background(), s,"http://t")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || gotTgt != "http://t" || gotName != "stub" {
		t.Fatalf("error handler calls=%d tgt=%q name=%q", calls, gotTgt, gotName)
	}
}

// TestScanSuppressesFetchAlreadyFailed pins the contract that
// checks.ErrFetchAlreadyFailed is a quiet skip, not an error worth
// surfacing. The crawler already reported the original network failure
// once via its own onError; firing the scanner's per-check reporter
// N times for the same dead URL would just be noise.
func TestScanSuppressesFetchAlreadyFailed(t *testing.T) {
	c := &stubCheck{name: "stub", err: checks.ErrFetchAlreadyFailed}
	var calls atomic.Int64
	s := New(newNilClient(), []checks.Check{c},
		WithErrorHandler(func(target, check string, err error) {
			calls.Add(1)
		}),
	)
	findings, err := runOne(context.Background(), s, "http://dead")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings on suppressed-error path, want 0", len(findings))
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("error handler fired %d times for ErrFetchAlreadyFailed; want 0 (crawler already reported it)", n)
	}
}

// TestScanCancellationFlushesInFlightFindings pins the contract that once a
// check's Run has returned, all of its findings reach the reporter; even if
// ctx cancels while the per-finding send loop is mid-flight. Before the fix
// the send loop selected on ctx.Done(), so a cancel between sends silently
// dropped any remaining findings from that check.
func TestScanCancellationFlushesInFlightFindings(t *testing.T) {
	const n = 10
	findings := make([]checks.Finding, n)
	for i := range findings {
		findings[i] = checks.Finding{Check: "many", Title: fmt.Sprintf("f%d", i)}
	}
	c := &stubCheck{name: "many", findings: findings}
	s := New(newNilClient(), []checks.Check{c}, WithConcurrency(1))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pages := make(chan page.Page, 1)
	pages <- page.FromURL("http://t")
	close(pages)
	// Unbuffered so the sender parks between each send - that's the window
	// where the old code dropped findings on cancel.
	out := make(chan checks.Finding)

	scanDone := make(chan error, 1)
	go func() { scanDone <- s.ScanAll(ctx, pages, out) }()

	var got []checks.Finding
	got = append(got, <-out)
	got = append(got, <-out)
	// Sender is now parked on the third send. Cancel; the contract is that
	// the remaining 8 findings still arrive because the check already ran.
	cancel()
	for f := range out {
		got = append(got, f)
	}
	if len(got) != n {
		t.Fatalf("got %d findings, want %d (in-flight findings dropped on cancel)", len(got), n)
	}
	if err := <-scanDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanAll err = %v, want context.Canceled", err)
	}
}

func TestScanContextCancellationStopsWork(t *testing.T) {
	c := &stubCheck{name: "slow", delay: 200 * time.Millisecond,
		findings: []checks.Finding{{Title: "x"}}}
	s := New(newNilClient(), []checks.Check{c}, WithConcurrency(2))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled

	pages := make(chan page.Page, 5)
	for i := 0; i < 5; i++ {
		pages <- page.FromURL("http://t")
	}
	close(pages)
	out := make(chan checks.Finding, 16)
	err := s.ScanAll(ctx, pages, out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanAll err = %v, want context.Canceled", err)
	}
	// Drain to ensure out is closed.
	for range out {
	}
}

func TestScanConcurrencyOptionRespected(t *testing.T) {
	// Default concurrency=8. WithConcurrency(0) is ignored; WithConcurrency(3)
	// should apply.
	c := &stubCheck{name: "stub"}
	s := New(newNilClient(), []checks.Check{c}, WithConcurrency(0))
	if s.concurrency != 8 {
		t.Fatalf("default concurrency = %d, want 8", s.concurrency)
	}
	s = New(newNilClient(), []checks.Check{c}, WithConcurrency(3))
	if s.concurrency != 3 {
		t.Fatalf("concurrency = %d, want 3", s.concurrency)
	}
}

// stubGatedCheck implements fingerprint.StackGated and records whether it
// was run. Use it to verify the scanner consults AppliesTo.
type stubGatedCheck struct {
	stubCheck
	wantValue string // e.g. "wordpress"; check applies iff stack.Matches(wantValue)
}

func (s *stubGatedCheck) AppliesTo(stack *fingerprint.Stack) bool {
	return stack.Matches(s.wantValue)
}

func TestScanGatedCheckRunsWhenStackMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<meta name="generator" content="WordPress 6.4">`))
	}))
	defer srv.Close()

	client := newNilClient()
	det := fingerprint.New(client)
	gated := &stubGatedCheck{
		stubCheck: stubCheck{name: "wp", findings: []checks.Finding{{Title: "wp-only"}}},
		wantValue: "wordpress",
	}
	s := New(client, []checks.Check{gated}, WithFingerprint(det))

	got, err := runOne(context.Background(), s,srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 (gated check should have fired against WP)", len(got))
	}
	if gated.hits.Load() != 1 {
		t.Fatalf("gated check hits = %d, want 1", gated.hits.Load())
	}
}

func TestScanGatedCheckSkippedWhenStackDoesNotMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Plain nginx response, no WordPress signals.
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newNilClient()
	det := fingerprint.New(client)
	gated := &stubGatedCheck{
		stubCheck: stubCheck{name: "wp", findings: []checks.Finding{{Title: "wp-only"}}},
		wantValue: "wordpress",
	}
	var skips atomic.Int64
	s := New(client, []checks.Check{gated},
		WithFingerprint(det),
		WithSkipHandler(func(target, check, reason string) { skips.Add(1) }),
	)

	got, err := runOne(context.Background(), s,srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d findings, want 0 (gated check should be skipped)", len(got))
	}
	if gated.hits.Load() != 0 {
		t.Fatalf("gated check hits = %d, want 0", gated.hits.Load())
	}
	if skips.Load() != 1 {
		t.Fatalf("skip handler calls = %d, want 1", skips.Load())
	}
}

// stackObservingCheck records the *fingerprint.Stack attached to its
// runCtx. Used to verify the scanner propagates the detected stack
// through checks.WithStack so intra-check filters (content-discovery's
// per-entry gating) can read it.
type stackObservingCheck struct {
	stubCheck
	gotStack *fingerprint.Stack
}

func (s *stackObservingCheck) Run(ctx context.Context, c *httpclient.Client, sc *scope.Scope, p page.Page) ([]checks.Finding, error) {
	s.gotStack = checks.StackFrom(ctx)
	return s.stubCheck.Run(ctx, c, sc, p)
}

func TestScanAttachesStackToCheckContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.7")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newNilClient()
	det := fingerprint.New(client)
	obs := &stackObservingCheck{stubCheck: stubCheck{name: "obs"}}
	s := New(client, []checks.Check{obs}, WithFingerprint(det))

	if _, err := runOne(context.Background(), s, srv.URL); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if obs.gotStack == nil {
		t.Fatalf("check observed nil stack; scanner did not call WithStack")
	}
	if obs.gotStack.Server != "apache" {
		t.Errorf("observed stack.Server = %q, want apache", obs.gotStack.Server)
	}
}

func TestScanWithoutFingerprintLeavesStackNil(t *testing.T) {
	// Without WithFingerprint wired, scanOne passes a nil stack into
	// WithStack, and StackFrom must return nil so intra-check filters
	// fall back to their permissive (no fingerprint) branch.
	obs := &stackObservingCheck{stubCheck: stubCheck{name: "obs"}}
	s := New(newNilClient(), []checks.Check{obs})
	if _, err := runOne(context.Background(), s, "http://t"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if obs.gotStack != nil {
		t.Errorf("expected nil stack without detector, got %+v", obs.gotStack)
	}
}

func TestScanWithoutFingerprintAlwaysRunsGatedChecks(t *testing.T) {
	// No detector wired â†’ AppliesTo must not be consulted, so a check that
	// would reject every stack still runs.
	gated := &stubGatedCheck{
		stubCheck: stubCheck{name: "wp", findings: []checks.Finding{{Title: "x"}}},
		wantValue: "wordpress",
	}
	s := New(newNilClient(), []checks.Check{gated})
	got, err := runOne(context.Background(), s,"http://example.invalid")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || gated.hits.Load() != 1 {
		t.Fatalf("expected gated check to run when no detector wired; findings=%d hits=%d",
			len(got), gated.hits.Load())
	}
}

// budgetedCheck records the deadline it observed and is used to verify the
// scanner wraps Run's ctx with a per-check deadline.
type budgetedCheck struct {
	stubCheck
	budget       time.Duration
	gotDeadline  bool
	gotRemaining time.Duration
}

func (b *budgetedCheck) Budget() time.Duration { return b.budget }
func (b *budgetedCheck) Run(ctx context.Context, c *httpclient.Client, s *scope.Scope, p page.Page) ([]checks.Finding, error) {
	if dl, ok := ctx.Deadline(); ok {
		b.gotDeadline = true
		b.gotRemaining = time.Until(dl)
	}
	return b.stubCheck.Run(ctx, c, s, p)
}

func TestScanAppliesPerCheckDeadline(t *testing.T) {
	// A check that doesn't implement Budgeted still gets DefaultBudget; a
	// check that opts up gets its declared budget. The deadline must come
	// from the scanner-attached timeout, not the parent ctx (which has none).
	def := &stubCheck{name: "default"}
	defObs := &observingCheck{stubCheck: def}
	opt := &budgetedCheck{
		stubCheck: stubCheck{name: "opt"},
		budget:    5 * time.Minute,
	}
	s := New(newNilClient(), []checks.Check{defObs, opt})
	if _, err := runOne(context.Background(), s, "http://t"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !defObs.gotDeadline {
		t.Fatalf("default check got no deadline; scanner did not wrap runCtx")
	}
	if got := defObs.gotRemaining; got <= 0 || got > checks.DefaultBudget {
		t.Fatalf("default check remaining = %v, want (0, %v]", got, checks.DefaultBudget)
	}
	if !opt.gotDeadline {
		t.Fatalf("budgeted check got no deadline")
	}
	if got := opt.gotRemaining; got <= checks.DefaultBudget || got > opt.budget {
		t.Fatalf("budgeted check remaining = %v, want (%v, %v]", got, checks.DefaultBudget, opt.budget)
	}
}

// observingCheck snapshots the ctx deadline it was handed. Used to verify
// that even checks that don't implement Budgeted get the scanner's default
// deadline applied.
type observingCheck struct {
	*stubCheck
	gotDeadline  bool
	gotRemaining time.Duration
}

func (o *observingCheck) Run(ctx context.Context, c *httpclient.Client, s *scope.Scope, p page.Page) ([]checks.Finding, error) {
	if dl, ok := ctx.Deadline(); ok {
		o.gotDeadline = true
		o.gotRemaining = time.Until(dl)
	}
	return o.stubCheck.Run(ctx, c, s, p)
}

func TestScanMultipleChecksParallel(t *testing.T) {
	a := &stubCheck{name: "a", findings: []checks.Finding{{Title: "fa"}}}
	b := &stubCheck{name: "b", findings: []checks.Finding{{Title: "fb"}}}
	s := New(newNilClient(), []checks.Check{a, b})
	got, err := runOne(context.Background(), s,"http://t")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.Title] = true
	}
	if !seen["fa"] || !seen["fb"] {
		t.Fatalf("missing finding(s): %v", seen)
	}
}
