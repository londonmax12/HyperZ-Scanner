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

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/fingerprint"
	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/scope"
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
func (s *stubCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, target string) ([]checks.Finding, error) {
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
		f.Target = target
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

	targets := make(chan string, 3)
	for _, u := range []string{"http://a", "http://b", "http://c"} {
		targets <- u
	}
	close(targets)
	out := make(chan checks.Finding, 16)
	if err := s.ScanAll(context.Background(), targets, out); err != nil {
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

	targets := make(chan string, 1)
	targets <- "http://t"
	close(targets)
	// Unbuffered so the sender parks between each send - that's the window
	// where the old code dropped findings on cancel.
	out := make(chan checks.Finding)

	scanDone := make(chan error, 1)
	go func() { scanDone <- s.ScanAll(ctx, targets, out) }()

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

	targets := make(chan string, 5)
	for i := 0; i < 5; i++ {
		targets <- "http://t"
	}
	close(targets)
	out := make(chan checks.Finding, 16)
	err := s.ScanAll(ctx, targets, out)
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

func TestScanWithoutFingerprintAlwaysRunsGatedChecks(t *testing.T) {
	// No detector wired → AppliesTo must not be consulted, so a check that
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
