package scanner

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonball/hyperz/internal/checks"
	"github.com/londonball/hyperz/internal/httpclient"
)

// stubCheck records every Run invocation and returns a configurable result.
type stubCheck struct {
	name     string
	findings []checks.Finding
	err      error
	delay    time.Duration
	hits     atomic.Int64
}

func (s *stubCheck) Name() string      { return s.name }
func (s *stubCheck) Mode() checks.Mode { return checks.ModePassive }
func (s *stubCheck) Run(ctx context.Context, _ *httpclient.Client, target string) ([]checks.Finding, error) {
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

func TestScanSingleTargetCollectsFindings(t *testing.T) {
	c := &stubCheck{
		name: "stub",
		findings: []checks.Finding{
			{Check: "stub", Severity: checks.SeverityLow, Title: "low"},
			{Check: "stub", Severity: checks.SeverityHigh, Title: "high"},
		},
	}
	s := New(newNilClient(), []checks.Check{c})
	got, err := s.Scan(context.Background(), "http://t")
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
	findings, err := s.Scan(context.Background(), "http://t")
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

func TestScanMultipleChecksParallel(t *testing.T) {
	a := &stubCheck{name: "a", findings: []checks.Finding{{Title: "fa"}}}
	b := &stubCheck{name: "b", findings: []checks.Finding{{Title: "fb"}}}
	s := New(newNilClient(), []checks.Check{a, b})
	got, err := s.Scan(context.Background(), "http://t")
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
