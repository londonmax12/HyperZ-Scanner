package scanner

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// stubOOBCheck records Run / Drain invocations and emits a configurable
// finding from Drain so the scanner-side OOB phase can be exercised
// without depending on the SSRF/XXE/SSTI implementations under test
// elsewhere.
type stubOOBCheck struct {
	name      string
	drainOut  []checks.Finding
	ranOnce   bool
	drainOnce bool
	oobAtRun  oob.Server
}

func (s *stubOOBCheck) Name() string        { return s.name }
func (s *stubOOBCheck) Level() checks.Level { return checks.LevelPassive }
func (s *stubOOBCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, _ page.Page) ([]checks.Finding, error) {
	s.ranOnce = true
	s.oobAtRun = checks.OOBFrom(ctx)
	return nil, nil
}
func (s *stubOOBCheck) Drain(ctx context.Context) []checks.Finding {
	s.drainOnce = true
	return s.drainOut
}

func TestScannerDrainsOOBChecksWhenServerAttached(t *testing.T) {
	stub := &stubOOBCheck{
		name: "stub-oob",
		drainOut: []checks.Finding{
			{Check: "stub-oob", Severity: checks.SeverityCritical, Title: "stub OOB finding"},
		},
	}
	srv := oob.NewBuiltin("127.0.0.1:0", "h")
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("oob start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	s := New(newNilClient(), []checks.Check{stub},
		WithOOB(srv),
		// Zero wait so the test doesn't pay the default 10s window.
		WithOOBWait(1*time.Millisecond),
	)
	got, err := runOne(context.Background(), s, "http://t")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !stub.ranOnce {
		t.Errorf("Run was never called")
	}
	if stub.oobAtRun == nil {
		t.Errorf("OOBFrom(ctx) was nil during Run; scanner should attach server to check context")
	}
	if !stub.drainOnce {
		t.Errorf("Drain was never called")
	}
	if len(got) != 1 || got[0].Title != "stub OOB finding" {
		t.Errorf("findings = %+v, want one drain finding", got)
	}
}

func TestScannerSkipsDrainWhenNoServer(t *testing.T) {
	stub := &stubOOBCheck{
		name:     "stub-oob",
		drainOut: []checks.Finding{{Title: "should not appear"}},
	}
	// No WithOOB option: scanner must not call Drain even though the
	// check implements OOBCheck. Otherwise blind findings would leak
	// from a check whose canaries were never minted.
	s := New(newNilClient(), []checks.Check{stub})
	got, err := runOne(context.Background(), s, "http://t")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if stub.drainOnce {
		t.Errorf("Drain should not run without --oob")
	}
	if len(got) != 0 {
		t.Errorf("findings = %+v, want none", got)
	}
}

func TestScannerSkipsDrainOnContextCancel(t *testing.T) {
	stub := &stubOOBCheck{
		name:     "stub-oob",
		drainOut: []checks.Finding{{Title: "should not appear"}},
	}
	srv := oob.NewBuiltin("127.0.0.1:0", "h")
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("oob start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	// Long wait makes ctx-cancel observable: the scanner should bail
	// out of the wait sleep without firing Drain. A canceled scan
	// shouldn't produce additional OOB findings - the operator gave up.
	s := New(newNilClient(), []checks.Check{stub},
		WithOOB(srv),
		WithOOBWait(5*time.Second),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := runOne(ctx, s, "http://t")
	// runOne propagates ctx.Err via ScanAll; that's expected.
	if err != context.Canceled && err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if stub.drainOnce {
		t.Errorf("Drain ran despite canceled ctx")
	}
	if len(got) != 0 {
		t.Errorf("findings = %+v, want none", got)
	}
}

// proveBuiltinReachable is a smoke check that the test process can
// actually issue a HTTP request to a Builtin listener bound on an
// ephemeral port. If this fails the higher-level OOB-flow tests would
// pass for the wrong reason (no hits to drain).
func TestBuiltinReachableFromTestProcess(t *testing.T) {
	srv := oob.NewBuiltin("127.0.0.1:0", "h")
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("oob start: %v", err)
	}
	defer srv.Stop(context.Background())
	c := srv.Register("smoke", nil)
	resp, err := http.Get("http://" + srv.LocalAddr() + "/" + c.Token)
	if err != nil {
		t.Fatalf("GET listener: %v", err)
	}
	resp.Body.Close()
	if got := srv.Hits(c.Token); len(got) != 1 {
		t.Errorf("want 1 smoke hit, got %d", len(got))
	}
}
