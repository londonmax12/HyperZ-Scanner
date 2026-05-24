package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestSQLiTimeName(t *testing.T) {
	if got := (SQLiTime{}).Name(); got != "sqli-time" {
		t.Fatalf("Name = %q, want sqli-time", got)
	}
}

func TestSQLiTimeLevel(t *testing.T) {
	if got := (SQLiTime{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

func TestSQLiTimeBudget(t *testing.T) {
	// Confirms the Budgeted interface is honored - DefaultBudget (60s)
	// is too short for a check that spends real wall time on sleeps.
	if got := (SQLiTime{}).Budget(); got <= DefaultBudget {
		t.Errorf("Budget = %v, want > DefaultBudget (%v)", got, DefaultBudget)
	}
}

// withTestSleep dials the production sleep down to a test-friendly
// value and restores it on cleanup. Sub-second won't work because the
// payload catalog uses integer-second {{SLEEP}} substitution, so 1s is
// the floor.
func withTestSleep(t *testing.T) {
	t.Helper()
	origSleep := sqliTimeSleep
	origMargin := sqliTimeMargin
	sqliTimeSleep = 1 * time.Second
	sqliTimeMargin = 0.5
	t.Cleanup(func() {
		sqliTimeSleep = origSleep
		sqliTimeMargin = origMargin
	})
}

// sleepyMySQLHandler simulates a backend that concatenates `id` into a
// SQL statement and actually runs MySQL SLEEP(): any payload containing
// `SLEEP(<N>)` causes a real time.Sleep of N seconds before responding.
func sleepyMySQLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if d := sleepFromPayload(id); d > 0 {
			time.Sleep(d)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("done"))
	})
}

// sleepFromPayload extracts the requested sleep duration from a wire
// value carrying one of the PayloadSQLiTime renderings. Recognises
// MySQL SLEEP(N), PostgreSQL pg_sleep(N), and MSSQL WAITFOR DELAY
// '0:0:N'. Returns 0 when none match (benign payload).
func sleepFromPayload(s string) time.Duration {
	// Look for SLEEP(<digits>) or pg_sleep(<digits>) or WAITFOR DELAY '0:0:<digits>'.
	for _, marker := range []string{"SLEEP(", "sleep(", "pg_sleep("} {
		i := strings.Index(s, marker)
		if i < 0 {
			continue
		}
		rest := s[i+len(marker):]
		end := strings.Index(rest, ")")
		if end < 0 {
			continue
		}
		n, ok := parseDigits(rest[:end])
		if ok {
			return time.Duration(n) * time.Second
		}
	}
	if i := strings.Index(s, "0:0:"); i >= 0 {
		rest := s[i+len("0:0:"):]
		end := strings.IndexAny(rest, "'\"")
		if end < 0 {
			end = len(rest)
		}
		if n, ok := parseDigits(rest[:end]); ok {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

func parseDigits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func TestSQLiTimeDetectsSleepBasedSQLi(t *testing.T) {
	withTestSleep(t)
	srv := httptest.NewServer(sleepyMySQLHandler())
	defer srv.Close()

	findings, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", f.CWE)
	}
	if !strings.Contains(f.Title, "id") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "confirmation latency") {
		t.Errorf("Detail should describe the confirmation latency: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestSQLiTimeEvidenceCapturesTimingStats(t *testing.T) {
	withTestSleep(t)
	srv := httptest.NewServer(sleepyMySQLHandler())
	defer srv.Close()

	findings, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if ev == nil || ev.Exchange == nil {
		t.Fatalf("Evidence/Exchange missing: %+v", ev)
	}
	// Snippet should carry the timing summary, not the response body
	// (which is irrelevant for blind timing detection).
	if !strings.Contains(ev.Snippet, "baseline=") || !strings.Contains(ev.Snippet, "confirmation=") {
		t.Errorf("Evidence snippet should carry timing stats: %q", ev.Snippet)
	}
}

func TestSQLiTimeNoFindingOnFastHandler(t *testing.T) {
	withTestSleep(t)
	// Handler ignores its inputs and returns immediately. No latency
	// divergence, no finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on fast handler, got %d: %+v", len(findings), findings)
	}
}

func TestSQLiTimeConfirmationRejectsOneOffJitter(t *testing.T) {
	withTestSleep(t)
	// Handler sleeps ONLY on the first sleep-shaped probe (simulates a
	// one-off jitter spike or cold-cache slow path), then responds
	// immediately for every subsequent call. The candidate probe
	// crosses the threshold but the confirmation does not - the check
	// must NOT report it as a finding.
	var slowConsumed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if d := sleepFromPayload(id); d > 0 {
			if slowConsumed.CompareAndSwap(false, true) {
				time.Sleep(d)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when confirmation fails, got %d: %+v", len(findings), findings)
	}
}

func TestSQLiTimeRespectsScope(t *testing.T) {
	withTestSleep(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := SQLiTime{}.Run(context.Background(), newTestClient(t), sc,
		page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings out of scope, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; out-of-scope check must not probe", got)
	}
}

func TestSQLiTimeNoProbeWhenNoSinks(t *testing.T) {
	withTestSleep(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/static"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sinks, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; no-sinks page must not be probed", got)
	}
}

func TestSQLiTimeDedupeKeyStableAndPerParam(t *testing.T) {
	withTestSleep(t)
	srv := httptest.NewServer(sleepyMySQLHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(rawurl))
		if err != nil {
			t.Fatalf("Run %q: %v", rawurl, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", rawurl, len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/user?id=42")
	b := run(srv.URL + "/user?id=99")
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestSQLiTimeAppendsPayloadOntoOriginalValue(t *testing.T) {
	withTestSleep(t)
	// Handler records what landed in `id` on the FIRST sleep-shaped
	// probe. The wire value must start with the original "42" - that's
	// the append-not-replace guarantee.
	var seenWire atomic.Value
	seenWire.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if d := sleepFromPayload(id); d > 0 {
			if cur, _ := seenWire.Load().(string); cur == "" {
				seenWire.Store(id)
			}
			time.Sleep(d)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := seenWire.Load().(string)
	if got == "" {
		t.Fatalf("server never saw a sleep-shaped probe")
	}
	if !strings.HasPrefix(got, "42") {
		t.Errorf("wire value = %q, want a string starting with the original \"42\"", got)
	}
}

func TestSQLiTimeEmptyValueUsesFiller(t *testing.T) {
	withTestSleep(t)
	// Form inputs frequently arrive with empty values. The check
	// should anchor with sqliTimeFillerValue so the payload still has
	// a valid SQL prefix to land against.
	var seenWire atomic.Value
	seenWire.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if d := sleepFromPayload(id); d > 0 {
			if cur, _ := seenWire.Load().(string); cur == "" {
				seenWire.Store(id)
			}
			time.Sleep(d)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id="))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := seenWire.Load().(string)
	if got == "" {
		t.Fatalf("server never saw a sleep-shaped probe")
	}
	if !strings.HasPrefix(got, sqliTimeFillerValue) {
		t.Errorf("wire value = %q, want a string starting with filler %q", got, sqliTimeFillerValue)
	}
}

func TestSQLiTimeIgnoresUnparseableTarget(t *testing.T) {
	withTestSleep(t)
	findings, err := SQLiTime{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestSleepFromPayload(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want time.Duration
	}{
		{"mysql SLEEP", "' AND SLEEP(2)-- -", 2 * time.Second},
		{"mysql lowercase sleep", "' AND sleep(3)-- -", 3 * time.Second},
		{"pg_sleep", "' AND pg_sleep(1)-- -", 1 * time.Second},
		{"mssql WAITFOR", "'; WAITFOR DELAY '0:0:4'-- -", 4 * time.Second},
		{"plain value", "42", 0},
		{"benign canary", "42hpzc0123abcd", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sleepFromPayload(tc.s); got != tc.want {
				t.Errorf("sleepFromPayload(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}
