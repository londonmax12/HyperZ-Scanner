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

func TestCmdInjectionName(t *testing.T) {
	if got := (CmdInjection{}).Name(); got != "cmd-injection" {
		t.Fatalf("Name = %q, want cmd-injection", got)
	}
}

func TestCmdInjectionLevel(t *testing.T) {
	if got := (CmdInjection{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

func TestCmdInjectionBudget(t *testing.T) {
	if got := (CmdInjection{}).Budget(); got <= DefaultBudget {
		t.Errorf("Budget = %v, want > DefaultBudget (%v)", got, DefaultBudget)
	}
}

// withTestCmdSleep dials the production sleep down to a test-friendly
// value and restores it on cleanup. 1s is the floor - the payload
// catalog uses integer-second {{SLEEP}} substitution.
func withTestCmdSleep(t *testing.T) {
	t.Helper()
	origSleep := cmdInjectionSleep
	origMargin := cmdInjectionMargin
	cmdInjectionSleep = 1 * time.Second
	cmdInjectionMargin = 0.5
	t.Cleanup(func() {
		cmdInjectionSleep = origSleep
		cmdInjectionMargin = origMargin
	})
}

// sleepFromShellPayload extracts the requested sleep duration from a
// wire value carrying one of the PayloadCmdInject renderings. Covers
// the POSIX `sleep N` and Windows `ping -n N 127.0.0.1` shapes. Returns
// 0 when neither matches.
func sleepFromShellPayload(s string) time.Duration {
	if i := strings.Index(s, "sleep "); i >= 0 {
		rest := s[i+len("sleep "):]
		if n, end := leadingDigits(rest); end > 0 {
			return time.Duration(n) * time.Second
		}
	}
	if i := strings.Index(s, "ping -n "); i >= 0 {
		rest := s[i+len("ping -n "):]
		if n, end := leadingDigits(rest); end > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

// leadingDigits parses the longest leading run of digits from s.
// Returns (parsed value, number of bytes consumed).
func leadingDigits(s string) (int, int) {
	n, end := 0, 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		n = n*10 + int(s[end]-'0')
		end++
	}
	return n, end
}

// sleepyShellHandler simulates a backend that concatenates `host` into
// a shell command (e.g. `ping <host>`): any payload containing
// `sleep <N>` or `ping -n <N>` causes a real time.Sleep of N seconds.
func sleepyShellHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if d := sleepFromShellPayload(host); d > 0 {
			time.Sleep(d)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("done"))
	})
}

func TestCmdInjectionDetectsShellExecution(t *testing.T) {
	withTestCmdSleep(t)
	srv := httptest.NewServer(sleepyShellHandler())
	defer srv.Close()

	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/ping?host=example.com"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.CWE != "CWE-78" {
		t.Errorf("CWE = %q, want CWE-78", f.CWE)
	}
	if !strings.Contains(f.Title, "host") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "confirmation latency") {
		t.Errorf("Detail should describe the confirmation latency: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestCmdInjectionDetectsWindowsPingDelay(t *testing.T) {
	// Cross-platform coverage: a Windows backend has no `sleep` binary
	// but `ping -n N 127.0.0.1` approximates an N-second delay. The
	// check must catch this via the same TimingCompare path.
	withTestCmdSleep(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		// Only react to the windows-ping shape, NOT to POSIX sleep -
		// this proves the windows-specific payload is what's firing.
		if i := strings.Index(host, "ping -n "); i >= 0 {
			rest := host[i+len("ping -n "):]
			if n, end := leadingDigits(rest); end > 0 {
				time.Sleep(time.Duration(n) * time.Second)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/ping?host=example.com"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "windows-ping-delay") {
		t.Errorf("Detail should mention the windows-ping payload: %q", findings[0].Detail)
	}
}

func TestCmdInjectionEvidenceCapturesTimingStats(t *testing.T) {
	withTestCmdSleep(t)
	srv := httptest.NewServer(sleepyShellHandler())
	defer srv.Close()

	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/ping?host=example.com"))
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
	if !strings.Contains(ev.Snippet, "baseline=") || !strings.Contains(ev.Snippet, "confirmation=") {
		t.Errorf("Evidence snippet should carry timing stats: %q", ev.Snippet)
	}
}

func TestCmdInjectionNoFindingOnFastHandler(t *testing.T) {
	withTestCmdSleep(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/ping?host=example.com"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on fast handler, got %d: %+v", len(findings), findings)
	}
}

func TestCmdInjectionConfirmationRejectsOneOffJitter(t *testing.T) {
	withTestCmdSleep(t)
	// Handler sleeps ONLY on the first sleep-shaped probe, then fast
	// afterwards. Candidate trips threshold, confirmation does not - no
	// finding.
	var slowConsumed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if d := sleepFromShellPayload(host); d > 0 {
			if slowConsumed.CompareAndSwap(false, true) {
				time.Sleep(d)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/ping?host=example.com"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when confirmation fails, got %d: %+v", len(findings), findings)
	}
}

func TestCmdInjectionRespectsScope(t *testing.T) {
	withTestCmdSleep(t)
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
	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t), sc,
		page.FromURL(srv.URL+"/?host=example.com"))
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

func TestCmdInjectionNoProbeWhenNoSinks(t *testing.T) {
	withTestCmdSleep(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
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

func TestCmdInjectionDedupeKeyStableAndPerParam(t *testing.T) {
	withTestCmdSleep(t)
	srv := httptest.NewServer(sleepyShellHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(rawurl))
		if err != nil {
			t.Fatalf("Run %q: %v", rawurl, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", rawurl, len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/ping?host=example.com")
	b := run(srv.URL + "/ping?host=other.example")
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestCmdInjectionAppendsPayloadOntoOriginalValue(t *testing.T) {
	withTestCmdSleep(t)
	var seenWire atomic.Value
	seenWire.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if d := sleepFromShellPayload(host); d > 0 {
			if cur, _ := seenWire.Load().(string); cur == "" {
				seenWire.Store(host)
			}
			time.Sleep(d)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?host=example.com"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := seenWire.Load().(string)
	if got == "" {
		t.Fatalf("server never saw a sleep-shaped probe")
	}
	if !strings.HasPrefix(got, "example.com") {
		t.Errorf("wire value = %q, want a string starting with original \"example.com\"", got)
	}
}

func TestCmdInjectionEmptyValueUsesFiller(t *testing.T) {
	withTestCmdSleep(t)
	var seenWire atomic.Value
	seenWire.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if d := sleepFromShellPayload(host); d > 0 {
			if cur, _ := seenWire.Load().(string); cur == "" {
				seenWire.Store(host)
			}
			time.Sleep(d)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?host="))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := seenWire.Load().(string)
	if got == "" {
		t.Fatalf("server never saw a sleep-shaped probe")
	}
	if !strings.HasPrefix(got, cmdInjectionFillerValue) {
		t.Errorf("wire value = %q, want a string starting with filler %q", got, cmdInjectionFillerValue)
	}
}

func TestCmdInjectionIgnoresUnparseableTarget(t *testing.T) {
	withTestCmdSleep(t)
	findings, err := CmdInjection{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestSleepFromShellPayload(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want time.Duration
	}{
		{"semicolon sleep", "; sleep 2", 2 * time.Second},
		{"and sleep", "&& sleep 3", 3 * time.Second},
		{"pipe sleep", "| sleep 4", 4 * time.Second},
		{"backtick sleep", "`sleep 1`", 1 * time.Second},
		{"dollar-paren sleep", "$(sleep 5)", 5 * time.Second},
		{"windows ping", "& ping -n 2 127.0.0.1", 2 * time.Second},
		{"plain value", "example.com", 0},
		{"benign canary", "example.comhpzc0123abcd", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sleepFromShellPayload(tc.s); got != tc.want {
				t.Errorf("sleepFromShellPayload(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}
