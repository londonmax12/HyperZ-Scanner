package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestCmdInjectionBlindName(t *testing.T) {
	if got := (CmdInjectionBlind{}).Name(); got != "cmd-injection-blind" {
		t.Fatalf("Name = %q, want cmd-injection-blind", got)
	}
}

func TestCmdInjectionBlindLevel(t *testing.T) {
	if got := (CmdInjectionBlind{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// blindErrorHandler simulates a backend that concatenates `host` into
// a shell command and returns error messages when the command fails.
// If the parameter contains a canary and a nonexistent command, it
// returns an error response that includes the attempted command.
func blindErrorHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		// Detect if this looks like an error-based injection attempt:
		// contains "nonexistent_cmd" in the parameter value.
		if strings.Contains(host, "nonexistent_cmd") {
			w.WriteHeader(http.StatusOK)
			// Return error that includes the entire attempted command for evidence.
			// This simulates a backend that shows command execution errors.
			_, _ = w.Write([]byte("Error output: sh: " + host + ": command not found\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Success"))
	})
}

func TestCmdInjectionBlindDetectsErrorBasedInjection(t *testing.T) {
	srv := httptest.NewServer(blindErrorHandler())
	defer srv.Close()

	findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
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
	if !strings.Contains(f.Detail, "error signature") {
		t.Errorf("Detail should mention error signature: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestCmdInjectionBlindEvidenceCapturesCanaryAndError(t *testing.T) {
	srv := httptest.NewServer(blindErrorHandler())
	defer srv.Close()

	findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
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
	if !strings.Contains(ev.Snippet, "canary=") || !strings.Contains(ev.Snippet, "error-signature=") {
		t.Errorf("Evidence snippet should carry canary and error: %q", ev.Snippet)
	}
}

func TestCmdInjectionBlindNoFindingWithoutBothCanaryAndError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler just returns an error without injection context
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sh: some error command not found"))
	}))
	defer srv.Close()

	findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/ping?host=example.com"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without canary+error match, got %d: %+v", len(findings), findings)
	}
}

func TestCmdInjectionBlindNoFindingOnSuccessResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Success"))
	}))
	defer srv.Close()

	findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/ping?host=example.com"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on success, got %d: %+v", len(findings), findings)
	}
}

func TestCmdInjectionBlindRespectsScope(t *testing.T) {
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
	findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t), sc,
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

func TestCmdInjectionBlindNoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
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

func TestCmdInjectionBlindDedupeKeyStableAndPerParam(t *testing.T) {
	srv := httptest.NewServer(blindErrorHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
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

func TestCmdInjectionBlindMultipleErrorPatterns(t *testing.T) {
	// Test that different error patterns all trigger findings
	errorPatterns := []string{
		"sh: command not found",
		"bash: : not found",
		"is not recognized as an internal or external command",
		"Permission denied",
	}

	for _, errPattern := range errorPatterns {
		t.Run(strings.Split(errPattern, ":")[0], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.URL.Query().Get("host")
				if strings.Contains(host, "nonexistent_cmd") {
					w.WriteHeader(http.StatusOK)
					// Include the host parameter in the error so the canary is present
					_, _ = w.Write([]byte(host + ": " + errPattern + "\n"))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}))
			defer srv.Close()

			findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
				nil, page.FromURL(srv.URL+"/?host=test.com"))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding for pattern %q, got %d", errPattern, len(findings))
			}
		})
	}
}

func TestCmdInjectionBlindIgnoresUnparseableTarget(t *testing.T) {
	findings, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestCmdErrorPatterns(t *testing.T) {
	patterns := CmdErrorPatterns()
	if len(patterns) == 0 {
		t.Fatal("CmdErrorPatterns should return non-empty list")
	}
	// Spot-check a few common patterns
	patternStr := strings.Join(patterns, "|")
	if !strings.Contains(patternStr, "command not found") {
		t.Errorf("patterns missing 'command not found': %v", patterns)
	}
	if !strings.Contains(patternStr, "is not recognized") {
		t.Errorf("patterns missing Windows signature: %v", patterns)
	}
}
