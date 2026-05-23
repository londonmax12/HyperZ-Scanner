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

func TestSQLiErrorName(t *testing.T) {
	if got := (SQLiError{}).Name(); got != "sqli-error" {
		t.Fatalf("Name = %q, want sqli-error", got)
	}
}

func TestSQLiErrorLevel(t *testing.T) {
	if got := (SQLiError{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnMySQLHandler simulates a backend that concatenates the `id` query
// param into a SQL statement and leaks the driver error verbatim when the
// statement fails to parse. The benign canary path returns 200 OK with no
// SQL text so the baseline subtraction is exercised.
func vulnMySQLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Any payload containing a bare single quote (or backtick) leaks
		// the MySQL signature. Benign alphanumeric values come back clean.
		if strings.ContainsAny(id, "'\"`") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version near '" + id + "' at line 1"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("user details for " + id))
	})
}

func TestSQLiErrorDetectsMySQLSyntaxError(t *testing.T) {
	srv := httptest.NewServer(vulnMySQLHandler())
	defer srv.Close()

	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
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
	if !strings.Contains(f.Detail, "sql syntax") && !strings.Contains(f.Detail, "mariadb") {
		t.Errorf("Detail should mention the matched MySQL/MariaDB signature: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestSQLiErrorDetectsPostgresError(t *testing.T) {
	// A different dialect's signature - confirms the pattern list isn't
	// MySQL-specific even though the catalog leads with MySQL payloads.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"`") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("pg_query(): unterminated quoted string at or near \"'\" LINE 1"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "pg_query") && !strings.Contains(findings[0].Detail, "unterminated quoted string") {
		t.Errorf("Detail should mention the matched Postgres signature: %q", findings[0].Detail)
	}
}

func TestSQLiErrorEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnMySQLHandler())
	defer srv.Close()

	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
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
	if ev.Exchange.Status != http.StatusInternalServerError {
		t.Errorf("Exchange.Status = %d, want 500", ev.Exchange.Status)
	}
	if !strings.Contains(strings.ToLower(ev.Exchange.ResponseBody), "sql syntax") {
		t.Errorf("Exchange body should contain the driver error: %q", ev.Exchange.ResponseBody)
	}
	if ev.Snippet == "" {
		t.Errorf("Evidence snippet should be populated")
	}
}

func TestSQLiErrorNoFindingOnRobustParameter(t *testing.T) {
	// Server uses parameterized queries: even with quotes/backticks the
	// response is benign. No SQL error patterns appear, no finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("safe content"))
	}))
	defer srv.Close()

	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/user?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe param, got %d: %+v", len(findings), findings)
	}
}

func TestSQLiErrorBaselineSubtractionSuppressesFalsePositive(t *testing.T) {
	// Page legitimately renders documentation text that includes a SQL
	// error signature for EVERY response - benign or otherwise. The
	// baseline-subtraction logic must drop the pattern since it isn't
	// introduced by our probe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Knowledge base: how to debug 'you have an error in your sql syntax' messages in MariaDB."))
	}))
	defer srv.Close()

	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/kb?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when error text is in baseline, got %d: %+v", len(findings), findings)
	}
}

func TestSQLiErrorRespectsScope(t *testing.T) {
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
	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t), sc,
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

func TestSQLiErrorNoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
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

func TestSQLiErrorDedupeKeyStableAndPerParam(t *testing.T) {
	srv := httptest.NewServer(vulnMySQLHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := SQLiError{}.Run(context.Background(), newTestClient(t),
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
	b := run(srv.URL + "/user?id=99") // same param, different value, same key
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestSQLiErrorMultipleVulnerableParamsProduceDistinctFindings(t *testing.T) {
	// Two params both flow into SQL. Distinct findings, distinct DedupeKeys.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, k := range []string{"id", "name"} {
			v := r.URL.Query().Get(k)
			if strings.ContainsAny(v, "'\"`") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Error: You have an error in your SQL syntax near '" + v + "'"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=1&name=a"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per vulnerable param), got %d: %+v", len(findings), findings)
	}
	keys := map[string]string{}
	for _, f := range findings {
		if prev, dup := keys[f.DedupeKey]; dup {
			t.Errorf("dedupe collision: %q and %q share key %q", prev, f.Title, f.DedupeKey)
		}
		keys[f.DedupeKey] = f.Title
	}
}

func TestSQLiErrorReportsTruncationWhenNoFinding(t *testing.T) {
	// Server returns a benign body that exceeds sqliErrorBodyCap = 32 KiB.
	// No driver-error pattern fires regardless, so we expect 0 findings
	// AND a truncation breadcrumb via Report.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("a", 40*1024)))
	}))
	defer srv.Close()

	var reported []string
	ctx := WithReporter(context.Background(), func(err error) {
		reported = append(reported, err.Error())
	})

	findings, err := SQLiError{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on benign oversized body, got %d: %+v", len(findings), findings)
	}
	if len(reported) == 0 {
		t.Fatal("expected a truncation breadcrumb via Report, got none")
	}
	joined := strings.Join(reported, "\n")
	if !strings.Contains(joined, "truncated") {
		t.Errorf("Report message should mention truncation: %q", joined)
	}
}

func TestSQLiErrorIgnoresUnparseableTarget(t *testing.T) {
	findings, err := SQLiError{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestSQLiErrorAppendsPayloadOntoOriginalValue(t *testing.T) {
	// Handler echoes the wire value it received back inside the SQL
	// error message. With original value=42 and payload `'`, we expect
	// to see `42'` in the error - confirming the check appends rather
	// than replaces. Replacement would emit just `'`.
	var seenWire atomic.Value
	seenWire.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"`") {
			seenWire.Store(id)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Error: You have an error in your SQL syntax near '" + id + "'"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := SQLiError{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?id=42"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := seenWire.Load().(string)
	if got == "" {
		t.Fatalf("server never saw a payload probe")
	}
	if !strings.HasPrefix(got, "42") {
		t.Errorf("wire value = %q, want a string starting with the original \"42\"", got)
	}
}

func TestMatchSQLPatterns(t *testing.T) {
	body := []byte("Stack trace:\nERROR: You have an error in your SQL syntax near token\n  at ...")
	hits := matchSQLPatterns(body)
	if len(hits) == 0 {
		t.Fatal("expected at least one hit on a known MySQL signature")
	}
	wantOne := false
	for _, h := range hits {
		if strings.Contains(h, "sql syntax") {
			wantOne = true
		}
	}
	if !wantOne {
		t.Errorf("hits = %+v, want one mentioning sql syntax", hits)
	}
}

func TestMatchSQLPatternsEmpty(t *testing.T) {
	if got := matchSQLPatterns(nil); got != nil {
		t.Errorf("empty body should yield nil hits, got %+v", got)
	}
	if got := matchSQLPatterns([]byte("totally benign HTML")); got != nil {
		t.Errorf("clean body should yield nil hits, got %+v", got)
	}
}

func TestSubtractPatterns(t *testing.T) {
	cases := []struct {
		name     string
		hits     []string
		baseline []string
		want     []string
	}{
		{"empty baseline returns all", []string{"a", "b"}, nil, []string{"a", "b"}},
		{"identical subtraction returns empty", []string{"a", "b"}, []string{"a", "b"}, []string{}},
		{"new hit survives", []string{"a", "b", "c"}, []string{"a"}, []string{"b", "c"}},
		{"all suppressed", []string{"a"}, []string{"a", "b"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := subtractPatterns(tc.hits, tc.baseline)
			if !equalStringSlices(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

