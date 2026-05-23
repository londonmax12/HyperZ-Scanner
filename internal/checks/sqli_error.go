package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

// SQLiError probes whether a user-influenced input is concatenated into a
// SQL statement by appending dialect-break payloads (a bare `'`, tautology
// suffixes, etc.) and looking for driver-error signatures in the response.
//
// One baseline request per sink establishes the "benign" pattern set: any
// SQLErrorPatterns substring already present in the baseline body is
// suppressed from subsequent matches, so a page that legitimately displays
// the text "you have an error in your sql syntax" (a documentation page,
// or a debug screen that exposes a prior query log) does not produce a
// false positive when our probe round-trips that same text unchanged.
//
// Per sink the probe sequence is at most 1 baseline + len(PayloadSQLiError)
// payloads, and stops at the first payload that introduces a new error
// pattern. On a 200-page crawl with N non-vulnerable sinks the request
// count is bounded above by N*(1+len(PayloadSQLiError)).
//
// This is an active (LevelDefault) check.
type SQLiError struct{}

func (SQLiError) Name() string { return "sqli-error" }

func (SQLiError) Level() Level { return LevelDefault }

// sqliErrorBodyCap bounds the response body the check reads. Sized to fit a
// typical 5xx error page including stack trace - driver errors usually
// appear near the top of the body, but ORM wrappers can push them into a
// long HTML template before the trace block.
const sqliErrorBodyCap = 32 << 10

func (c SQLiError) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}
	sinks := SinksFor(p)
	if len(sinks) == 0 {
		return nil, nil
	}

	var findings []Finding
	var firstErr error
	seen := map[string]struct{}{}
	for _, sink := range sinks {
		if ctx.Err() != nil {
			break
		}
		if u2, err := url.Parse(sink.URL); err == nil && !sc.Allows(u2) {
			continue
		}
		f, err := c.probe(ctx, client, p.URL, sink)
		if err != nil {
			Report(ctx, fmt.Errorf("probe %s %s=%s: %w", sink.Loc, sink.Name, sink.URL, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if f == nil {
			continue
		}
		if _, dup := seen[f.DedupeKey]; dup {
			continue
		}
		seen[f.DedupeKey] = struct{}{}
		findings = append(findings, *f)
	}
	if firstErr != nil && len(findings) == 0 {
		return nil, firstErr
	}
	return findings, nil
}

// probe runs the baseline + payload sweep for one sink. Returns a finding
// only when a payload introduces a SQLErrorPatterns substring that was NOT
// present in the benign baseline - the subtraction is what makes the check
// precise on debug pages that legitimately echo driver text.
func (c SQLiError) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	// Baseline: a benign canary keeps the request shape identical to the
	// payload probes (same method, same param name, same Content-Type) so
	// any pattern that fires here is purely a property of the page, not
	// of how we shaped the request.
	canary := NewCanary()
	_, _, baselineBody, baselineTruncated, err := c.send(ctx, client, sink, canary)
	if err != nil {
		return nil, err
	}
	baselineHits := matchSQLPatterns(baselineBody)

	anyTruncated := baselineTruncated
	for _, p := range PayloadsFor(PayloadSQLiError) {
		if ctx.Err() != nil {
			break
		}
		// Append onto the existing value rather than replace it: in a
		// numeric context (id=42) `42'` produces an unterminated literal,
		// while a bare `'` becomes `''` (valid empty string) and slips by.
		// For empty original values both forms degenerate to the payload
		// alone, which is still a parse-error on every dialect we cover.
		wire := sink.Value + p.Template
		req, resp, body, truncated, err := c.send(ctx, client, sink, wire)
		if err != nil {
			return nil, err
		}
		if truncated {
			anyTruncated = true
		}
		hits := matchSQLPatterns(body)
		newHits := subtractPatterns(hits, baselineHits)
		if len(newHits) == 0 {
			continue
		}
		probeURL := ""
		method := ""
		if req != nil {
			method = req.Method
			if req.URL != nil {
				probeURL = req.URL.String()
			}
		}
		status := statusOf(resp)
		// First payload that introduces a new error pattern wins: dedupe
		// key collapses any further hits on the same (loc, param) into
		// this same finding, so continuing to probe would burn requests
		// for no extra signal.
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("SQL injection (error-based) in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) appears to be concatenated into a SQL statement: payload sqli-error/%s "+
					"(wire value %q) provoked driver error signature %q in the response. "+
					"An attacker can extract or modify database contents via crafted values.",
				sink.Name, sink.Loc, p.Name, wire, newHits[0]),
			CWE:   "CWE-89",
			OWASP: "A03:2021 Injection",
			Remediation: "Use parameterized queries / prepared statements so user input is passed as a value, never " +
				"concatenated into SQL text. Disable verbose database error reporting in production responses regardless - " +
				"leaked error traces accelerate exploitation even when the underlying bug is patched.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     status,
				Snippet:    snippet(body, []byte(newHits[0]), true),
				Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	if anyTruncated {
		Report(ctx, fmt.Errorf("probe %s %s=%s: response body truncated at %d bytes during sweep, driver error may have been missed",
			sink.Loc, sink.Name, sink.URL, sqliErrorBodyCap))
	}
	return nil, nil
}

// send mutates sink with wireValue, dispatches the request, and reads up to
// sqliErrorBodyCap of the body. Mirrors the ReflectedXSS.send shape so
// future merger of the two checks' request shells is mechanical.
func (c SQLiError) send(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, sqliErrorBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}

// matchSQLPatterns returns every SQLErrorPatterns entry that appears in
// body. Body is lower-cased once per call (the pattern list is already
// lower-cased) so the substring scan is case-insensitive without per-
// pattern allocations.
func matchSQLPatterns(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pat := range SQLErrorPatterns() {
		if bytes.Contains(lower, []byte(pat)) {
			hits = append(hits, pat)
		}
	}
	return hits
}

// subtractPatterns returns the elements of hits that are not in baseline.
// Used to drop patterns that were already present before our probe ran -
// the difference is the part attributable to the injection attempt.
func subtractPatterns(hits, baseline []string) []string {
	if len(baseline) == 0 {
		return hits
	}
	bset := make(map[string]struct{}, len(baseline))
	for _, b := range baseline {
		bset[b] = struct{}{}
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if _, dup := bset[h]; dup {
			continue
		}
		out = append(out, h)
	}
	return out
}

