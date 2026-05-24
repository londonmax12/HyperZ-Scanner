package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// SSTI detects Server-Side Template Injection by probing whether user input is
// evaluated within a template engine.
//
// Two detection strategies are applied in sequence per sink:
//
// 1. Expression evaluation: sends canary-flanked math expressions in the syntax
// of major template engines (Jinja2, FreeMarker, ERB, Smarty, Velocity, Thymeleaf,
// Ruby interpolation, Razor). A match on canary+expected-result+canary proves the
// engine evaluated the expression. A confirming probe with a different math
// expression is then sent in the same engine syntax; a second match keeps the
// finding at Critical, a confirm-miss demotes it to High (the first hit is still
// strongly diagnostic, but a missed confirm warrants lower confidence).
//
// 2. Error-based: sends deliberately malformed template syntax ({{, ${, <%) and
// looks for engine-specific error signatures. Baseline subtraction (like SQLiError)
// suppresses false positives from pages that legitimately contain engine error text.
//
// At LevelDefault, probes query params and form fields (SinksFor). At LevelAggressive,
// also probes common header vectors (User-Agent, Referer, X-Forwarded-For, etc.).
//
// This is an active (LevelDefault) check.
type SSTI struct{}

func (SSTI) Name() string { return "ssti" }

func (SSTI) Level() Level { return LevelDefault }

const sstiBodyCap = 32 << 10

func (c SSTI) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}

	sinks := SinksFor(p)
	if LevelFrom(ctx) >= LevelAggressive {
		sinks = append(sinks, c.headerSinks(p.URL)...)
	}
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

func (c SSTI) headerSinks(pageURL string) []Sink {
	var sinks []Sink
	for _, name := range []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"} {
		sinks = append(sinks, Sink{
			Method: http.MethodGet,
			URL:    pageURL,
			Loc:    LocHeader,
			Name:   name,
			Value:  "",
		})
	}
	return sinks
}

// probe runs the detection sequence for one sink. Returns a finding when either
// expression evaluation (with confirmation) or error-based detection succeeds;
// whichever fires first wins (stops further probing).
func (c SSTI) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	// Baseline: establish the patterns present before our probes, for
	// error-based detection subtraction.
	canary := NewCanary()
	_, _, baselineBody, baselineTruncated, err := c.send(ctx, client, sink, canary)
	if err != nil {
		return nil, err
	}
	baselineErrors := matchSSTIErrors(baselineBody)

	anyTruncated := baselineTruncated

	// Phase 1: Expression evaluation - each probe renders a unique
	// canary-flanked expression. A match proves the engine evaluated the math.
	for _, probe := range SSTIExprProbes() {
		if ctx.Err() != nil {
			break
		}
		tok := NewCanary()
		wire := strings.ReplaceAll(probe.Template, "{{TOKEN}}", tok)
		req, resp, body, truncated, err := c.send(ctx, client, sink, wire)
		if err != nil {
			return nil, err
		}
		if truncated {
			anyTruncated = true
		}

		needle := []byte(tok + probe.Expected + tok)
		if !bytes.Contains(body, needle) {
			continue
		}

		// Confirmation: derive a second probe in the same engine syntax with
		// a different expression. A genuine SSTI evaluates this too; a one-
		// off coincidence on "49" between two canaries (already vanishingly
		// rare with 48-bit canaries) will not survive a second match.
		confirmTpl, confirmExpected := c.confirmProbe(probe)
		confirmTok := NewCanary()
		confirmWire := strings.ReplaceAll(confirmTpl, "{{TOKEN}}", confirmTok)
		_, _, confirmBody, confirmTruncated, confErr := c.send(ctx, client, sink, confirmWire)
		if confErr != nil {
			// Confirmation transport failure is not a reason to suppress the
			// first hit; the network might be flaky but we already have a
			// strong signal. Report the sub-error and proceed at High.
			Report(ctx, fmt.Errorf("ssti confirm %s %s=%s: %w", sink.Loc, sink.Name, sink.URL, confErr))
		}
		if confirmTruncated {
			anyTruncated = true
		}
		confirmNeedle := []byte(confirmTok + confirmExpected + confirmTok)
		confirmed := confErr == nil && bytes.Contains(confirmBody, confirmNeedle)

		severity := SeverityCritical
		titleSuffix := "expression evaluation"
		if !confirmed {
			severity = SeverityHigh
			titleSuffix = "expression evaluation, unconfirmed"
		}

		method, probeURL := requestIdentity(req)
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: severity,
			Title:    fmt.Sprintf("Server-Side Template Injection (%s) in %s %s %q", titleSuffix, locDescriptor(sink.Loc), sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) appears to be rendered in a %s-family template engine: payload ssti/%s "+
					"probed %s and evaluated to %s with context marker %q (confirmation probe %s -> %s %s). "+
					"Server-side template injection can range from sensitive data disclosure to remote code "+
					"execution depending on the engine and its sandboxing.",
				sink.Name, sink.Loc, probe.Name, probe.Name,
				probeMathSource(probe), probe.Expected, tok,
				confirmMathSource(probe), confirmExpected, confirmDispositionPhrase(confirmed, confErr),
			),
			CWE:   "CWE-1336",
			OWASP: "A03:2021 Injection",
			Remediation: "Never concatenate user input into template source code. Render user input as template " +
				"variables or data objects instead. Use template engines with sandboxing when user-controlled templates " +
				"are a product requirement.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     statusOf(resp),
				Snippet:    snippet(body, needle, false),
				Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}

	// Phase 2: Error-based detection - send deliberately malformed templates
	// and look for engine-specific error patterns (with baseline subtraction).
	for _, errorPayload := range sstiErrorPayloads {
		if ctx.Err() != nil {
			break
		}
		req, resp, body, truncated, err := c.send(ctx, client, sink, errorPayload)
		if err != nil {
			return nil, err
		}
		if truncated {
			anyTruncated = true
		}

		hits := matchSSTIErrors(body)
		newHits := subtractPatterns(hits, baselineErrors)
		if len(newHits) == 0 {
			continue
		}

		method, probeURL := requestIdentity(req)
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("Server-Side Template Injection (error-based) in %s %s %q", locDescriptor(sink.Loc), sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) appears to be rendered in a template engine: probe payload %q "+
					"provoked template engine error signature %q. "+
					"An attacker can likely extract sensitive information and may be able to execute code.",
				sink.Name, sink.Loc, errorPayload, newHits[0]),
			CWE:   "CWE-1336",
			OWASP: "A03:2021 Injection",
			Remediation: "Never concatenate user input into template source code. Render user input as template " +
				"variables or data objects instead. Use template engines with sandboxing when user-controlled templates " +
				"are a product requirement.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     statusOf(resp),
				Snippet:    snippet(body, []byte(newHits[0]), true),
				Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}

	if anyTruncated {
		Report(ctx, fmt.Errorf("probe %s %s=%s: response body truncated at %d bytes during sweep, "+
			"template injection may have been missed",
			sink.Loc, sink.Name, sink.URL, sstiBodyCap))
	}
	return nil, nil
}

// confirmProbe derives a follow-up template+expected pair from an
// expression probe by swapping its math operands. Every entry in
// SSTIExprProbes pivots on the literal "7*7" / "49"; substituting "8*9"
// / "72" keeps the engine syntax identical while exercising a fresh
// expression a passively-reflecting page cannot replay.
func (SSTI) confirmProbe(p SSTIProbe) (template, expected string) {
	return strings.Replace(p.Template, "7*7", "8*9", 1), "72"
}

// send mutates sink with wireValue, dispatches the request, and reads up to
// sstiBodyCap of the body.
func (c SSTI) send(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, sstiBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}

// requestIdentity extracts (method, URL) from req with nil-safety. Centralized
// here because the probe finding builders need both fields in the same shape.
func requestIdentity(req *http.Request) (method, rawURL string) {
	if req == nil {
		return "", ""
	}
	if req.URL != nil {
		rawURL = req.URL.String()
	}
	return req.Method, rawURL
}

// locDescriptor returns the human-facing role for a Loc - "parameter" for
// query/form/path/json inputs, "header" for headers, etc. - so the finding
// title reads "in query parameter" rather than "in query query".
func locDescriptor(l Loc) string {
	switch l {
	case LocHeader:
		return "header"
	case LocCookie:
		return "cookie"
	default:
		return "parameter"
	}
}

// probeMathSource extracts the canonical "7*7" inner expression from a probe
// template by stripping the {{TOKEN}} wrappers. Used to render a clean
// "probed 7*7" phrase in the finding detail without leaking framing tokens.
func probeMathSource(p SSTIProbe) string {
	return strings.ReplaceAll(p.Template, "{{TOKEN}}", "")
}

// confirmMathSource returns probeMathSource for the confirm template that
// confirmProbe would derive from p.
func confirmMathSource(p SSTIProbe) string {
	tpl, _ := SSTI{}.confirmProbe(p)
	return strings.ReplaceAll(tpl, "{{TOKEN}}", "")
}

// confirmDispositionPhrase returns the phrase the finding detail uses to
// describe the confirmation probe outcome: "confirmed", "did not confirm",
// or "transport error: <err>" when the confirmation request itself failed.
func confirmDispositionPhrase(confirmed bool, confErr error) string {
	if confErr != nil {
		return fmt.Sprintf("transport error: %v", confErr)
	}
	if confirmed {
		return "confirmed"
	}
	return "did not confirm"
}

// matchSSTIErrors returns every SSTIErrorPatterns entry that appears in body.
// Body is lowercased once per call so substring scans are case-insensitive.
func matchSSTIErrors(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pat := range SSTIErrorPatterns() {
		if bytes.Contains(lower, []byte(pat)) {
			hits = append(hits, pat)
		}
	}
	return hits
}
