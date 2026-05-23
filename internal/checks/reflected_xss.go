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

// ReflectedXSS probes whether user input on a target page is echoed back into
// the response unescaped, in a context where script execution is achievable.
//
// The check runs in two stages per Sink:
//
//  1. Send a bare canary. FindReflections classifies the surrounding HTML / JS
//     context. Non-reflecting sinks are dropped here so the page's full param
//     surface costs one request per sink, not N payloads * sinks.
//  2. For each reflection context, render the curated PayloadXSS variant whose
//     breakout shape matches (attribute breakout for quoted-attr reflections,
//     bare svg/img tags for HTML-text reflections, JS-string breakouts for
//     script-string reflections). A finding fires only when the rendered
//     payload bytes round-trip intact - that is the discriminator between
//     "reflected unescaped" (exploitable) and "reflected with HTML-encoding"
//     (safe).
//
// This is an active (LevelDefault) check; only the bare canary fires at
// LevelPassive scans (it never runs there) and a 200-page crawl with no
// reflecting params produces ~SinksFor(p) requests per page, not the full
// payload sweep.
type ReflectedXSS struct{}

func (ReflectedXSS) Name() string { return "reflected-xss" }

func (ReflectedXSS) Level() Level { return LevelDefault }

// reflectedXSSBodyCap bounds the response body the check reads. Larger than
// the passive-check default because reflection can land deep in a templated
// page (footer, late-rendering script block); 64 KiB covers the realistic
// envelope without exposing the check to a runaway response.
const reflectedXSSBodyCap = 64 << 10

func (c ReflectedXSS) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
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

// probe runs the canary-then-breakout sequence for one sink. Returns a
// finding only when a context-appropriate payload survived encoding; bare
// reflection alone is not reported because we cannot prove exploitability
// without seeing a breakout payload round-trip intact.
func (c ReflectedXSS) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	canary := NewCanary()
	_, resp1, body1, canaryTruncated, err := c.send(ctx, client, sink, canary)
	if err != nil {
		return nil, err
	}
	var headers1 http.Header
	if resp1 != nil {
		headers1 = resp1.Header
	}
	reflections := FindReflections(body1, headers1, canary)
	if len(reflections) == 0 {
		// Reflection might have landed past the body cap; flag uncertainty
		// so the operator knows the no-finding result was on a clipped read.
		if canaryTruncated {
			Report(ctx, fmt.Errorf("probe %s %s=%s: canary response body truncated at %d bytes, reflection may have been missed",
				sink.Loc, sink.Name, sink.URL, reflectedXSSBodyCap))
		}
		return nil, nil
	}

	anyTruncated := canaryTruncated
	for _, p := range payloadsForContexts(reflections, LevelFrom(ctx)) {
		if ctx.Err() != nil {
			break
		}
		tok := NewCanary()
		rendered := p.Render(tok, 0)
		req, resp2, body2, truncated, err := c.send(ctx, client, sink, rendered)
		if err != nil {
			return nil, err
		}
		if truncated {
			anyTruncated = true
		}
		if !bytes.Contains(body2, []byte(rendered)) {
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
		status := 0
		if resp2 != nil {
			status = resp2.StatusCode
		}
		ctxs := contextSummary(reflections)
		// First surviving payload wins: the dedupe key collapses any
		// further hits on the same (loc, param) into the same finding, so
		// continuing to probe would burn requests for no extra signal.
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("Reflected XSS in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) is reflected unescaped into the response (%s context). "+
					"Payload xss/%s round-tripped intact - an attacker can craft a link to %s that executes script in the victim's browser.",
				sink.Name, sink.Loc, ctxs, p.Name, probeURL),
			CWE:   "CWE-79",
			OWASP: "A03:2021 Injection",
			Remediation: "Context-aware output encoding: HTML-encode user input rendered into HTML text, " +
				"attribute-encode for values placed in tag attributes, and JavaScript-encode (or hand off via JSON) for values " +
				"placed inside <script>. Prefer templating engines that auto-escape by default; never concatenate user input into HTML.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     status,
				Snippet:    snippet(body2, []byte(rendered), false),
				Exchange:   RecordExchange(req, nil, false, resp2, body2, truncated),
			},
			// Per (page, loc, param) - the same input vulnerable across many
			// crawl entry points collapses to one finding, while distinct
			// inputs on the same page stay distinct.
			DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	if anyTruncated {
		Report(ctx, fmt.Errorf("probe %s %s=%s: response body truncated at %d bytes during payload sweep, breakout may have been missed",
			sink.Loc, sink.Name, sink.URL, reflectedXSSBodyCap))
	}
	return nil, nil
}

// send mutates sink with payload, dispatches the request, reads up to
// reflectedXSSBodyCap of the body, and returns everything the caller needs
// for both detection and evidence. resp.Body is closed before return; the
// caller works with the captured body slice.
func (c ReflectedXSS) send(ctx context.Context, client *httpclient.Client, sink Sink, payload string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, payload)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, reflectedXSSBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}

// payloadsForContexts maps the bare-canary reflection contexts onto the
// curated PayloadXSS variants whose breakout shape matches each context.
//
// At LevelDefault, output is exactly the context-matched set, deduped by
// payload name so repeated contexts (token echoed twice in the same shape)
// don't double the request count.
//
// At LevelAggressive, every payload is still tried so a breakout achievable
// through an alternate shape (sloppy attribute echo, double-rendered context)
// is caught - but the context-matched payloads are front-loaded so the
// probe's first-success short-circuit can return after one or two requests
// in the common case instead of grinding through the full catalog.
func payloadsForContexts(refs []Reflection, level Level) []Payload {
	matched := selectByContext(refs)
	if level < LevelAggressive {
		return matched
	}
	all := PayloadsFor(PayloadXSS)
	matchedSet := make(map[string]struct{}, len(matched))
	for _, p := range matched {
		matchedSet[p.Name] = struct{}{}
	}
	out := make([]Payload, 0, len(all))
	out = append(out, matched...)
	for _, p := range all {
		if _, dup := matchedSet[p.Name]; dup {
			continue
		}
		out = append(out, p)
	}
	return out
}

// selectByContext returns the context-matched payload subset, deduped by
// name and ordered by first appearance of each context in refs.
func selectByContext(refs []Reflection) []Payload {
	byName := map[string]Payload{}
	for _, p := range PayloadsFor(PayloadXSS) {
		byName[p.Name] = p
	}
	seen := map[string]struct{}{}
	var out []Payload
	push := func(names ...string) {
		for _, n := range names {
			if _, dup := seen[n]; dup {
				continue
			}
			p, ok := byName[n]
			if !ok {
				continue
			}
			out = append(out, p)
			seen[n] = struct{}{}
		}
	}
	for _, r := range refs {
		switch r.Context {
		case CtxHTMLText:
			// Free HTML on both sides; any tag-injection payload executes.
			push("html-svg-onload", "html-img-onerror")
		case CtxAttrUnquoted:
			// In tag-content / unquoted-attr state the parser does not
			// leave attribute mode on a bare `<`; we need `>` first to
			// close the host tag before our `<svg ...>` can form.
			push("attr-unquoted-break")
		case CtxAttrDoubleQuoted:
			push("attr-double-break")
		case CtxAttrSingleQuoted:
			push("attr-single-break")
		case CtxScriptText:
			// Already inside <script> but not in a string literal: bare
			// JS executes directly. Leading `;` makes the payload safe
			// at both statement and expression positions.
			push("js-bare-break")
		case CtxScriptStringDouble:
			push("js-string-double-break")
		case CtxScriptStringSingle:
			push("js-string-single-break")
		case CtxHTMLComment, CtxHeaderValue:
			// Comment requires a `-->` escape we do not currently render;
			// header-value reflection isn't XSS by itself. Default-level
			// scan skips both; aggressive level still hits everything via
			// the catalog-wide tail of payloadsForContexts.
		}
	}
	return out
}

// contextSummary returns a comma-separated, dedup-ordered list of context
// names for use in finding text. Source order is preserved so the first
// reflection's context leads the rendering.
func contextSummary(refs []Reflection) string {
	seen := map[Context]struct{}{}
	var names []string
	for _, r := range refs {
		if _, dup := seen[r.Context]; dup {
			continue
		}
		seen[r.Context] = struct{}{}
		names = append(names, r.Context.String())
	}
	return strings.Join(names, ", ")
}
