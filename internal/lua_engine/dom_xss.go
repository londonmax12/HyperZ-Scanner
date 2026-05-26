package lua_engine

import (
	"context"
	"fmt"
	"time"

	"github.com/londonmax12/hyperz/internal/browser"
)

// DOMXSS detects XSS that lives entirely in client JavaScript - the
// server never reflects the payload but the page's JS reads it from a
// DOM source (location.hash, location.search, document.referrer,
// postMessage) and pipes it into a sink (innerHTML, document.write,
// eval, Function, setTimeout-string, javascript: URI).
//
// Detection uses runtime execution, not static reflection: the check
// loads the target in a headless browser with a payload that, on
// execution, calls a CDP binding the scanner installed. If the binding
// fires with the expected canary token we have proof of execution -
// no inference from "the payload bytes round-tripped" and therefore
// no false positives from encoded-but-reflected echoes.
//
// Skipped silently when no browser Pool is attached to ctx; the
// operator must opt in via --js. Cost is one tab per (sink x payload)
// at the per-tab settle window, which is why this is LevelDefault
// gated behind a flag rather than always-on - the reflected-xss check
// covers server-reflected paths cheaply and DOMXSS picks up only the
// DOM-only delta when the operator wants it.
type DOMXSS struct{}

// domXSSSettle bounds how long Visit waits for the binding to fire on
// each probe. Long enough for typical event-loop work (DOMContentLoaded
// handlers, framework hydration that reads location.hash on mount) to
// finish; short enough that a 50-page crawl with a handful of sinks
// each doesn't dominate scan time.
const domXSSSettle = 1500 * time.Millisecond

// domXSSProbe pairs a payload with the sink class that payload can
// plausibly reach. The hint is recorded on the finding so triage starts
// with a narrower search than "any of innerHTML/document.write/eval/
// Function/setTimeout-string/javascript-URI" - the binding tells us
// execution happened, the payload tells us through which family.
type domXSSProbe struct {
	payload  string
	sinkHint string
}

// domXSSPayloads are the breakouts the check fires through fragment
// and query sources. Each carries a `{{token}}` placeholder substituted
// per probe so the controller can correlate a binding fire back to the
// payload that caused it (and silently ignore noise calls if a site
// happens to expose its own debug binding with the same name).
//
// The set is intentionally small - every entry costs one tab. Add only
// payloads that catch a sink shape the existing set misses.
var domXSSPayloads = []domXSSProbe{
	{
		// HTML-context: <img onerror> works inside text and most attribute
		// breakouts; the leading `">` handles the common case where the
		// source is interpolated into an unquoted or double-quoted attr.
		payload:  `"><img src=x onerror="` + browser.BindingName + `('{{token}}')">`,
		sinkHint: "HTML-context sink (innerHTML / document.write / insertAdjacentHTML)",
	},
	{
		// SVG-onload is a fallback for pages that strip <img> or sanitize
		// `src`; <svg onload> survives many partial sanitizers.
		payload:  `<svg onload="` + browser.BindingName + `('{{token}}')">`,
		sinkHint: "HTML-context sink (innerHTML / document.write / insertAdjacentHTML)",
	},
	{
		// javascript: URI - catches sinks like `location.href = userInput`
		// or `<a href={userInput}>` followed by a programmatic click.
		payload:  `javascript:` + browser.BindingName + `('{{token}}')`,
		sinkHint: "URL-navigation sink (location.href / anchor href / window.open with attacker-controlled URL)",
	},
}

func (c DOMXSS) visit(ctx context.Context, pool browser.Pool, target, probeURL, source, param, token, payload, sinkHint string) *Finding {
	fired, err := pool.Visit(ctx, probeURL, token, domXSSSettle)
	if err != nil {
		Report(ctx, fmt.Errorf("dom-xss visit %s: %w", probeURL, err))
		return nil
	}
	if !fired {
		return nil
	}
	title := "DOM XSS via " + source
	if param != "" {
		title = fmt.Sprintf("DOM XSS via %s in parameter %q", source, param)
	}
	return &Finding{
		Check:    "dom-xss",
		Target:   target,
		URL:      probeURL,
		Severity: SeverityHigh,
		Title:    title,
		Detail: fmt.Sprintf(
			"Client-side JavaScript read the payload from %s and piped it into a %s. "+
				"The headless-browser canary fired with token %q after loading the probe URL - "+
				"the payload reached executable JS without round-tripping through the server, "+
				"so the bug is in client code, not server output encoding.",
			source, sinkHint, token),
		CWE:   "CWE-79",
		OWASP: "A03:2021 Injection",
		Remediation: "Treat DOM sources (location.*, document.referrer, document.cookie, postMessage " +
			"event.data) as untrusted. Never pass them to innerHTML, document.write, eval, Function, " +
			"setTimeout/setInterval with a string argument, or as a javascript: URI. Use textContent " +
			"or setAttribute; when HTML is unavoidable, sanitize through a vetted library (DOMPurify) " +
			"before injection.",
		Evidence: &Evidence{
			Method:     "GET",
			RequestURL: probeURL,
			Snippet:    "headless-browser execution; payload: " + payload,
		},
		// One finding per (page, source, param). The same source firing
		// across many crawl entry points collapses to one row; two
		// distinct vulnerable params on the same page stay distinct.
		DedupeKey: MakeKey("dom-xss", ScopeParam, target, "source:"+source, "param:"+param),
	}
}
