package checks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// StoredXSS detects persistent cross-site scripting: an input on one page
// whose value is stored server-side and rendered unescaped on a (usually
// different) page later. ReflectedXSS catches the case where the same
// request that submits the input also echoes it; this check covers the
// gap where the storage write and the rendering read are split across
// requests, which most real comment/profile/forum bugs are.
//
// The check runs across two scanner phases:
//
//  1. Phase 1 (Plant): for every Sink on every in-scope page, send a
//     small fixed family of XSS payloads, each carrying a fresh canary.
//     Three payloads cover the dominant storage contexts (HTML text,
//     double-quoted attribute, JS double-quoted string) - if the sink
//     stores content for later rendering, at least one of these will
//     round-trip intact on whichever detect page actually renders the
//     value. Each (method, URL, loc, name) sink plants exactly once
//     across the whole scan; the same form discovered on N crawled
//     pages does not burn 3*N plant requests. Plant responses are
//     also mined for same-origin URLs (Location header, body links)
//     that the crawler hadn't seen, so a "view your post" redirect
//     target reachable only after submission still gets a detect-pass
//     re-fetch.
//
//  2. Phase 2 (Detect): the scanner re-fetches every URL in the
//     visited+DetectURLs union and hands each response body to Detect.
//     Detect extracts every canary-shaped token from the body, looks
//     each one up in the planted map, and fires a high-severity
//     finding when the full payload bytes - the breakout, not just the
//     canary - survived encoding. A canary that appears without its
//     surrounding breakout means the application stored the input but
//     encoded it correctly; that case is intentionally silent here
//     (the same bar the ReflectedXSS check uses for "exploitable").
//
// This is a state-mutating check: plants persist on the target until
// the operator removes them. Unlike ProtoPollution there is no useful
// cleanup pass - the whole point of the check is that the input
// survives the scan. StoredXSS only loads when the operator runs with
// --pollute, the same gate ProtoPollution sits behind.
//
// Severity is High when a breakout round-trips intact. The check does
// not chain to a screenshot or executor; the round-trip proof is the
// same standard ReflectedXSS uses.
type StoredXSS struct {
	mu sync.Mutex
	// plantedSinks records (method, URL, loc, name) keys that have
	// already been planted by some earlier Plant call. Many crawled
	// pages can carry the same form, but the underlying sink is a
	// single attack surface; re-planting per page would burn N times
	// the requests for no extra signal.
	plantedSinks map[sinkKey]struct{}
	// canaries maps each minted canary back to the plant record it was
	// issued for. Detect walks every canary-shaped match in a re-fetched
	// body and uses this map to recover the original sink, payload, and
	// breakout bytes the canary belongs to.
	canaries map[string]*storedXSSPlant
	// detectURLs is the same-origin URL set harvested from plant
	// response bodies / Location headers during phase 1. The scanner
	// unions this with the crawler's visited set to build the phase-2
	// re-fetch list.
	detectURLs map[string]struct{}
	// detectFired tracks the (sink) keys that already produced a
	// finding during phase 2 so two different detect pages that both
	// render the same stored payload do not double-report. Per-sink
	// granularity matches the DedupeKey shape (ScopeParam over loc+name);
	// keeping the set here lets the in-process dedupe stay O(1) instead
	// of relying on the reporter's later collapse.
	detectFired map[sinkKey]struct{}
}

// sinkKey is the cross-page identity of a sink: same (method, url, loc,
// name) across many pages is one attack surface, not N. Used to dedupe
// plants and findings.
type sinkKey struct {
	method string
	url    string
	loc    Loc
	name   string
}

// storedXSSPlant is the per-canary record Detect consults when it finds
// a hpzc-shaped match in a re-fetched body. payload is the rendered
// wire bytes the plant sent (the breakout surrounding the canary);
// payloadName labels which member of the storedXSSPayloads family was
// used. plantURL is the URL the canary was submitted to and is used in
// both the finding evidence and the dedupe key. payloadCtx categorises
// the breakout shape so the finding text can describe what would execute.
type storedXSSPlant struct {
	sink        sinkKey
	payload     string
	payloadName string
	payloadCtx  string
	plantURL    string
}

func (*StoredXSS) Name() string { return "stored-xss" }

func (*StoredXSS) Level() Level { return LevelDefault }

// Budget gives Plant headroom for three sequential plant requests per
// sink across the page's full input surface. DefaultBudget (60s) is
// tight when a page exposes ten or more form sinks against a rate-
// limited target; 90s covers that envelope without inviting a runaway
// check to pin its worker for the full 3-minute ProtoPollution budget.
// Detect runs under a separate budget per re-fetched page, so this
// applies only to Plant.
func (*StoredXSS) Budget() time.Duration { return 90 * time.Second }

// storedXSSBodyCap bounds the response body Plant reads when mining for
// same-origin DetectURLs and the response body Detect scans for canary
// echoes. Picked larger than the reflected-XSS cap because the detect
// page is often a long listing (forum thread, comment feed, profile
// timeline) - a canary stored at position N can sit deep in the
// document.
const storedXSSBodyCap = 256 << 10

// storedXSSPayloads is the per-context payload family Plant fans out
// for each sink. Three covers HTML text, double-quoted attribute, and
// double-quoted JS string - the three contexts ~95% of real storage
// reads land in. Single-quoted attribute and JS-string variants are
// intentionally omitted: the cost of two more plant requests per sink
// is significant on a large scan, and double-quoted is the dominant
// HTML-spec convention (browsers normalise mixed quoting to double).
//
// Each payload is constructed so the canary {{TOKEN}} sits inside the
// breakout bytes - matching the breakout in a re-fetched body means
// the application stored the value AND failed to encode the outer
// markup, which is the exploitability bar this check fires on.
var storedXSSPayloads = []struct {
	Name     string
	Context  string
	Template string
}{
	{
		Name:     "html-text-svg",
		Context:  "HTML text",
		Template: `<svg onload=alert(1)>{{TOKEN}}</svg>`,
	},
	{
		Name:     "attr-double-break",
		Context:  "double-quoted attribute",
		Template: `"><svg onload=alert(1)>{{TOKEN}}</svg>`,
	},
	{
		Name:     "js-string-double-break",
		Context:  "JS double-quoted string",
		Template: `";alert(1);//{{TOKEN}}`,
	},
}

// canaryRe matches the wire form NewCanary produces: the fixed prefix
// followed by exactly canaryHexLen lowercase hex characters. Detect
// uses this to extract every plant-shaped token from a re-fetched body
// in one pass, then hashmap-lookup each match into the planted map.
var canaryRe = regexp.MustCompile(canaryPrefix + `[0-9a-f]{` + fmt.Sprintf("%d", canaryHexLen) + `}`)

// Plant is the phase-1 entry point. For every Sink visible on p, dedupe
// against the cross-page plantedSinks set, then send the curated
// payload family. Plant responses are mined for same-origin links that
// extend the phase-2 detect set. Findings are never returned here; the
// only way a stored-XSS hit can surface is through Detect, which sees
// the persistent state Plant left behind.
func (c *StoredXSS) Plant(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !allows(sc, u) {
		return nil, nil
	}
	sinks := SinksFor(p)
	if len(sinks) == 0 {
		return nil, nil
	}

	for _, sink := range sinks {
		if ctx.Err() != nil {
			break
		}
		if su, err := url.Parse(sink.URL); err == nil && !allows(sc, su) {
			continue
		}
		// One plant set per cross-page sink. The crawler hands us the
		// same form on every page that hosts it; without this check
		// the request count would scale with crawl depth instead of
		// with the attack surface.
		k := sinkKey{method: sink.Method, url: sink.URL, loc: sink.Loc, name: sink.Name}
		c.mu.Lock()
		if c.plantedSinks == nil {
			c.plantedSinks = map[sinkKey]struct{}{}
		}
		_, already := c.plantedSinks[k]
		if !already {
			c.plantedSinks[k] = struct{}{}
		}
		c.mu.Unlock()
		if already {
			continue
		}

		for _, pl := range storedXSSPayloads {
			if ctx.Err() != nil {
				break
			}
			tok := NewCanary()
			rendered := strings.ReplaceAll(pl.Template, tokenPlaceholder, tok)
			req, resp, body, err := c.send(ctx, client, sink, rendered)
			if err != nil {
				// Per-sink failures surface via Report (the scanner's
				// reporter is wired to onError); do not also return the
				// error from Plant - the scanner would re-emit it as a
				// second onError event for the same failure, and would
				// short-circuit the findings flush for any future
				// version of Plant that emits findings alongside errors.
				Report(ctx, fmt.Errorf("plant %s %s=%s payload=%s: %w", sink.Loc, sink.Name, sink.URL, pl.Name, err))
				continue
			}

			// Record the canary even if the plant response itself
			// doesn't appear to have stored anything visible -
			// the canary is what Detect uses to match against
			// every re-fetched body, not just this one.
			plantURL := sink.URL
			if req != nil && req.URL != nil {
				plantURL = req.URL.String()
			}
			c.recordPlant(tok, &storedXSSPlant{
				sink:        k,
				payload:     rendered,
				payloadName: pl.Name,
				payloadCtx:  pl.Context,
				plantURL:    plantURL,
			})

			// Mine the plant response for same-origin URLs the
			// crawler might not have visited. Location headers
			// from POST-redirect-GET flows are the highest-yield
			// source; body links cover apps that return the
			// rendered storage page directly.
			if resp != nil {
				c.absorbDetectURLs(plantURL, resp.Header.Get("Location"), body)
			}
		}
	}

	return nil, nil
}

// Run satisfies the Check interface. StoredXSS does not produce findings
// in a single-phase invocation: without phase-2 wiring there is no
// detect pass to observe persistence, and re-running Plant here would
// only double the request count. Returning nil keeps the check
// registerable in older single-phase scanner code paths without
// emitting misleading output.
func (c *StoredXSS) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	return nil, nil
}

// DetectURLs returns the same-origin URL set harvested from plant
// responses during phase 1. Called once between phases by the scanner;
// safe to call concurrently with in-flight Plant calls (mutex-guarded)
// though in practice the scanner waits for phase 1 to drain first.
func (c *StoredXSS) DetectURLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.detectURLs) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.detectURLs))
	for u := range c.detectURLs {
		out = append(out, u)
	}
	return out
}

// Detect is the phase-2 entry point. Walks every canary-shaped token in
// p.Body; for each token that traces back to one of our plants AND
// whose surrounding breakout bytes also appear intact in the body,
// emits a high-severity finding. Per-sink dedupe keeps a stored payload
// rendered on many detect pages collapsed to one finding.
func (c *StoredXSS) Detect(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	if len(p.Body) == 0 {
		return nil, nil
	}
	matches := canaryRe.FindAll(p.Body, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.canaries == nil {
		return nil, nil
	}

	var findings []Finding
	seenLocally := map[sinkKey]struct{}{}
	for _, m := range matches {
		plant, ok := c.canaries[string(m)]
		if !ok {
			continue
		}
		if _, dup := seenLocally[plant.sink]; dup {
			continue
		}
		// Cross-call dedupe: another detect page already fired this
		// sink's finding earlier in phase 2. Skip silently rather
		// than relying on the reporter's collapse so the operator
		// sees one finding per sink, not one per detect URL that
		// happened to render it.
		if c.detectFired == nil {
			c.detectFired = map[sinkKey]struct{}{}
		}
		if _, dup := c.detectFired[plant.sink]; dup {
			seenLocally[plant.sink] = struct{}{}
			continue
		}
		// The bar for "stored XSS": the rendered payload bytes -
		// breakout shell included - round-trip intact in the
		// detect-page body. A canary alone without the surrounding
		// breakout means the app stored the value but encoded its
		// outer markup; that's safe in this context and not
		// reported as stored-XSS (it could still be a different
		// finding class - leaked PII storage - which is outside
		// this check's remit).
		if !bytes.Contains(p.Body, []byte(plant.payload)) {
			continue
		}
		seenLocally[plant.sink] = struct{}{}
		c.detectFired[plant.sink] = struct{}{}
		findings = append(findings, Finding{
			Check:    c.Name(),
			Target:   plant.plantURL,
			URL:      p.URL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("Stored XSS in %s parameter %q", plant.sink.loc, plant.sink.name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) submitted to %s is stored server-side and rendered unescaped at %s (%s context). "+
					"Payload xss/%s round-tripped intact across the storage boundary - an attacker can plant script that fires for every visitor of the detect page.",
				plant.sink.name, plant.sink.loc, plant.plantURL, p.URL, plant.payloadCtx, plant.payloadName),
			CWE:   "CWE-79",
			OWASP: "A03:2021 Injection",
			Remediation: "Apply context-aware output encoding at the rendering boundary, not just at the storage one: " +
				"HTML-encode user input rendered into HTML text, attribute-encode for values placed in tag attributes, " +
				"and JavaScript-encode (or hand off via JSON) for values placed inside <script>. " +
				"Storing the raw user input is fine when every read path is guaranteed to escape - audit every template that renders this field.",
			Evidence: &Evidence{
				Method:     http.MethodGet,
				RequestURL: p.URL,
				Status:     p.Status,
				Snippet:    snippet(p.Body, []byte(plant.payload), false),
			},
			DedupeKey: MakeKey(c.Name(), ScopeParam, plant.plantURL, "loc:"+string(plant.sink.loc), "param:"+plant.sink.name),
		})
	}
	return findings, nil
}

// recordPlant stashes the canary -> plant record mapping. The write
// happens under the same mutex Plant uses for plantedSinks so a
// concurrent Detect can't observe a half-installed entry.
func (c *StoredXSS) recordPlant(canary string, plant *storedXSSPlant) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.canaries == nil {
		c.canaries = map[string]*storedXSSPlant{}
	}
	c.canaries[canary] = plant
}

// absorbDetectURLs extends the phase-2 detect set with same-origin URLs
// surfaced in the plant response: Location header (the POST-redirect-GET
// destination most write endpoints return) plus body links the
// application rendered in the immediate response. Cross-origin URLs are
// dropped here so an unrelated CDN reference in a 200 body doesn't get
// added to the re-fetch list (scope would drop it later anyway, but
// filtering early keeps the set small).
func (c *StoredXSS) absorbDetectURLs(plantURL, locationHeader string, body []byte) {
	base, err := url.Parse(plantURL)
	if err != nil {
		return
	}

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			return
		}
		if !strings.EqualFold(resolved.Host, base.Host) {
			return
		}
		resolved.Fragment = ""
		c.mu.Lock()
		if c.detectURLs == nil {
			c.detectURLs = map[string]struct{}{}
		}
		c.detectURLs[resolved.String()] = struct{}{}
		c.mu.Unlock()
	}

	if locationHeader != "" {
		add(locationHeader)
	}
	if len(body) > 0 {
		c.harvestBodyLinks(body, add)
	}
}

// harvestBodyLinks tokenises body and feeds add() with every navigable
// same-origin URL it finds: <a href>, <form action>, and the url= field
// inside <meta http-equiv="refresh">. Other link sources (img/script
// src, link rel=...) are intentionally skipped: the goal is to find
// pages where stored content might be rendered, not every asset.
func (c *StoredXSS) harvestBodyLinks(body []byte, add func(string)) {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				return
			}
			return
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		switch string(name) {
		case "a":
			for {
				k, v, more := z.TagAttr()
				if string(k) == "href" {
					add(string(v))
				}
				if !more {
					break
				}
			}
		case "form":
			for {
				k, v, more := z.TagAttr()
				if string(k) == "action" {
					add(string(v))
				}
				if !more {
					break
				}
			}
		case "meta":
			var equiv, content string
			for {
				k, v, more := z.TagAttr()
				switch string(k) {
				case "http-equiv":
					equiv = string(v)
				case "content":
					content = string(v)
				}
				if !more {
					break
				}
			}
			if strings.EqualFold(equiv, "refresh") {
				if u := parseMetaRefreshURL(content); u != "" {
					add(u)
				}
			}
		}
	}
}

// parseMetaRefreshURL extracts the url= field from a meta-refresh
// content attribute. The attribute shape is "N; url=DEST" where N is a
// seconds count and url= is case-insensitive. Returns "" when no url=
// field is present.
func parseMetaRefreshURL(content string) string {
	for _, part := range strings.Split(content, ";") {
		part = strings.TrimSpace(part)
		if len(part) < 4 {
			continue
		}
		if strings.EqualFold(part[:4], "url=") {
			return strings.Trim(part[4:], `"' `)
		}
	}
	return ""
}

// send issues a single plant request through Sink.MutateRequest, reads
// the response body up to storedXSSBodyCap, and closes the body before
// returning. Returns the request (for plantURL recovery), the response,
// and the captured body slice. Mirrors ReflectedXSS.send but ignores
// the truncation flag - body harvesting tolerates a clipped tail.
func (c *StoredXSS) send(ctx context.Context, client *httpclient.Client, sink Sink, payload string) (*http.Request, *http.Response, []byte, error) {
	req, err := sink.MutateRequest(ctx, payload)
	if err != nil {
		return nil, nil, nil, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, err
	}
	defer resp.Body.Close()
	body, _, err := httpclient.ReadBodyCapped(resp, storedXSSBodyCap)
	if err != nil {
		return req, resp, nil, err
	}
	return req, resp, body, nil
}

// allows wraps scope.Scope.Allows so a nil scope (the unconstrained
// default) permits everything. Centralised here so Plant doesn't repeat
// the nil-check at every callsite; the rest of the package uses the
// same convention through scope.Scope.Allows directly.
func allows(sc *scope.Scope, u *url.URL) bool {
	if sc == nil {
		return true
	}
	return sc.Allows(u)
}
