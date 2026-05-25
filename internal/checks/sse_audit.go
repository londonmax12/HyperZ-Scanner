package checks

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// SSEAudit probes Server-Sent Events (text/event-stream) endpoints for
// cross-origin disclosure. SSE is a long-lived GET that browsers expose
// to JavaScript via EventSource; like fetch() it is subject to CORS, so
// an endpoint that returns Access-Control-Allow-Origin: * (or echoes a
// foreign Origin alongside credentials) leaks every event in the stream
// to any web page the victim happens to visit.
//
// Discovery is two-tracked:
//
//   1. Self-evidence: the already-fetched page response is itself an SSE
//      stream (Content-Type: text/event-stream). The check uses the
//      page's own URL as the probe target.
//   2. Body refs: the page body contains `new EventSource(...)` literals
//      whose URL argument the regex extracts. Captures both quoted and
//      template-literal arguments; bare-variable arguments are out of
//      scope for a passive body scan.
//
// Per endpoint: at most one probe GET with a foreign Origin. The probe
// uses a short read (read-and-cancel) so a real event stream does not
// stall the worker - we only need the response headers to decide.
//
// Active (LevelDefault) check.
type SSEAudit struct{}

func (SSEAudit) Name() string { return "sse-audit" }

func (SSEAudit) Level() Level { return LevelDefault }

const (
	// sseBodyCap bounds how much of the page body the check scans for
	// EventSource literals. Matches the other passive HTML / JS scanners
	// in the catalog.
	sseBodyCap = 2 << 20
	// sseProbeBodyCap bounds how much of the probe response body we
	// keep. SSE responses can be open-ended (the server holds the
	// stream); we read at most this much before closing the connection.
	// 4 KiB is enough for the initial `event: ...` / `data: ...` frame
	// to land in evidence without buffering the full stream.
	sseProbeBodyCap = 4 << 10
	// sseAttackerOrigin is the foreign Origin presented during the
	// cross-origin probe. example.com is reserved by IANA and will
	// never appear in a legitimate allowlist.
	sseAttackerOrigin = "https://hyperz-attacker.example"
	// sseMaxEndpointsPerPage caps how many distinct SSE endpoints we
	// probe from one page. Real apps almost never expose more than one
	// or two; the cap protects against pathological config blobs.
	sseMaxEndpointsPerPage = 5
)

// sseEventSourceRE matches `new EventSource("url")`,
// `new EventSource('url')`, and `new EventSource(`url`)` constructions.
// The URL is captured in group 1; the three quote styles are all
// accepted. Whitespace between `new`, `EventSource`, and the opening
// paren is tolerated to match prettified bundles. Bare-variable
// arguments (new EventSource(streamURL)) are out of scope for a passive
// body scan because the URL string never appears at the call site.
var sseEventSourceRE = regexp.MustCompile(
	"(?i)new\\s+EventSource\\s*\\(\\s*[`'\"]([^`'\"\\s]+)[`'\"]",
)

func (c SSEAudit) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	pageURL, err := url.Parse(p.URL)
	if err != nil || pageURL.Host == "" {
		return nil, nil
	}
	if !sc.Allows(pageURL) {
		return nil, nil
	}

	endpoints := discoverSSEEndpoints(p, pageURL)
	if len(endpoints) == 0 {
		return nil, nil
	}

	var findings []Finding
	probed := 0
	for _, ep := range endpoints {
		if probed >= sseMaxEndpointsPerPage {
			break
		}
		epURL, err := url.Parse(ep)
		if err != nil || epURL.Host == "" {
			continue
		}
		// Same-host filter: third-party SSE endpoints aren't ours to
		// probe, and probing them is out-of-scope by default.
		if !strings.EqualFold(epURL.Hostname(), pageURL.Hostname()) {
			continue
		}
		if !sc.Allows(epURL) {
			continue
		}

		probed++
		f, err := c.probe(ctx, client, ep)
		if err != nil {
			Report(ctx, fmt.Errorf("sse-audit probe %s: %w", ep, err))
			continue
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

// probe issues one GET with a foreign Origin and inspects the response
// for the combination that lets an attacker page read the stream:
//
//   - Content-Type must be text/event-stream (confirms it's SSE, not a
//     redirect to a login page or a plain JSON error). Without that,
//     CORS posture doesn't matter - there's no stream to read.
//   - Access-Control-Allow-Origin must permit the attacker's origin,
//     either by wildcard or by echoing it back.
//   - Access-Control-Allow-Credentials elevates severity: credentials
//     in cookies / authorization headers ride along, so the attacker
//     reads authenticated stream content.
//
// Returns nil when CORS is correctly restrictive or when the endpoint
// turns out not to be SSE.
func (c SSEAudit) probe(ctx context.Context, client *httpclient.Client, target string) (*Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Origin", sseAttackerOrigin)
	// Stream pacing: SSE servers typically push the first event
	// immediately, but a chatty one might withhold. Cache-Control: no-cache
	// matches what EventSource sends and avoids hitting a stale 304.
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !isEventStream(ct) {
		return nil, nil
	}

	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")

	severity, title, detail := classifySSECors(acao, acac, target)
	if severity == "" {
		// CORS posture is fine (no ACAO, or the server only allows its
		// own origin). The endpoint exists but is not cross-origin
		// readable; nothing to flag.
		return nil, nil
	}

	body, truncated, err := httpclient.ReadBodyCapped(resp, sseProbeBodyCap)
	if err != nil {
		// A short read on an open stream is normal; surface only
		// non-EOF errors as probe failures.
		Report(ctx, fmt.Errorf("sse-audit read %s: %w", target, err))
	}

	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: severity,
		Title:    title,
		Detail:   detail,
		CWE:      "CWE-942",
		OWASP:    "A05:2021 Security Misconfiguration",
		Remediation: "Validate the request Origin against a hardcoded allowlist before echoing it into " +
			"Access-Control-Allow-Origin. SSE has no built-in same-origin protection; the only thing keeping a " +
			"foreign page from reading the stream via EventSource is server-side CORS. If the stream MUST be public, " +
			"remove credentials from the channel (sessionless tokens in the URL or first message) so a permissive " +
			"ACAO does not leak authenticated content.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: target,
			Status:     resp.StatusCode,
			Snippet:    buildSSESnippet(resp, body),
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		DedupeKey: MakeKey(c.Name(), ScopePage, target, "cors:"+severityCorsKey(acao, acac)),
	}, nil
}

// classifySSECors returns the finding severity, title, and detail for
// the observed CORS posture, or ("", "", "") when the posture does not
// expose the stream cross-origin.
//
// The shape mirrors cors-config's logic but with SSE-specific framing:
// the impact is "any web page can read this live stream," not "any
// origin can call this endpoint."
func classifySSECors(acao string, acac bool, target string) (Severity, string, string) {
	switch {
	case acao == "":
		return "", "", ""

	case acao == "*" && acac:
		// Browsers refuse the spec-illegal `*` + credentials
		// combination at runtime, but the configuration signals the
		// server misunderstands the credentials contract. Frame it as
		// a misconfiguration the operator should fix rather than a
		// directly exploitable one.
		return SeverityMedium,
			"SSE endpoint sets wildcard CORS with credentials (spec-illegal)",
			fmt.Sprintf("SSE endpoint %s returned Access-Control-Allow-Origin: * together with "+
				"Access-Control-Allow-Credentials: true. The CORS spec forbids this combination; browsers refuse to "+
				"deliver the stream, but the configuration indicates the credentials contract is misunderstood and is "+
				"often paired with a more permissive variant on a sibling endpoint.", target)

	case acao == "*":
		return SeverityMedium,
			"SSE endpoint is readable from any origin",
			fmt.Sprintf("SSE endpoint %s returned Access-Control-Allow-Origin: *. Any web page the victim visits can "+
				"open an EventSource against this URL and read every event the server pushes. Credentials do NOT ride "+
				"along on wildcard CORS, so authenticated stream content is not exposed directly - but stream content "+
				"that does not require credentials (public counters, feature flag values, telemetry) is now harvestable "+
				"cross-origin.", target)

	case strings.EqualFold(acao, "null"):
		return SeverityMedium,
			"SSE endpoint trusts the null origin",
			fmt.Sprintf("SSE endpoint %s returned Access-Control-Allow-Origin: null. Sandboxed iframes, data: URIs, "+
				"and file: contexts all present as the null origin; trusting it lets attacker-controlled documents in "+
				"those contexts read the stream%s.", target, sseCredSuffix(acac))

	case strings.EqualFold(acao, sseAttackerOrigin):
		// The server echoed our spoofed Origin verbatim, which is the
		// classic reflective-CORS bug. With credentials this is high;
		// without, still notable because anyone who can guess a target
		// origin (i.e. anyone) can drink from the stream.
		if acac {
			return SeverityHigh,
				"SSE endpoint reflects arbitrary Origin with credentials",
				fmt.Sprintf("SSE endpoint %s echoed the attacker-supplied Origin (%s) into "+
					"Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true. Any web page the "+
					"victim visits can open an EventSource against this URL with the victim's cookies attached and read "+
					"the entire authenticated stream in real time.", target, sseAttackerOrigin)
		}
		return SeverityMedium,
			"SSE endpoint reflects arbitrary Origin",
			fmt.Sprintf("SSE endpoint %s echoed the attacker-supplied Origin (%s) into Access-Control-Allow-Origin. "+
				"Credentials are not in the ACAO scope, but any origin can still open the stream and read the events.",
				target, sseAttackerOrigin)
	}
	return "", "", ""
}

// sseCredSuffix appends a credentials qualifier when ACAC is on. Used
// in detail prose so the null-origin (and similar) findings can call
// out the elevated impact without changing the title.
func sseCredSuffix(acac bool) string {
	if acac {
		return " (Access-Control-Allow-Credentials: true compounds the impact by exposing the authenticated stream)"
	}
	return ""
}

// severityCorsKey collapses the relevant ACAO/ACAC posture into a stable
// dedupe component. Two findings with different CORS shapes on the same
// endpoint are genuinely different issues; identical shapes on the same
// endpoint should collapse.
func severityCorsKey(acao string, acac bool) string {
	creds := "0"
	if acac {
		creds = "1"
	}
	return strings.ToLower(acao) + ":" + creds
}

// buildSSESnippet renders a compact response summary for Evidence.Snippet.
// Includes status, Content-Type, the CORS headers, and the first few
// bytes of the body (typically the first SSE frame).
func buildSSESnippet(resp *http.Response, body []byte) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for _, k := range []string{
		"Content-Type",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Cache-Control",
	} {
		if v := resp.Header.Get(k); v != "" {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	if len(body) > 0 {
		sb.WriteByte('\n')
		sb.Write(body)
	}
	return sb.String()
}

// discoverSSEEndpoints returns the deduped, stable-ordered list of SSE
// endpoint URLs derivable from p. Two sources are merged: the page URL
// itself when its response Content-Type is text/event-stream, and any
// `new EventSource(...)` literals found in the body. Body-derived URLs
// are resolved against the page URL so relative paths land at the right
// host.
func discoverSSEEndpoints(p page.Page, pageURL *url.URL) []string {
	seen := map[string]struct{}{}
	add := func(raw string) {
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := pageURL.ResolveReference(ref)
		if resolved.Host == "" {
			return
		}
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			return
		}
		seen[resolved.String()] = struct{}{}
	}

	// Track 1: the page IS the SSE endpoint.
	if p.Headers != nil && isEventStream(p.Headers.Get("Content-Type")) {
		add(p.URL)
	}

	// Track 2: EventSource literals in the body.
	if len(p.Body) > 0 {
		scan := p.Body
		if len(scan) > sseBodyCap {
			scan = scan[:sseBodyCap]
		}
		for _, m := range sseEventSourceRE.FindAllSubmatch(scan, -1) {
			if len(m) >= 2 {
				add(string(m[1]))
			}
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isEventStream reports whether ct (a Content-Type header value) names
// an SSE stream. Parameters (charset, boundary) are stripped before
// comparison so a perfectly labeled response is not skipped on a
// technicality.
func isEventStream(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "text/event-stream")
}
