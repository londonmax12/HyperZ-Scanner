package lua_engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
)

// SSRF probes whether a target application will fetch an attacker-controlled
// URL via a URL parameter (e.g., image proxy, webhook, fetch endpoint). For
// each candidate Sink the check issues a no-follow request with the param
// set to a canary on a reserved (.example) domain; a response that contains
// certain error signatures (connection refused, name resolution failure,
// timeout, etc.) suggests the server attempted to reach the canary host.
//
// Candidates are chosen to bound probe volume:
//   - sinks with names suggesting URL acceptance (url, uri, fetch, proxy,
//     endpoint, webhook, etc.) are always probed.
//   - additional "generic" URL parameter names are only probed on URLs with
//     path keywords hinting at proxy/webhook functionality.
//
// This is an active (LevelDefault) check; it only runs when the user opts
// into a `default` or `aggressive` scan. Per-host rate limiting in the
// HTTP client governs probe pacing.
type SSRF struct{}

const (
	// ssrfCanary uses RFC 2606 .example so the host is guaranteed
	// unregistered. The path marker makes the probe easy to spot in target
	// access logs.
	ssrfCanary  = "http://internal.example:8080/hyperz-probe"
	ssrfBodyCap = 8 << 10
)

// ssrfErrorPatterns are response content markers that indicate the server
// attempted to fetch the canary URL and encountered a network/DNS error.
// These signatures come from common libraries and frameworks across
// different languages (Python requests, Go http, Node.js, PHP curl, etc.).
var ssrfErrorPatterns = []string{
	// DNS failures
	"getaddrinfo failed",
	"nodename nor servname provided",
	"name or service not known",
	"no address associated with hostname",
	"temporary failure in name resolution",
	"host not found",
	"cannot resolve host",
	"unknown host",
	// Connection refused
	"connection refused",
	"econnrefused",
	"connection reset by peer",
	"reset by peer",
	// Connection timeouts
	"connection timed out",
	"operation timed out",
	"dial tcp",
	"timeout",
	// Proxy/fetch library errors
	"failed to fetch",
	"httperror",
	"socket timeout",
	"unable to connect",
	"unreachable",
	// Python requests specific
	"connectionerror",
	"requests.exceptions",
	// Node.js specific
	"enotfound",
	"request to",
	// Java specific
	"unknownhostexception",
	"connectexception",
	// PHP specific
	"failed to open stream",
	"could not resolve host",
	// Ruby specific
	"connection refused -- connect",
	"getaddrinfo",
	// Generic fetch/request patterns
	"fetch error",
	"request failed",
	"failed to request",
}

// ssrfSpecificParamNames are parameter names strongly indicating URL-fetch
// functionality. These are always probed.
var ssrfSpecificParamNames = []string{
	"url",
	"uri",
	"endpoint",
	"target",
	"fetch",
	"proxy",
	"image_url",
	"image_uri",
	"webhook",
	"callback",
	"callback_url",
	"callback_uri",
	"return_url",
	"return_uri",
	"source",
	"source_url",
	"destination",
	"request_url",
}

// ssrfGenericParamNames are additional parameter names only probed when
// the page looks like it handles proxying/webhooks based on path keywords.
var ssrfGenericParamNames = []string{
	"q",
	"query",
	"link",
	"page",
	"resource",
	"data",
	"content",
	"http",
}

// ssrfPathKeywords are path substrings that flag a URL as likely handling
// URL fetches (proxy, image handling, webhook receivers, etc.).
var ssrfPathKeywords = []string{
	"proxy",
	"fetch",
	"image",
	"avatar",
	"webhook",
	"callback",
	"export",
	"report",
	"download",
	"preview",
	"screenshot",
}

// probeOOB issues one no-follow request with an OOB canary URL planted in
// sink.Name. The check does NOT emit a finding from this call: callbacks
// land asynchronously on the OOB listener, so detection is deferred to
// the Drain pass after the scanner's OOB wait window elapses. The body
// is drained and discarded - the listener-side hit is the signal.
func (c SSRF) probeOOB(ctx context.Context, client *httpclient.Client, srv oob.Server, target string, sink Sink) error {
	canary := srv.Register("ssrf", map[string]string{
		"target": target,
		"sink":   sink.Name,
		"loc":    string(sink.Loc),
		"method": sink.Method,
	})
	req, err := sink.MutateRequest(ctx, canary.HTTPURL)
	if err != nil {
		return err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Read a small chunk so the connection returns to the pool cleanly.
	// We cap aggressively because the response body has no signal here.
	_, _, _ = httpclient.ReadBodyCapped(resp, 1<<10)
	return nil
}

// buildSSRFOOBFinding renders one OOB-confirmed SSRF finding from the
// canary registration and the hits it received. Severity is Critical:
// an OOB callback proves the target both fetched the URL AND reached
// the scanner's egress, the strongest evidence the SSRF check can
// produce. The in-band path tops out at High because it relies on a
// reflected error string.
func buildSSRFOOBFinding(reg oob.Registration, hits []oob.Hit) Finding {
	target := reg.Extra["target"]
	sink := reg.Extra["sink"]
	loc := reg.Extra["loc"]
	method := reg.Extra["method"]
	hit := hits[0]
	ua := hit.Headers.Get("User-Agent")
	return Finding{
		Check:    "ssrf",
		Target:   target,
		URL:      target,
		Severity: SeverityCritical,
		Title:    fmt.Sprintf("Server-Side Request Forgery (OOB-confirmed) via %s %s", loc, sink),
		Detail: fmt.Sprintf(
			"Parameter %q (%s) accepts a URL that the server fetches. "+
				"Probe with canary %s caused the target to issue a request that landed on the OOB "+
				"listener (method=%s, source=%s, user-agent=%q, %d hit(s)). "+
				"An attacker can craft URLs to probe internal network, bypass authentication, "+
				"or attack internal services.",
			sink, loc, reg.Canary.HTTPURL, hit.Method, hit.SourceAddr, ua, len(hits)),
		CWE:   "CWE-918",
		OWASP: "A10:2021 Server-Side Request Forgery (SSRF)",
		Remediation: "Validate and restrict the URL parameter to a strict allowlist of domains/hosts. " +
			"Disable access to private/internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1). " +
			"Use a URL parsing library that properly validates scheme and host. Never fetch arbitrary user-supplied URLs.",
		Evidence: &Evidence{
			Method:     method,
			RequestURL: target,
			Snippet: fmt.Sprintf(
				"Canary URL: %s\nFirst hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
				reg.Canary.HTTPURL,
				hit.Method, hit.Path, hit.SourceAddr,
				hit.Timestamp.Format(time.RFC3339), ua, len(hits)),
		},
		DedupeKey: MakeKey("ssrf", ScopeParam, target, "loc:"+loc, "param:"+sink, "oob"),
	}
}

// ssrfSinks returns the deduped, sorted set of Sinks to probe.
func ssrfSinks(p page.Page, u *url.URL, sweep bool) []Sink {
	type key struct {
		method string
		url    string
		loc    Loc
		name   string
	}
	seen := map[key]struct{}{}
	add := func(out []Sink, s Sink) []Sink {
		if s.Name == "" || s.URL == "" {
			return out
		}
		k := key{s.Method, s.URL, s.Loc, s.Name}
		if _, ok := seen[k]; ok {
			return out
		}
		seen[k] = struct{}{}
		return append(out, s)
	}

	var out []Sink
	for _, s := range SinksFor(p) {
		out = add(out, s)
	}

	// Always probe sinks with names that strongly suggest URL handling
	for _, name := range ssrfSpecificParamNames {
		out = add(out, Sink{
			Method: http.MethodGet,
			URL:    p.URL,
			Loc:    LocQuery,
			Name:   name,
		})
	}

	// Probe generic names only when the page looks like it fetches URLs
	if sweep {
		for _, name := range ssrfGenericParamNames {
			out = add(out, Sink{
				Method: http.MethodGet,
				URL:    p.URL,
				Loc:    LocQuery,
				Name:   name,
			})
		}
	}

	return out
}

func looksProxyish(path string) bool {
	p := strings.ToLower(path)
	for _, kw := range ssrfPathKeywords {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
}

// probe issues one no-follow request with the canary URL overlaid onto
// sink.Name. Returns a finding when the response body contains error
// signatures indicating the server attempted to fetch the canary host.
func (c SSRF) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	req, err := sink.MutateRequest(ctx, ssrfCanary)
	if err != nil {
		return nil, err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, truncated, err := httpclient.ReadBodyCapped(resp, ssrfBodyCap)
	if err != nil {
		return nil, err
	}

	// Check for SSRF error markers in the response body
	matchedPattern := ssrfMatchesError(body)
	if matchedPattern == "" {
		return nil, nil
	}

	probeURL := req.URL.String()
	return &Finding{
		Check:    "ssrf",
		Target:   target,
		URL:      probeURL,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("Server-Side Request Forgery via %s ?%s=", sink.Loc, sink.Name),
		Detail: fmt.Sprintf(
			"Parameter %q (%s) accepts a URL that the server fetches. "+
				"Probe with %s triggered server-side request attempt; "+
				"response contains error signature %q indicating connection failure. "+
				"An attacker can craft URLs to probe internal network, bypass authentication, or attack internal services.",
			sink.Name, sink.Loc, ssrfCanary, matchedPattern),
		CWE:   "CWE-918",
		OWASP: "A10:2021 Server-Side Request Forgery (SSRF)",
		Remediation: "Validate and restrict the URL parameter to a strict allowlist of domains/hosts. " +
			"Disable access to private/internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1). " +
			"Use a URL parsing library that properly validates scheme and host. Never fetch arbitrary user-supplied URLs.",
		Evidence: &Evidence{
			Method:     req.Method,
			RequestURL: probeURL,
			Status:     resp.StatusCode,
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		DedupeKey: MakeKey("ssrf", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
	}, nil
}

// ssrfMatchesError returns the first matched error pattern from the body,
// or empty string if no match found. Comparison is case-insensitive.
func ssrfMatchesError(body []byte) string {
	bodyLower := strings.ToLower(string(body))
	for _, pattern := range ssrfErrorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return pattern
		}
	}
	return ""
}
