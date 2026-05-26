package lua_engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// HostHeaderInjection probes whether the Host header is reflected in the
// response body or used to generate absolute URLs. An unsafely-used Host
// header can be exploited for cache poisoning, password reset link hijacking,
// and SSRF-like attacks via host-based routing. The check injects a canary
// domain into the Host header and searches the response for reflection.
//
// This is an active (LevelDefault) check; it only runs when the user opts
// into a `default` or `aggressive` scan.
type HostHeaderInjection struct{}

const (
	// hostHeaderCanary is a reserved (.example) domain used to probe for
	// reflection. RFC 2606 guarantees it's unregistered.
	hostHeaderCanary  = "evil.example"
	hostHeaderBodyCap = 4 << 10
)

// probe issues a request with an injected Host header and checks for
// reflection in the response. Returns a Finding if the canary host
// appears in the response body, or (nil, nil) otherwise.
func (c HostHeaderInjection) probe(ctx context.Context, client *httpclient.Client, target string, u *url.URL) (*Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	// Preserve the original request structure but override the Host header.
	// This is the Host header that will be sent to the server (not Host: field
	// manipulation which would break the request).
	req.Host = hostHeaderCanary
	req.Header.Set("Host", hostHeaderCanary)

	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, truncated, err := httpclient.ReadBodyCapped(resp, hostHeaderBodyCap)
	if err != nil {
		return nil, err
	}

	// Check for reflection of the canary host in common patterns:
	// 1. Exact match: evil.example
	// 2. URL format: https://evil.example or http://evil.example
	// 3. Host-only format: evil.example/path
	bodyLower := strings.ToLower(string(body))
	if !strings.Contains(bodyLower, strings.ToLower(hostHeaderCanary)) {
		return nil, nil
	}

	return &Finding{
		Check:    "host-header-injection",
		Target:   target,
		URL:      target,
		Severity: SeverityHigh,
		Title:    "Host header reflected in response",
		Detail: fmt.Sprintf(
			"The Host header is reflected unsafely in the response body. "+
				"When probed with Host: %s, the response contained the injected host value. "+
				"This can lead to cache poisoning, password reset link hijacking, SSRF via routing, and authentication bypass. "+
				"An attacker can control the Host header in HTTP/1.1 requests to inject content into cache entries or response-generation logic.",
			hostHeaderCanary),
		CWE:   "CWE-74",
		OWASP: "A06:2021 Vulnerable and Outdated Components",
		Remediation: "Whitelist the allowed Host header values and validate incoming Host headers against this list. " +
			"Use absolute URLs from configuration (not derived from the Host header) for sensitive operations like password resets. " +
			"Implement cache-busting strategies per Host header variant, or use Host-independent cache keys. " +
			"Use HTTP/2 or enforce Host header validation at the proxy layer.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: target,
			Status:     resp.StatusCode,
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		// Dedupe per host: the same vulnerable page hit from many entry points
		// is one issue per host.
		DedupeKey: MakeKey("host-header-injection", ScopeHost, target),
	}, nil
}
