package injection

import "strings"

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

func looksProxyish(path string) bool {
	p := strings.ToLower(path)
	for _, kw := range ssrfPathKeywords {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
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
