package lua_engine

import (
	"mime"
	"regexp"
	"strings"
)

// sseBodyCap bounds how much of the page body the check scans for
// EventSource literals. Matches the other passive HTML / JS scanners
// in the catalog.
const sseBodyCap = 2 << 20

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
