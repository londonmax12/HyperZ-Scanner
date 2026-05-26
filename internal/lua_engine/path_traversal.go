package lua_engine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// PathTraversal probes whether a user-influenced input is concatenated
// into a filesystem path, by sending canonical `../` escapes (plus URL-
// encoded, double-encoded, nested, null-byte, and Windows variants) and
// scanning the response for the disclosed contents of /etc/passwd or
// the Windows hosts file. A match on TraversalMarkers is the smoking
// gun - those byte sequences are short enough not to false-positive on
// prose but specific enough that any appearance means a privileged file
// just rode out through an unrelated HTTP response.
//
// Blast radius is bounded by an input-surface heuristic. At LevelDefault
// the check only probes sinks whose param name looks file-ish (file,
// path, include, template, ...) OR whose existing value carries a
// path-shaped character (`/`, `\`, `.`). At LevelAggressive every Sink
// is probed regardless. Without the gating an 8-sink page would burn
// ~50 requests; with it, the noisy fan-out is reserved for parameters
// the app actively treats as filenames.
//
// A baseline probe per sink suppresses false positives on pages that
// legitimately render the marker text (a sysadmin docs page describing
// /etc/passwd format). Markers already present in the baseline body are
// subtracted from subsequent matches, so only newly-disclosed file
// content fires a finding.
//
// Active (LevelDefault) check.
type PathTraversal struct{}

// pathTraversalBodyCap bounds the response body the check reads.
// /etc/passwd is small (typically <4 KiB) and ships near the top of any
// page that mistakenly embeds it; 32 KiB covers the case where a
// templated wrapper pushes the file body past the first KiB.
const pathTraversalBodyCap = 32 << 10

// pathParamKeywords are param-name substrings that mark a sink as
// "probably consumed as a filesystem path." Matched case-insensitively
// against the param name. Loose by design - false positives just cost
// a few extra probes; missing a real path param costs a missed finding.
var pathParamKeywords = []string{
	"file",
	"filename",
	"path",
	"page",
	"doc",
	"document",
	"template",
	"tpl",
	"include",
	"dir",
	"folder",
	"src",
	"view",
	"load",
	"read",
	"image",
	"img",
}

// pathSinkCandidate reports whether sink looks worth probing at
// LevelDefault. The two signals: a path-ish name, or a value that
// already carries a path-shaped character. Either one moves the sink
// out of "noise" territory; both are loose enough to err on the side
// of coverage.
func pathSinkCandidate(s Sink) bool {
	name := strings.ToLower(s.Name)
	for _, kw := range pathParamKeywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return strings.ContainsAny(s.Value, "/\\.")
}

// probe runs the baseline + payload sweep for one sink. The baseline
// captures any TraversalMarkers already present in the page (a doc
// site, an admin help screen) so the payload-stage match can subtract
// them and only fire on newly-disclosed file content.
func (c PathTraversal) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	canary := NewCanary()
	_, _, baselineBody, _, err := c.send(ctx, client, sink, canary)
	if err != nil {
		return nil, err
	}
	baselineHits := matchTraversalMarkers(baselineBody)

	for _, p := range PayloadsFor(PayloadTraversal) {
		if ctx.Err() != nil {
			break
		}
		// Traversal payloads must replace the value entirely - prepending
		// the original ("42../../../../etc/passwd") doesn't traverse on
		// any backend that joins inputs as a path component.
		req, resp, body, truncated, err := c.send(ctx, client, sink, p.Template)
		if err != nil {
			Report(ctx, fmt.Errorf("path-traversal payload %s %s=%s pl=%s: %w",
				sink.Loc, sink.Name, sink.URL, p.Name, err))
			continue
		}
		hits := matchTraversalMarkers(body)
		newHits := subtractPatterns(hits, baselineHits)
		if len(newHits) == 0 {
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
		status := statusOf(resp)
		return &Finding{
			Check:    "path-traversal",
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("Path traversal in %s parameter %q", sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) is concatenated into a filesystem path: payload path-traversal/%s "+
					"(wire value %q) caused the response to disclose %q - a sensitive system file. "+
					"An attacker can read arbitrary files reachable by the server process.",
				sink.Name, sink.Loc, p.Name, p.Template, newHits[0]),
			CWE:   "CWE-22",
			OWASP: "A01:2021 Broken Access Control",
			Remediation: "Resolve user-supplied paths against a fixed root and reject any result that escapes it " +
				"(filepath.Clean + prefix check, or chroot-equivalent containment). Never pass raw user input to " +
				"os.Open / fs.ReadFile - even after a regex filter, encoded variants (`..%2f`, `....//`) bypass naive " +
				"defenses. Prefer opaque IDs that map to allowlisted filenames server-side.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     status,
				Snippet:    snippet(body, []byte(newHits[0]), false),
				Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey("path-traversal", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	return nil, nil
}

// send mutates sink with wireValue, dispatches the request, and reads
// up to pathTraversalBodyCap of the body. Mirrors the sibling active
// checks' send shape so the per-check shells stay structurally aligned.
func (c PathTraversal) send(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, pathTraversalBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}

// matchTraversalMarkers returns every TraversalMarkers entry that
// appears in body. Markers are case-sensitive byte sequences - the
// disclosed file content (passwd line shape, Windows hosts banner) is
// emitted verbatim by the OS, so a case-folded scan would only add
// false-positive surface.
func matchTraversalMarkers(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var hits []string
	for _, m := range TraversalMarkers() {
		if bytes.Contains(body, []byte(m)) {
			hits = append(hits, m)
		}
	}
	return hits
}
