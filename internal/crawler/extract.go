package crawler

import (
	"net/url"
	"regexp"
)

var linkRegex = regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']([^"'\s>]+)["']`)

// extractLinks pulls href/src targets out of an HTML body and resolves them
// against base. Non-http(s) schemes are dropped; fragments are stripped so
// "#section" anchors don't produce duplicate visits.
func extractLinks(base *url.URL, body []byte) []string {
	matches := linkRegex.FindAllSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		ref, err := url.Parse(string(m[1]))
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		resolved.Fragment = ""
		s := resolved.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
