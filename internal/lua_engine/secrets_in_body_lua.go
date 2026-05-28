package lua_engine

import "sort"

// This file exposes the secrets-in-body check's helpers to the Lua
// bridge. Sibling to secrets_in_body.go: the pattern catalogue + the
// per-pattern matching loop stay in Go (440 lines of regex) and the
// Lua port owns only the surrounding orchestration.

// IsScannableContentType reports whether ct is a text-shaped body that
// is worth running the secret-pattern scanner over. Binary types
// (images, fonts, archives) are filtered out so the regex sweep is not
// wasted on bytes that can not legitimately carry a credential string.
func IsScannableContentType(ct string) bool { return isScannableContentType(ct) }

// SecretHit is one match the secret scanner found in a body. Pattern
// metadata is exposed verbatim so the Lua port can build the per-hit
// detail strings the Go check produces; Raw is the un-redacted bytes
// (caller is expected to redact before they reach the report) and
// Count collapses repeat hits of the same exact token in the same
// body.
type SecretHit struct {
	ID       string
	Label    string
	Severity Severity
	Raw      string
	Count    int
}

// ScanSecretsInBody runs the full secret-pattern catalogue over body
// and returns hits in the same (severity desc, id, redacted form)
// order the Go check produces. The Lua port consumes this directly
// and only owns the surrounding orchestration (Detail lead-in, title,
// dedupe key composition).
func ScanSecretsInBody(body []byte) []SecretHit {
	if len(body) == 0 {
		return nil
	}
	type key struct{ id, raw string }
	seen := map[key]*secretHit{}
	for _, pat := range secretPatterns {
		matches := pat.re.FindAllIndex(body, -1)
		for _, m := range matches {
			if pat.contextRE != nil && !HasNearbyContext(body, m[0], m[1], pat.contextRE) {
				continue
			}
			raw := string(body[m[0]:m[1]])
			k := key{id: pat.id, raw: raw}
			if h, ok := seen[k]; ok {
				h.count++
				continue
			}
			seen[k] = &secretHit{pattern: pat, raw: raw, count: 1}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	hits := make([]*secretHit, 0, len(seen))
	for _, h := range seen {
		hits = append(hits, h)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		ri := SeverityRank(hits[i].pattern.severity)
		rj := SeverityRank(hits[j].pattern.severity)
		if ri != rj {
			return ri > rj
		}
		if hits[i].pattern.id != hits[j].pattern.id {
			return hits[i].pattern.id < hits[j].pattern.id
		}
		return redactSecret(hits[i].raw) < redactSecret(hits[j].raw)
	})
	out := make([]SecretHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, SecretHit{
			ID:       h.pattern.id,
			Label:    h.pattern.label,
			Severity: h.pattern.severity,
			Raw:      h.raw,
			Count:    h.count,
		})
	}
	return out
}

// RedactSecret returns the safe-to-print form of raw. Lua port calls
// this once per hit so the redaction rule (first/last four chars,
// PEM header pass-through, full-mask for short values) only lives in
// the Go side.
func RedactSecret(raw string) string { return redactSecret(raw) }
