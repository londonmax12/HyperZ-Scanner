package lua_engine

import (
	"bytes"
)

// MatchSQLPatterns returns every SQLErrorPatterns entry that appears in
// body. Body is lower-cased once per call (the pattern list is already
// lower-cased) so the substring scan is case-insensitive without per-
// pattern allocations.
func MatchSQLPatterns(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pat := range SQLErrorPatterns() {
		if bytes.Contains(lower, []byte(pat)) {
			hits = append(hits, pat)
		}
	}
	return hits
}

// SubtractPatterns returns the elements of hits that are not in baseline.
// Used to drop patterns that were already present before our probe ran -
// the difference is the part attributable to the injection attempt.
func SubtractPatterns(hits, baseline []string) []string {
	if len(baseline) == 0 {
		return hits
	}
	bset := make(map[string]struct{}, len(baseline))
	for _, b := range baseline {
		bset[b] = struct{}{}
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if _, dup := bset[h]; dup {
			continue
		}
		out = append(out, h)
	}
	return out
}
