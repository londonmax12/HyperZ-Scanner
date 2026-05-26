package lua_engine

import (
	"strings"
)

// SRIMissing flags executable subresources loaded from a different origin that
// do not carry an integrity="sha…" attribute. Without SRI, an attacker who
// compromises the CDN or sits on the network path can swap the file for a
// malicious version and the browser will execute it.
//
// Scope is deliberately narrow:
//
//   - <script src=...> from a different host - SRI is the defined defense, no
//     SRI is high impact.
//   - <link rel="stylesheet|preload|modulepreload|prefetch" href=...> from a
//     different host - SRI is supported and applicable. Other link rels
//     (icon, canonical, dns-prefetch, manifest, alternate, ...) are excluded:
//     they either don't fetch executable content, don't validate via SRI in
//     any browser, or are navigation hints.
//
// <iframe> is intentionally not covered: there is no integrity mechanism for
// cross-origin iframe src in any current browser, so flagging it would be a
// guaranteed false positive.
type SRIMissing struct{}

// sriMissingBodyCap bounds how much HTML we tokenize. Matches the other
// passive HTML scanners; documents past this size lose late-page <script>
// coverage in exchange for predictable cost.
const sriMissingBodyCap = 2 << 20

// sriLinkRels is the set of <link rel> tokens for which SRI is meaningful.
// A rel attribute may carry multiple space-separated tokens; any match here
// qualifies the link for an SRI check.
var sriLinkRels = map[string]struct{}{
	"stylesheet":    {},
	"preload":       {},
	"modulepreload": {},
	"prefetch":      {},
}

// linkRelIsSRIEligible reports whether rel - which may carry multiple
// space-separated tokens - names a relationship that fetches a subresource
// SRI applies to. An empty rel falls through to false: a <link> without a
// rel is inert in browsers and not worth flagging.
func linkRelIsSRIEligible(rel string) bool {
	for _, tok := range strings.Fields(rel) {
		if _, ok := sriLinkRels[strings.ToLower(tok)]; ok {
			return true
		}
	}
	return false
}
