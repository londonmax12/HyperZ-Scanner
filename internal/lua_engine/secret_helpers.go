package lua_engine

import (
	"regexp"
	"strings"
)

// secretContextWindow is the byte radius HasNearbyContext checks around
// a candidate match. 256 is enough to surface the vendor-identifying
// token that gates an ambiguous shape (e.g. "Mailgun" appearing near
// key-<32hex>) without dragging in cross-section noise.
const secretContextWindow = 256

// HasNearbyContext reports whether contextRE matches inside a window of
// [secretContextWindow] bytes on each side of the candidate match
// spanning [start, end). It exists to gate ambiguously-shaped patterns
// (e.g. Mailgun's key-<32hex>) so a hit is kept only when there is a
// vendor-identifying token in the immediate neighbourhood, not anywhere
// in the body.
//
// Lives at the engine root because both the discovery/secrets_in_body
// scanner and the platform/openapi auditor (which reuses the same
// gate) need it; keeping the helper here means neither has to import
// the other.
func HasNearbyContext(body []byte, start, end int, contextRE *regexp.Regexp) bool {
	winStart := start - secretContextWindow
	if winStart < 0 {
		winStart = 0
	}
	winEnd := end + secretContextWindow
	if winEnd > len(body) {
		winEnd = len(body)
	}
	return contextRE.Match(body[winStart:winEnd])
}

// RedactSecret produces the short, non-reversible form of raw that is
// safe to embed in a report. The first four and last four characters
// are kept so a reviewer can recognise the same key across two
// findings; everything in the middle becomes a single ellipsis. Very
// short matches and PEM block headers (which carry no secret material
// themselves) are special-cased so the output stays meaningful.
func RedactSecret(raw string) string {
	if strings.HasPrefix(raw, "-----BEGIN") {
		return raw + " (key body redacted)"
	}
	if len(raw) <= 12 {
		return strings.Repeat("*", len(raw))
	}
	return raw[:4] + "..." + raw[len(raw)-4:]
}
