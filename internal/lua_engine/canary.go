package lua_engine

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// canaryPrefix marks a string as a hyperz probe token. Short (4 chars) so it
// fits comfortably inside payloads and reflection windows, and not a
// dictionary word - "hpzc" almost certainly does not appear in legitimate
// site content, so any match in a response is overwhelmingly likely to be
// ours.
const canaryPrefix = "hpzc"

// canaryHexLen is the number of lowercase hex chars appended after the prefix.
// 12 hex chars = 48 random bits: a birthday-bound collision needs ~2^24 probes
// in a single scan, far above any plausible per-scan probe count.
const canaryHexLen = 12

// NewCanary returns a unique probe marker of the form "hpzc<12 hex chars>"
// (e.g. "hpzc9f3a72e1b8c4"). Active checks use the result as a needle they
// place into a request and search for in the response - the marker is
// chosen so a hit is almost certainly the check's own input echoed back,
// not a coincidence.
//
// Each call returns a fresh token. Reads from crypto/rand; a failure means
// the platform CSPRNG is broken and there is no useful fallback, so this
// panics rather than silently emitting a predictable token.
func NewCanary() string {
	var b [canaryHexLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("hyperz: crypto/rand failed: " + err.Error())
	}
	return canaryPrefix + hex.EncodeToString(b[:])
}

// IsCanary reports whether s has the shape NewCanary would produce: the
// fixed prefix followed by exactly canaryHexLen lowercase hex characters.
// It does not prove s was minted by this scan - use it to filter
// "could-be-a-canary" out of evidence text, not as an identity check.
func IsCanary(s string) bool {
	if !strings.HasPrefix(s, canaryPrefix) {
		return false
	}
	rest := s[len(canaryPrefix):]
	if len(rest) != canaryHexLen {
		return false
	}
	for _, c := range rest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
