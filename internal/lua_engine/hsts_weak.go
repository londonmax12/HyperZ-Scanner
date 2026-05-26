package lua_engine

import (
	"fmt"
	"strings"
)

// HSTSWeak inspects a present Strict-Transport-Security header for
// configurations that materially reduce or eliminate its downgrade-attack
// protection: short max-age values, missing includeSubDomains, the explicit
// max-age=0 "forget me" signal, malformed or duplicate directives, multiple
// HSTS headers, or the header being delivered over plain HTTP (where
// browsers ignore it per RFC 6797 §8.1).
//
// This complements [SecurityHeaders], which only fires when the header is
// absent entirely. A site that ships
//
//	Strict-Transport-Security: max-age=60
//
// passes the "has HSTS" bar but is barely protected: a one-minute pin is
// trivial for an attacker to outwait. Without this check that policy
// slips through every passive scan unflagged.
//
// Severity climbs with how completely the weakness defeats the policy:
// max-age=0 actively un-pins a previously trusted host (High); a missing
// or unparseable max-age makes the entire header invalid (High); short
// max-age bands shrink the practical protection window (High/Medium/Low);
// missing includeSubDomains leaves any HTTP-served subdomain as a
// downgrade vector (Low).
type HSTSWeak struct{}

// hstsWeakness is one (problem) entry surfaced during analysis. The check
// consolidates every weakness in a policy into a single Finding (mirroring
// [CSPWeak] / [SecurityHeaders]) so a header with three problems produces
// one report row with three bullets instead of three near-duplicate rows.
type hstsWeakness struct {
	severity Severity
	// id is a short stable token used as a per-weakness dedupe suffix so
	// the same defect on the same host produces the same DedupeKey across
	// multiple runs and across crawled URLs.
	id     string
	detail string
}

// Max-age severity bands. The HSTS preload list and the major scanners
// (Mozilla Observatory, securityheaders.com) all draw the floor at one
// year (31536000 seconds). Anything materially shorter cannot survive a
// long-lived downgrade window and gets closer to "no HSTS at all" as the
// value shrinks.
const (
	hstsMaxAgeRecommended = 31536000 // 1 year - preload-list floor
	hstsMaxAgeShort       = 15552000 // ~6 months
	hstsMaxAgeVeryShort   = 86400    // 1 day
)

// hstsParseError is one structural problem found while parsing an HSTS
// header value. It is surfaced as a Low-severity weakness so authors see
// the latent bug without it shouting over the substantive policy defects.
type hstsParseError struct {
	id     string
	detail string
}

// parseHSTS splits an HSTS header value into directive name -> value.
// Names are lower-cased; flag directives (includeSubDomains, preload)
// carry an empty value. The returned errors describe structural problems
// (duplicate directives) that RFC 6797 §6.1 says browsers must consider
// when validating the policy.
//
// Per the spec a duplicate directive makes the entire header invalid,
// but we still record the first occurrence so other checks can run; the
// duplication is surfaced via parseErrs.
func parseHSTS(header string) (map[string]string, []hstsParseError) {
	out := map[string]string{}
	var errs []hstsParseError
	seen := map[string]bool{}
	for _, raw := range strings.Split(header, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, value, _ := strings.Cut(raw, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		value = strings.TrimSpace(value)
		// RFC 6797 §6.1 allows directive values as quoted-string; strip
		// the outer pair so callers can read the raw token uniformly.
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if seen[name] {
			errs = append(errs, hstsParseError{
				id:     "duplicate-" + name,
				detail: fmt.Sprintf("Directive %q appears more than once in the header value. RFC 6797 §6.1 says any duplicate directive causes browsers to discard the entire policy. Remove the duplicate.", name),
			})
			continue
		}
		seen[name] = true
		out[name] = value
	}
	return out, errs
}
