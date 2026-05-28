package lua_engine

import (
	"fmt"
	"strings"
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
				detail: fmt.Sprintf("Directive %q appears more than once in the header value. RFC 6797 6.1 says any duplicate directive causes browsers to discard the entire policy. Remove the duplicate.", name),
			})
			continue
		}
		seen[name] = true
		out[name] = value
	}
	return out, errs
}
