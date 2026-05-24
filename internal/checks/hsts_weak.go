package checks

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
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

func (HSTSWeak) Name() string { return "hsts-weak" }

func (HSTSWeak) Level() Level { return LevelPassive }

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

func (c HSTSWeak) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, 0)
	if err != nil {
		return nil, err
	}

	values := snap.Headers.Values("Strict-Transport-Security")
	if len(values) == 0 {
		// Absence is security-headers' job; nothing for us to say.
		return nil, nil
	}

	// Per RFC 6797 §8.1 the UA processes only the first HSTS header when
	// multiple are present. We mirror that for parsing and flag the
	// duplication separately so authors notice the latent confusion.
	directives, parseErrs := parseHSTS(values[0])

	var weaknesses []hstsWeakness

	// HSTS over plain HTTP is ignored by browsers (RFC 6797 §8.1). The
	// header has no effect but its presence often masks the misconception
	// that "we have HSTS" when the upgrade path is still wide open.
	if u := p.ParsedURL(); u != nil && strings.EqualFold(u.Scheme, "http") {
		weaknesses = append(weaknesses, hstsWeakness{
			severity: SeverityLow,
			id:       "over-http",
			detail:   "Strict-Transport-Security is delivered over plain HTTP. RFC 6797 §8.1 requires user agents to ignore HSTS headers received over insecure transport, so this header provides no protection at all. Serve HSTS only over HTTPS, and redirect HTTP to HTTPS so the first secure response can set the pin.",
		})
	}

	if len(values) > 1 {
		weaknesses = append(weaknesses, hstsWeakness{
			severity: SeverityLow,
			id:       "multiple-headers",
			detail:   fmt.Sprintf("Response carries %d Strict-Transport-Security headers. RFC 6797 §8.1 directs the user agent to process only the first; subsequent headers are silently dropped, masking whichever policy the author actually intended. Consolidate to a single header.", len(values)),
		})
	}

	for _, pe := range parseErrs {
		weaknesses = append(weaknesses, hstsWeakness{
			severity: SeverityLow,
			id:       "malformed:" + pe.id,
			detail:   pe.detail,
		})
	}

	maxAgeRaw, hasMaxAge := directives["max-age"]
	switch {
	case !hasMaxAge:
		weaknesses = append(weaknesses, hstsWeakness{
			severity: SeverityHigh,
			id:       "missing-max-age",
			detail:   "max-age is required by RFC 6797 §6.1; a Strict-Transport-Security header without it is invalid and browsers discard the whole policy. Set max-age=63072000; includeSubDomains; preload (or at minimum max-age=31536000) to actually pin the host.",
		})
	default:
		v, perr := strconv.ParseInt(strings.TrimSpace(maxAgeRaw), 10, 64)
		switch {
		case perr != nil || v < 0:
			weaknesses = append(weaknesses, hstsWeakness{
				severity: SeverityHigh,
				id:       "max-age-invalid",
				detail:   fmt.Sprintf("max-age=%q is not a non-negative integer; browsers treat the entire HSTS header as invalid and discard it. Set max-age to a positive number of seconds, e.g. max-age=63072000.", maxAgeRaw),
			})
		case v == 0:
			// max-age=0 is the spec-defined way to TELL browsers to forget
			// any previously cached pin. Shipping it from a live site is
			// almost always a regression (template default, dev override
			// leaked to prod) rather than an intentional rollback.
			weaknesses = append(weaknesses, hstsWeakness{
				severity: SeverityHigh,
				id:       "max-age-zero",
				detail:   "max-age=0 instructs browsers to immediately forget any HSTS pin they previously cached for this host, effectively turning HSTS off. Unless this is a deliberate, time-boxed rollback, ship a real max-age (e.g. 63072000) so the host stays pinned.",
			})
		case v < hstsMaxAgeVeryShort:
			weaknesses = append(weaknesses, hstsWeakness{
				severity: SeverityHigh,
				id:       "max-age-tiny",
				detail:   fmt.Sprintf("max-age=%d (less than one day) is short enough that an attacker who can keep a victim off HTTPS even briefly will see the pin expire. Raise to at least max-age=31536000 (one year).", v),
			})
		case v < hstsMaxAgeShort:
			weaknesses = append(weaknesses, hstsWeakness{
				severity: SeverityMedium,
				id:       "max-age-short",
				detail:   fmt.Sprintf("max-age=%d (less than six months) is below the preload-list floor and well under standard guidance. Raise to max-age=31536000 (one year) or 63072000 (two years) so the pin survives long enough to actually defeat downgrade attempts.", v),
			})
		case v < hstsMaxAgeRecommended:
			weaknesses = append(weaknesses, hstsWeakness{
				severity: SeverityLow,
				id:       "max-age-below-year",
				detail:   fmt.Sprintf("max-age=%d is below the one-year (31536000) value required for the HSTS preload list and recommended by Mozilla Observatory. Raise to at least max-age=31536000.", v),
			})
		}
	}

	if _, ok := directives["includesubdomains"]; !ok {
		weaknesses = append(weaknesses, hstsWeakness{
			severity: SeverityLow,
			id:       "missing-include-subdomains",
			detail:   "includeSubDomains is not set. Subdomains of this host (login.example.com, api.example.com, ...) get no HSTS protection from this policy, leaving cookie-stealing downgrade vectors via any HTTP-served subdomain. Confirm every subdomain serves HTTPS, then add includeSubDomains.",
		})
	}

	if len(weaknesses) == 0 {
		return nil, nil
	}

	// Stable order so reports diff cleanly across runs.
	sort.SliceStable(weaknesses, func(i, j int) bool {
		return weaknesses[i].id < weaknesses[j].id
	})

	maxSev := SeverityInfo
	details := make([]string, 0, len(weaknesses))
	idParts := make([]string, 0, len(weaknesses))
	for _, w := range weaknesses {
		if SeverityRank(w.severity) > SeverityRank(maxSev) {
			maxSev = w.severity
		}
		details = append(details, fmt.Sprintf("[%s]: %s", w.severity, w.detail))
		idParts = append(idParts, w.id)
	}

	var title string
	if len(weaknesses) == 1 {
		title = "Strict-Transport-Security has 1 weakness"
	} else {
		title = fmt.Sprintf("Strict-Transport-Security has %d weaknesses", len(weaknesses))
	}

	leadIn := fmt.Sprintf("Response from %s ships a Strict-Transport-Security header but its configuration materially weakens the downgrade-attack protection HSTS is meant to provide. Each entry below names the weakness and how to fix it.", p.URL)

	remediation := "Aim for Strict-Transport-Security: max-age=63072000; includeSubDomains; preload. " +
		"Confirm every subdomain serves HTTPS before enabling includeSubDomains. " +
		"Once max-age >= 31536000, includeSubDomains, and preload are in place, submit the host at https://hstspreload.org so first-visit downgrade is also defeated."

	return []Finding{{
		Check:       c.Name(),
		Target:      p.URL,
		URL:         p.URL,
		Severity:    maxSev,
		Title:       title,
		Detail:      leadIn,
		Details:     details,
		CWE:         "CWE-319",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: remediation,
		Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
		DedupeKey:   MakeKey(c.Name(), ScopeHost, p.URL, idParts...),
	}}, nil
}

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
