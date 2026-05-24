package checks

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// CrossOriginIsolation inspects Cross-Origin-Opener-Policy (COOP) and
// Cross-Origin-Embedder-Policy (COEP) for configurations that prevent the
// document from reaching the cross-origin isolated state, or that leave
// the window.opener / cross-origin embed defenses partially deployed.
//
// Cross-origin isolation gates the powerful platform features that became
// unsafe after Spectre: SharedArrayBuffer, performance.measureUserAgent-
// SpecificMemory(), high-resolution timers, and the JS Self-Profiling API.
// Reaching the isolated state requires BOTH of:
//
//	Cross-Origin-Opener-Policy: same-origin
//	Cross-Origin-Embedder-Policy: require-corp   (or credentialless)
//
// Either header on its own is insufficient: COOP alone hardens window
// .opener but does not isolate the agent cluster; COEP alone still
// enforces CORP on cross-origin subresources (and can break embeds that
// lack it) but does not enable cross-origin isolation without COOP.
//
// This complements [SecurityHeaders], which never fires for COOP / COEP
// (the headers are advanced opt-ins; flagging every site without them
// would be noise). The check here fires only when the response shows
// evidence the author was reaching for isolation - i.e. at least one of
// COOP or COEP is present - and surfaces the ways that goal is undone.
//
// Severity climbs with how completely the weakness defeats the policy:
// COEP set without COOP (Medium) leaves the document believing it is
// isolated when in fact the browser falls back to unsafe-none; explicit
// unsafe-none (Low) is the no-op default the header was supposed to
// improve on; allow-popups variants paired with COEP (Low) are the
// classic "I thought this enabled isolation" misconfiguration; invalid
// values and multi-header confusion are Low parse-level bugs.
type CrossOriginIsolation struct{}

func (CrossOriginIsolation) Name() string { return "cross-origin-isolation" }

func (CrossOriginIsolation) Level() Level { return LevelPassive }

// coiWeakness is one (header, problem) entry surfaced during analysis.
// The check consolidates every weakness into a single Finding (mirroring
// [HSTSWeak] / [CSPWeak]) so a response with three problems produces one
// report row with three bullets instead of three near-duplicate rows.
type coiWeakness struct {
	severity Severity
	// id is a short stable token used as a per-weakness dedupe suffix so
	// the same defect on the same host produces the same DedupeKey across
	// multiple runs and across crawled URLs.
	id     string
	detail string
}

// Recognized policy tokens. The spec defines these as case-sensitive
// lowercase tokens; we lower-case the observed value before comparison so
// a "Same-Origin" typo still maps to a known policy (and we surface the
// invalid case via the parser rather than as a missing-header).
var (
	coopValidValues = map[string]bool{
		"unsafe-none":              true,
		"same-origin-allow-popups": true,
		"same-origin":              true,
		// noopener-allow-popups is a proposed COOP value with early /
		// partial cross-browser implementation; accepted here so a
		// forward-looking site using it is not mis-flagged as invalid.
		"noopener-allow-popups": true,
	}
	coepValidValues = map[string]bool{
		"unsafe-none":    true,
		"require-corp":   true,
		"credentialless": true,
	}
)

func (c CrossOriginIsolation) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, 0)
	if err != nil {
		return nil, err
	}
	// COOP / COEP only have meaning on top-level document responses. A
	// JSON API, an image, or a 404 page carrying these headers is at most
	// an inert misconfiguration; flagging it would dilute the report.
	if snap.Status != http.StatusOK || !isHTMLContentType(snap.Headers.Get("Content-Type")) {
		return nil, nil
	}

	coopValues := snap.Headers.Values("Cross-Origin-Opener-Policy")
	coepValues := snap.Headers.Values("Cross-Origin-Embedder-Policy")
	if len(coopValues) == 0 && len(coepValues) == 0 {
		// No evidence the author was reaching for cross-origin isolation;
		// nothing for us to say. SecurityHeaders also stays quiet here so
		// non-isolated sites do not get spammed with COOP / COEP nudges.
		return nil, nil
	}

	coopPolicy, coopRaw, coopPresent := coiPolicyOf(coopValues)
	coepPolicy, coepRaw, coepPresent := coiPolicyOf(coepValues)

	var weaknesses []coiWeakness

	// COOP / COEP are structured-header sf-items (RFC 8941). Per RFC 8941
	// §3 multiple header lines are concatenated with commas and parsed as
	// a single item; multiple policy tokens fail that parse and the
	// browser falls back to the unsafe-none default, dropping the entire
	// policy. Surface the multi-header case explicitly so the author
	// notices the latent footgun.
	if len(coopValues) > 1 {
		weaknesses = append(weaknesses, coiWeakness{
			severity: SeverityLow,
			id:       "coop-multiple-headers",
			detail:   fmt.Sprintf("Response carries %d Cross-Origin-Opener-Policy headers. Browsers concatenate same-named headers and parse the result as a single structured-header item; multiple policy tokens fail that parse and the document falls back to the unsafe-none default, so the entire policy is discarded. Consolidate to a single COOP header.", len(coopValues)),
		})
	}
	if len(coepValues) > 1 {
		weaknesses = append(weaknesses, coiWeakness{
			severity: SeverityLow,
			id:       "coep-multiple-headers",
			detail:   fmt.Sprintf("Response carries %d Cross-Origin-Embedder-Policy headers. Browsers concatenate same-named headers and parse the result as a single structured-header item; multiple policy tokens fail that parse and the document falls back to the unsafe-none default, so the entire policy is discarded. Consolidate to a single COEP header.", len(coepValues)),
		})
	}

	// COOP value-level analysis.
	if coopPresent {
		switch {
		case !coopValidValues[coopPolicy]:
			weaknesses = append(weaknesses, coiWeakness{
				severity: SeverityLow,
				// Suffix the policy token so two different bad values on
				// the same host dedupe as two findings rather than one;
				// the fix is per-value, not per-host.
				id:     "coop-invalid-value:" + coopPolicy,
				detail: fmt.Sprintf("Cross-Origin-Opener-Policy value %q is not a recognized policy. Browsers fall back to the unsafe-none default, so this header has no protective effect. Use same-origin (for full isolation and window.opener hardening) or same-origin-allow-popups (when popups still need a live window.opener handle, e.g. OAuth flows).", coopRaw),
			})
		case coopPolicy == "unsafe-none":
			weaknesses = append(weaknesses, coiWeakness{
				severity: SeverityLow,
				id:       "coop-unsafe-none",
				detail:   "Cross-Origin-Opener-Policy is explicitly set to unsafe-none. This is the browser default; the header has no protective effect, the document remains exposed to cross-origin window.opener attacks, and no cross-origin isolation is possible. Use same-origin (or same-origin-allow-popups when popups must keep a window.opener handle).",
			})
		case coopPolicy == "same-origin-allow-popups", coopPolicy == "noopener-allow-popups":
			// allow-popups variants harden against window.opener but do
			// NOT enable cross-origin isolation. Flag whenever COEP is
			// present and non-unsafe-none, since the pairing is the
			// classic "I thought this enabled isolation" misconfiguration
			// regardless of whether the COEP value is also typo'd: the
			// author's *intent* was isolation, and the COOP variant
			// alone defeats it. An invalid COEP also fires the
			// coep-invalid-value weakness; the two are independent
			// problems. Used alone (no COEP at all), allow-popups is a
			// legitimate window.opener hardening choice and we stay
			// quiet.
			if coepPresent && coepPolicy != "unsafe-none" {
				weaknesses = append(weaknesses, coiWeakness{
					severity: SeverityLow,
					id:       "coop-allow-popups-with-coep",
					detail:   fmt.Sprintf("Cross-Origin-Opener-Policy is %q while Cross-Origin-Embedder-Policy is set to %q. The allow-popups COOP variants do not enable cross-origin isolation; the document will not be cross-origin isolated and SharedArrayBuffer, performance.measureUserAgentSpecificMemory(), and high-resolution timers remain unavailable despite the COEP header. Switch COOP to same-origin if isolation is the goal.", coopRaw, coepRaw),
				})
			}
		}
	}

	// COEP value-level analysis.
	if coepPresent {
		switch {
		case !coepValidValues[coepPolicy]:
			weaknesses = append(weaknesses, coiWeakness{
				severity: SeverityLow,
				// Suffix the policy token so two different bad values on
				// the same host dedupe as two findings rather than one;
				// the fix is per-value, not per-host.
				id:     "coep-invalid-value:" + coepPolicy,
				detail: fmt.Sprintf("Cross-Origin-Embedder-Policy value %q is not a recognized policy. Browsers fall back to the unsafe-none default, so this header has no protective effect. Use require-corp (strict; requires Cross-Origin-Resource-Policy on every cross-origin subresource) or credentialless (newer; cross-origin subresources are fetched without credentials and skipped if they need them).", coepRaw),
			})
		case coepPolicy == "unsafe-none":
			weaknesses = append(weaknesses, coiWeakness{
				severity: SeverityLow,
				id:       "coep-unsafe-none",
				detail:   "Cross-Origin-Embedder-Policy is explicitly set to unsafe-none. This is the browser default; the document is not cross-origin isolated and cross-origin subresources can be embedded without their CORP consent. Use require-corp (strict) or credentialless (less invasive rollout) to enable isolation.",
			})
		}
	}

	// Partial-isolation: COEP set to a strong value while COOP is missing
	// entirely. Cross-origin isolation requires both halves; the COEP
	// header still enforces CORP on cross-origin subresources (and may
	// break embeds that lack a CORP header) but without COOP the agent
	// cluster is not isolated, so the author pays the embed-breakage
	// cost without getting SharedArrayBuffer / hi-res timers in return.
	if coepPresent && !coopPresent && (coepPolicy == "require-corp" || coepPolicy == "credentialless") {
		weaknesses = append(weaknesses, coiWeakness{
			severity: SeverityMedium,
			id:       "coop-missing-with-coep",
			detail:   "Cross-Origin-Embedder-Policy is set but Cross-Origin-Opener-Policy is missing. Cross-origin isolation requires BOTH Cross-Origin-Opener-Policy: same-origin and a strong COEP value; with only COEP, require-corp still enforces CORP on cross-origin subresources (and can break embeds that lack a CORP header) but does not enable SharedArrayBuffer, performance.measureUserAgentSpecificMemory(), or high-resolution timers. Add Cross-Origin-Opener-Policy: same-origin.",
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
		title = "cross-origin isolation has 1 weakness"
	} else {
		title = fmt.Sprintf("cross-origin isolation has %d weaknesses", len(weaknesses))
	}

	leadIn := fmt.Sprintf("Response from %s carries cross-origin isolation headers but the configuration materially weakens or undoes the protection COOP / COEP are meant to provide. Each entry below names the weakness and how to fix it.", p.URL)

	remediation := "Aim for Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp on every HTML document that should be cross-origin isolated. " +
		"Tag every cross-origin subresource (images, scripts, fonts, frames) with Cross-Origin-Resource-Policy: same-origin or cross-origin so require-corp does not block them. " +
		"During rollout, deploy Cross-Origin-Embedder-Policy-Report-Only first to inventory subresources that would break under require-corp, then switch to enforcement once the report stream is clean."

	return []Finding{{
		Check:       c.Name(),
		Target:      p.URL,
		URL:         p.URL,
		Severity:    maxSev,
		Title:       title,
		Detail:      leadIn,
		Details:     details,
		CWE:         "CWE-693",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: remediation,
		Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
		// Per-host: COOP / COEP are server-wide configuration; the same
		// defect on every crawled page is one issue, not N.
		DedupeKey: MakeKey(c.Name(), ScopeHost, p.URL, idParts...),
	}}, nil
}

// coiPolicyOf returns the lower-cased policy token from a COOP / COEP
// header value list, the original (pre-normalization) raw value used in
// human-readable detail text, and whether any non-empty value was seen.
//
// Only the first header instance is considered; the multi-header case is
// surfaced separately by the caller. The leading token is taken up to
// the first ';' so parameters such as `report-to="endpoint"` (used by the
// Reporting API) do not poison the token comparison.
func coiPolicyOf(values []string) (policy, raw string, present bool) {
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		raw = trimmed
		token := trimmed
		if i := strings.IndexByte(token, ';'); i >= 0 {
			token = token[:i]
		}
		policy = strings.ToLower(strings.TrimSpace(token))
		present = true
		return
	}
	return "", "", false
}
