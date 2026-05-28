package lua_engine

import (
	"fmt"
	"strings"
)

// cspWeakness is one (directive, problem) pair surfaced during analysis.
// The check consolidates every weakness in a policy into a single Finding
// (mirroring [SecurityHeaders]) so a header with seven problems produces
// one report row with seven bullets instead of seven near-duplicate rows.
type cspWeakness struct {
	directive string
	severity  Severity
	// id is a short stable token used as a per-directive dedupe suffix so
	// the same weakness on the same host produces the same DedupeKey
	// across multiple runs and across crawled URLs.
	id     string
	detail string
}

// parseCSP splits a CSP header value into directive -> source list. Directive
// names are lower-cased; source tokens keep their original case so hashes and
// nonces stay byte-identical to what the server sent (callers lower-case for
// comparisons separately). Per the CSP spec, the first occurrence of a
// directive wins and subsequent duplicates inside the same header are
// ignored, so this matches what browsers actually enforce.
func parseCSP(header string) map[string][]string {
	out := map[string][]string{}
	for _, raw := range strings.Split(header, ";") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, exists := out[name]; exists {
			continue
		}
		// Empty source list is a valid (and meaningful: "directive present
		// with zero sources" = block all) state. Distinguish it from a
		// missing directive by storing a non-nil empty slice.
		out[name] = append([]string{}, fields[1:]...)
	}
	return out
}

// resolveFetchDirective returns the effective source list a fetch directive
// would enforce, falling back to default-src if the directive isn't set.
// Returns (sources, fromFallback, present). present is false only when both
// the directive and default-src are absent; in that case the browser allows
// any source for the directive.
func resolveFetchDirective(dirs map[string][]string, name string) (sources []string, fromFallback, present bool) {
	if v, ok := dirs[name]; ok {
		return v, false, true
	}
	if v, ok := dirs["default-src"]; ok {
		return v, true, true
	}
	return nil, false, false
}

// hasNonceOrHash reports whether any source in sources is a nonce or hash
// expression. Browsers in CSP Level 3 ignore 'unsafe-inline' in a directive
// that also carries any nonce or hash, so the presence of either neutralizes
// the inline-script bypass.
func hasNonceOrHash(sources []string) bool {
	for _, s := range sources {
		ls := strings.ToLower(s)
		if strings.HasPrefix(ls, "'nonce-") ||
			strings.HasPrefix(ls, "'sha256-") ||
			strings.HasPrefix(ls, "'sha384-") ||
			strings.HasPrefix(ls, "'sha512-") {
			return true
		}
	}
	return false
}

// hasKeyword reports whether sources contains the named keyword token,
// matched case-insensitively against the bareword (e.g. 'unsafe-inline').
func hasKeyword(sources []string, kw string) bool {
	kw = strings.ToLower(kw)
	for _, s := range sources {
		if strings.ToLower(s) == kw {
			return true
		}
	}
	return false
}

// hasBareWildcard reports whether sources contains the bare "*" token. A
// host-pattern wildcard like "*.example.com" or a scheme like "https:" is
// not the same thing and is handled separately by hasSchemeOnly /
// hasWildcardHostPattern.
func hasBareWildcard(sources []string) bool {
	for _, s := range sources {
		if s == "*" {
			return true
		}
	}
	return false
}

// dangerousSchemes lists scheme-only source values that act as origin-wide
// allowlists when they appear in script-src. http: / https: trust any host;
// data: / blob: / filesystem: let an attacker smuggle script bodies inline.
var dangerousScriptSchemes = []string{"http:", "https:", "data:", "blob:", "filesystem:"}

// schemeOnlySources returns the subset of sources that are bare scheme
// tokens ("https:", "data:", ...) - i.e. allowlist the entire scheme
// without restricting host. These are the canonical CSP foot-gun for
// script-src; even a "https:" allowlist permits any HTTPS-hosted CDN.
func schemeOnlySources(sources []string, schemes []string) []string {
	var out []string
	for _, s := range sources {
		ls := strings.ToLower(strings.TrimSpace(s))
		for _, sc := range schemes {
			if ls == sc {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func analyzeScriptSrc(dirs map[string][]string) []cspWeakness {
	const dir = "script-src"
	sources, fromFallback, present := resolveFetchDirective(dirs, dir)
	if !present {
		// No script-src and no default-src means scripts are unrestricted.
		// This is the most permissive possible state for the worst-impact
		// directive in CSP, so it gets the strongest flag.
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityHigh,
			id:        "missing-and-no-default",
			detail:    "Neither script-src nor default-src is set, so the policy places no restriction on where scripts may load from. Any reflected or stored HTML-injection can pull script content from an attacker-controlled origin. Add an explicit script-src (ideally nonce-based) or at minimum set default-src 'self'.",
		}}
	}

	var ws []cspWeakness
	nonceOrHash := hasNonceOrHash(sources)
	strictDynamic := hasKeyword(sources, "'strict-dynamic'")

	if hasKeyword(sources, "'unsafe-inline'") && !nonceOrHash {
		// 'unsafe-inline' is the single most damaging mistake in a CSP:
		// inline event handlers and <script> bodies become executable
		// again, which is exactly the attack class CSP exists to prevent.
		// CSP3 browsers ignore 'unsafe-inline' when any nonce or hash is
		// also present, so we only fire when there is no such neutralizer.
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityCritical,
			id:        "unsafe-inline",
			detail:    "'unsafe-inline' is allowlisted with no neutralizing nonce or hash source, so inline event handlers and inline <script> blocks run unchallenged. This re-opens the exact XSS pathway CSP is meant to close. Replace inline scripts with external files or per-response nonces, then drop 'unsafe-inline'.",
		})
	}

	if hasKeyword(sources, "'unsafe-eval'") {
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityHigh,
			id:        "unsafe-eval",
			detail:    "'unsafe-eval' is allowlisted, permitting eval(), Function(), setTimeout(string), and similar string-to-code call sites. An attacker who lands a string into one of those sinks gets script execution under the page's origin. Refactor offending call sites to pass functions instead of strings, then drop 'unsafe-eval'.",
		})
	}

	if hasKeyword(sources, "'unsafe-hashes'") {
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityMedium,
			id:        "unsafe-hashes",
			detail:    "'unsafe-hashes' is set, allowing inline event handler attributes (onclick=, onerror=, ...) to execute when their bodies match an explicit hash. Hash-allowlisting individual handlers is brittle and tends to grow into a sprawl of exceptions; migrate handlers to addEventListener in scripts that already satisfy the policy.",
		})
	}

	if hasBareWildcard(sources) {
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityHigh,
			id:        "wildcard-host",
			detail:    "Bare \"*\" appears in the script-src source list, allowing scripts to load from any host. Replace with an explicit allowlist of origins you actually trust, or - preferably - a nonce-based policy.",
		})
	}

	if schemes := schemeOnlySources(sources, dangerousScriptSchemes); len(schemes) > 0 {
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityHigh,
			id:        "scheme-only:" + strings.Join(schemes, ","),
			detail:    fmt.Sprintf("script-src allows scheme-only source(s) %s, which trust every host that speaks that scheme. \"https:\" alone permits any HTTPS-hosted CDN; \"data:\" / \"blob:\" let an attacker smuggle a script body inline. Replace with concrete origins and/or move to a nonce-based policy.", strings.Join(schemes, ", ")),
		})
	}

	if strictDynamic && !nonceOrHash {
		// 'strict-dynamic' extends trust from a nonced/hashed script to
		// any script it loads, but with no nonce or hash to bootstrap
		// from, no script ever becomes trusted - so the entire policy
		// silently collapses to a no-op for first-party script.
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityMedium,
			id:        "strict-dynamic-without-nonce",
			detail:    "'strict-dynamic' is set but no nonce or hash source is provided to bootstrap trust. With nothing trusted to start from, scripts will be blocked entirely in CSP3 browsers (a denial-of-functionality), and in browsers that fall back to the allowlist the host / scheme entries take over instead - hiding the policy author's intent.",
		})
	}

	if fromFallback {
		// Inheriting from default-src is technically valid but a common
		// foot-gun: future changes to default-src silently change the
		// script policy. Worth a low-severity nudge.
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityLow,
			id:        "inherited-from-default",
			detail:    "script-src is not set explicitly and is inheriting from default-src. Any later loosening of default-src will silently loosen script execution too. Set script-src explicitly so its policy is decoupled from the catch-all.",
		})
	}

	return ws
}

func analyzeStyleSrc(dirs map[string][]string) []cspWeakness {
	const dir = "style-src"
	sources, fromFallback, present := resolveFetchDirective(dirs, dir)
	if !present {
		// No style-src AND no default-src is permissive but the impact is
		// narrower than for scripts; reported at Low.
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityLow,
			id:        "missing-and-no-default",
			detail:    "Neither style-src nor default-src is set, so stylesheets and inline styles are unrestricted. CSS injection can be used for data exfiltration via selector-based side channels and for clickjacking-adjacent UI rewrites; set at least default-src 'self' or an explicit style-src.",
		}}
	}

	var ws []cspWeakness
	if hasKeyword(sources, "'unsafe-inline'") && !hasNonceOrHash(sources) {
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityMedium,
			id:        "unsafe-inline",
			detail:    "'unsafe-inline' is allowlisted in style-src with no neutralizing nonce or hash. CSS injection can then exfiltrate attribute values via crafted selectors (the \"CSS keylogger\" pattern) and overlay UI elements for clickjacking. Replace inline styles with external files or nonces.",
		})
	}
	if hasBareWildcard(sources) {
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityLow,
			id:        "wildcard-host",
			detail:    "Bare \"*\" appears in style-src, allowing stylesheets from any host. Narrow this to the specific origins that actually serve your CSS.",
		})
	}
	if fromFallback {
		// Mirror the script-src nudge: silently inheriting from default-src
		// couples stylesheet policy to whatever future change widens the
		// catch-all. Set style-src explicitly so the two stay decoupled.
		ws = append(ws, cspWeakness{
			directive: dir,
			severity:  SeverityLow,
			id:        "inherited-from-default",
			detail:    "style-src is not set explicitly and is inheriting from default-src. Any later loosening of default-src will silently loosen stylesheet policy too. Set style-src explicitly so its policy is decoupled from the catch-all.",
		})
	}
	return ws
}

func analyzeObjectSrc(dirs map[string][]string) []cspWeakness {
	const dir = "object-src"
	// object-src is one of the directives that DOES fall back to default-src,
	// so a default-src 'none' policy is sufficient. We only flag when the
	// effective value permits something other than 'none'.
	sources, _, present := resolveFetchDirective(dirs, dir)
	if !present {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityMedium,
			id:        "missing-and-no-default",
			detail:    "Neither object-src nor default-src is set. <object>, <embed>, and (legacy) <applet> can load arbitrary plugin / SVG content that executes script under the page origin. Set object-src 'none' explicitly - it is almost never needed and has no cost.",
		}}
	}
	// Only 'none' is a complete defense here; everything else allows at
	// least some plugin / SVG content to load.
	if len(sources) == 1 && strings.EqualFold(sources[0], "'none'") {
		return nil
	}
	if hasBareWildcard(sources) {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityMedium,
			id:        "wildcard-host",
			detail:    "object-src is set to \"*\", allowing <object> / <embed> content to load from anywhere. Set object-src 'none' unless your app actually relies on plugin content.",
		}}
	}
	return []cspWeakness{{
		directive: dir,
		severity:  SeverityLow,
		id:        "not-none",
		detail:    fmt.Sprintf("object-src resolves to %q rather than 'none'. <object> / <embed> are almost never required in modern apps and are a well-known XSS smuggling surface; tightening to 'none' is the recommended default.", strings.Join(sources, " ")),
	}}
}

func analyzeBaseURI(dirs map[string][]string) []cspWeakness {
	const dir = "base-uri"
	// base-uri does NOT fall back to default-src. A missing base-uri means
	// any <base href="..."> injected via HTML injection repoints every
	// relative URL on the page (including script src) to an attacker host.
	v, present := dirs[dir]
	if !present {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityMedium,
			id:        "missing",
			detail:    "base-uri is not set (and unlike most directives it does NOT inherit from default-src). An attacker with HTML injection can inject <base href=\"//evil/\"> to repoint every relative URL on the page - including script and stylesheet src - to a host they control. Set base-uri 'none' (or 'self') so the original document URL stays authoritative.",
		}}
	}
	if hasBareWildcard(v) {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityMedium,
			id:        "wildcard-host",
			detail:    "base-uri is set to \"*\", which permits an injected <base> tag to point relative URLs at any host. Restrict to 'none' or 'self'.",
		}}
	}
	return nil
}

func analyzeFrameAncestors(dirs map[string][]string) []cspWeakness {
	const dir = "frame-ancestors"
	// frame-ancestors does NOT fall back to default-src. When it's missing
	// the policy provides no clickjacking defense and the site is relying
	// solely on X-Frame-Options (which security-headers tracks separately).
	v, present := dirs[dir]
	if !present {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityLow,
			id:        "missing",
			detail:    "frame-ancestors is not set (it does NOT inherit from default-src). The CSP therefore provides no clickjacking defense and the site relies entirely on X-Frame-Options, which is older and less expressive. Add frame-ancestors 'none' (or 'self') to define framing policy in CSP as well.",
		}}
	}
	if hasBareWildcard(v) {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityMedium,
			id:        "wildcard-host",
			detail:    "frame-ancestors is set to \"*\", explicitly allowing any site to frame this page. Unless this is an intentional embed widget, restrict to 'none' or 'self' to defend against clickjacking.",
		}}
	}
	return nil
}

func analyzeFormAction(dirs map[string][]string) []cspWeakness {
	const dir = "form-action"
	// form-action also does NOT fall back to default-src. When missing,
	// an injected form (or a form-action override via HTML injection) can
	// exfiltrate POST data to any host. Lower-severity than the script
	// bypasses but worth surfacing.
	v, present := dirs[dir]
	if !present {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityLow,
			id:        "missing",
			detail:    "form-action is not set (it does NOT inherit from default-src), so an injected <form> or a <button formaction=\"...\"> override can post submitted values to any origin. Set form-action 'self' (plus any legitimate off-site POST targets) to bound where form submissions may go.",
		}}
	}
	if hasBareWildcard(v) {
		return []cspWeakness{{
			directive: dir,
			severity:  SeverityLow,
			id:        "wildcard-host",
			detail:    "form-action is set to \"*\", which lets a single HTML injection redirect any form submission off-site. Restrict to 'self' (and the small set of off-site POST targets the app actually uses, if any).",
		}}
	}
	return nil
}
