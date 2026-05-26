package checks

import (
	"context"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// JWTFact is one raw scan observation the JWT bridge surfaces to the
// Lua port. Each fact represents a single sub-probe verdict (or a
// passive header advisory); the Lua check dispatches on Kind to pick
// the per-kind severity / title / remediation text and builds the
// finding from the structured Params bag.
//
// Keeping facts strictly data (no embedded *Finding) means the rule's
// catalog metadata - severity, text, dedupe shape - lives in the .lua
// file and can be edited without recompiling the scanner. Mirrors
// the takeover bridge's design: scan algorithm in Go, rule prose in
// Lua.
type JWTFact struct {
	Kind   string
	Target string
	Params map[string]any
}

// ScanFacts runs the JWT check against p and returns one JWTFact per
// detected issue. Equivalent to Run but does not compose Findings -
// the Lua bridge consumes the facts and composes its own findings,
// so this lets the Lua port stay rule-native instead of pass-through.
//
// Token dedupe (the c.probed set keyed on token fingerprint) carries
// across ScanFacts calls just like across Run calls so a token seen
// on N crawled pages is probed once. The OOB jku/x5u probes are
// dispatched the same way Run does - findings surface later via
// DrainFacts after the operator-configured wait window.
func (c *JWTVulns) ScanFacts(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]JWTFact, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil
	}
	if !allows(sc, u) {
		return nil, nil
	}

	sources := harvestJWTs(p)
	if len(sources) == 0 {
		return nil, nil
	}

	var facts []JWTFact
	for _, src := range sources {
		fp := tokenFingerprint(src.raw)
		c.mu.Lock()
		if c.probed == nil {
			c.probed = map[string]struct{}{}
		}
		if _, ok := c.probed[fp]; ok {
			c.mu.Unlock()
			continue
		}
		c.probed[fp] = struct{}{}
		c.mu.Unlock()

		parsed, err := parseJWT(src.raw)
		if err != nil {
			Report(ctx, parseJWTReportErr(src.raw, err))
			continue
		}
		findings := c.probeToken(ctx, client, p.URL, src, parsed)
		for _, f := range findings {
			facts = append(facts, factFromFinding(p.URL, f))
		}
	}
	return facts, nil
}

// DrainFacts is the ScanFacts analogue of Drain: one JWTFact per OOB
// callback the JWT probes triggered during the active phase. The
// scanner calls this after the wait window through the Lua bridge so
// findings still flow even when the Go-side JWTVulns has been
// shadowed by a Lua override in mergeLuaOverrides.
func (c *JWTVulns) DrainFacts(ctx context.Context) []JWTFact {
	findings := c.Drain(ctx)
	if len(findings) == 0 {
		return nil
	}
	out := make([]JWTFact, 0, len(findings))
	for _, f := range findings {
		out = append(out, factFromFinding(f.Target, f))
	}
	return out
}

// factFromFinding converts an internally-composed Finding back into
// the (kind, params) shape the bridge surfaces. The kind is a stable
// machine identifier (matches the dedupe suffix the Go check used);
// params carries every runtime value the Lua composer needs to
// rebuild the same finding (or a different one) without re-running
// the probe.
//
// Two design notes:
//
//   - We round-trip through Finding rather than refactoring every
//     probe* function to emit JWTFact directly. The probe code is
//     thoroughly tested and changing its return type risks regressing
//     the math/oracle decisions; mapping at the boundary is a smaller
//     blast radius for the same Lua-port goal.
//   - We carry the original composed Finding inside params under the
//     `_finding` key. The Lua port can either lift fields off that
//     finding for its own composition or pass it through verbatim
//     (when the Lua text would duplicate the Go text). Either choice
//     keeps the rule's catalog metadata in Lua hands.
func factFromFinding(target string, f Finding) JWTFact {
	kind := jwtKindFromDedupe(f.DedupeKey, f.Title)
	params := map[string]any{
		"title":       f.Title,
		"detail":      f.Detail,
		"severity":    string(f.Severity),
		"cwe":         f.CWE,
		"owasp":       f.OWASP,
		"remediation": f.Remediation,
		"dedupe_key":  f.DedupeKey,
	}
	if f.Evidence != nil {
		params["evidence_snippet"] = f.Evidence.Snippet
		params["evidence_status"] = f.Evidence.Status
		params["evidence_method"] = f.Evidence.Method
		params["evidence_url"] = f.Evidence.RequestURL
	}
	return JWTFact{
		Kind:   kind,
		Target: target,
		Params: params,
	}
}

// jwtKindFromDedupe maps the kind suffix the Go check baked into the
// dedupe key back to the stable machine identifier the Lua port keys
// its templates on. Falling back to a Title-prefix sniff covers OOB
// findings whose dedupe shape carries the callback hash, not a kind
// suffix.
func jwtKindFromDedupe(key, title string) string {
	// The Go check's dedupe keys carry the kind tag as one of the
	// MakeKey parts; the hash is opaque so we can't recover the tag
	// from the key itself. The title is the cleanest fallback:
	// every probe* function emits a distinctive Title prefix.
	t := strings.ToLower(title)
	switch {
	case strings.Contains(t, "alg=none"):
		return "alg-none"
	case strings.Contains(t, "kid header resolves to filesystem path"):
		return "kid-traversal"
	case strings.Contains(t, "kid header concatenated into sql"):
		return "kid-sqli"
	case strings.Contains(t, "well-known weak hmac secret"):
		return "weak-secret"
	case strings.Contains(t, "algorithm confusion"):
		return "alg-confusion"
	case strings.Contains(t, "crit header"):
		return "crit-abuse"
	case strings.Contains(t, "jku") || strings.Contains(t, "x5u"):
		return "key-url"
	case strings.Contains(t, "kid header is a url"):
		return "kid-as-url"
	default:
		return "other"
	}
}

// parseJWTReportErr is a tiny helper that builds the ScanFacts side's
// report error so the call site stays one-line.
func parseJWTReportErr(raw string, err error) error {
	return jwtParseErr{raw: raw, err: err}
}

type jwtParseErr struct {
	raw string
	err error
}

func (e jwtParseErr) Error() string {
	return "jwt parse " + redactToken(e.raw) + ": " + e.err.Error()
}

func (e jwtParseErr) Unwrap() error { return e.err }
