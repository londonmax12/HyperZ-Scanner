package checks

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

type CORSConfig struct{}

func (CORSConfig) Name() string { return "cors-config" }

func (CORSConfig) Level() Level { return LevelPassive }

// All three branches below map to CWE-942 (Permissive Cross-domain Policy
// with Untrusted Domains) and OWASP A05 Security Misconfiguration. Pulled
// into constants so the branches can't drift on metadata.
const (
	corsCWE   = "CWE-942"
	corsOWASP = "A05:2021 Security Misconfiguration"
)

// Run inspects the cached response for permissive CORS configuration. It is
// purely passive: no Origin probe is sent. That keeps the check cheap and
// safe, but means servers that only emit CORS headers when an Origin is
// present in the request won't produce findings here.
func (c CORSConfig) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, 0)
	if err != nil {
		return nil, err
	}
	acao := strings.TrimSpace(snap.Headers.Get("Access-Control-Allow-Origin"))
	if acao == "" {
		return nil, nil
	}
	acac := strings.EqualFold(strings.TrimSpace(snap.Headers.Get("Access-Control-Allow-Credentials")), "true")
	ev := BuildEvidence("GET", p.URL, snap.Status, snap.Headers, "")

	switch {
	case acao == "*":
		// `*` alone is the intentionally-public marker and is normal for
		// public APIs. Paired with credentials it is a CORS-spec violation:
		// browsers refuse the combination at runtime, but the response
		// shape still signals the server misunderstands the credentials
		// contract and may apply the same handler to other paths.
		if !acac {
			return nil, nil
		}
		return []Finding{{
			Check:       c.Name(),
			Target:      p.URL,
			URL:         p.URL,
			Severity:    SeverityHigh,
			Title:       "CORS allows any origin with credentials",
			Detail:      fmt.Sprintf("response from %s set Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. The CORS spec forbids this combination; browsers refuse it, but the configuration indicates the credentials contract is misunderstood and is often paired with a permissive handler that this passive scan did not reach.", p.URL),
			CWE:         corsCWE,
			OWASP:       corsOWASP,
			Remediation: "Drop Access-Control-Allow-Credentials, or replace * with a hardcoded allowlist of trusted origins. The two together are invalid per the CORS spec.",
			Evidence:    ev,
			DedupeKey:   MakeKey(c.Name(), ScopeHost, p.URL, "wildcard-with-credentials"),
		}}, nil

	case strings.EqualFold(acao, "null"):
		// `null` is the origin presented by sandboxed iframes, data: and
		// file: pages, and certain redirect chains - exactly the contexts
		// an attacker can put a victim into. Trusting it is rarely
		// intentional and is the canonical CWE-942 example.
		return []Finding{{
			Check:       c.Name(),
			Target:      p.URL,
			URL:         p.URL,
			Severity:    SeverityMedium,
			Title:       "CORS trusts the null origin",
			Detail:      fmt.Sprintf("response from %s set Access-Control-Allow-Origin: null. Sandboxed iframes, data: URIs, and file: contexts all present as the null origin, so any of them can issue cross-origin reads against this host%s.", p.URL, credSuffix(acac)),
			CWE:         corsCWE,
			OWASP:       corsOWASP,
			Remediation: "Remove null from the allowed origins. Use an explicit allowlist of HTTPS origins instead.",
			Evidence:    ev,
			DedupeKey:   MakeKey(c.Name(), ScopeHost, p.URL, "null-origin"),
		}}, nil

	default:
		// A specific origin in ACAO. If it points at the page's own host
		// the server is just normalizing or echoing the trivial case -
		// benign. If it points elsewhere AND credentials are enabled, the
		// server is either reflecting whatever Origin a caller supplies
		// (the classic exploitable bug) or statically trusting a third
		// party with credentials - both warrant a high-severity flag.
		if !acac || sameOriginAs(acao, p.URL) {
			return nil, nil
		}
		return []Finding{{
			Check:       c.Name(),
			Target:      p.URL,
			URL:         p.URL,
			Severity:    SeverityHigh,
			Title:       "CORS trusts a foreign origin with credentials",
			Detail:      fmt.Sprintf("response from %s set Access-Control-Allow-Origin: %s with Access-Control-Allow-Credentials: true. This is the shape produced by servers that reflect the caller's Origin verbatim; if so, any attacker-controlled page can read authenticated responses from this host.", p.URL, acao),
			CWE:         corsCWE,
			OWASP:       corsOWASP,
			Remediation: "Validate the request Origin against a hardcoded allowlist before echoing it. Never reflect Origin alongside Access-Control-Allow-Credentials: true.",
			Evidence:    ev,
			DedupeKey:   MakeKey(c.Name(), ScopeHost, p.URL, "foreign-origin-with-credentials"),
		}}, nil
	}
}

// credSuffix appends a credentials qualifier to the null-origin detail when
// ACAC is on. The null-origin finding fires regardless (the trust itself is
// the problem) but the impact is materially worse when credentials ride
// along, so the prose calls it out.
func credSuffix(acac bool) string {
	if acac {
		return " (Access-Control-Allow-Credentials: true compounds the impact by exposing authenticated responses)"
	}
	return ""
}

// sameOriginAs reports whether acao parses to the same scheme://host(:port)
// as targetURL. The page's own origin echoed back is benign normalization;
// only the cross-origin case is worth flagging.
func sameOriginAs(acao, targetURL string) bool {
	a, err1 := url.Parse(acao)
	t, err2 := url.Parse(targetURL)
	if err1 != nil || err2 != nil {
		return false
	}
	if a.Scheme == "" || a.Host == "" || t.Scheme == "" || t.Host == "" {
		return false
	}
	return strings.EqualFold(a.Scheme, t.Scheme) && strings.EqualFold(a.Host, t.Host)
}
