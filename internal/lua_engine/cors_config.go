package lua_engine

import (
	"net/url"
	"strings"
)

type CORSConfig struct{}

// All three branches below map to CWE-942 (Permissive Cross-domain Policy
// with Untrusted Domains) and OWASP A05 Security Misconfiguration. Pulled
// into constants so the branches can't drift on metadata.
const (
	corsCWE   = "CWE-942"
	corsOWASP = "A05:2021 Security Misconfiguration"
)

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
