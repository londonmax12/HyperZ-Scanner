package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// CORSReflection actively probes whether the target reflects an
// attacker-controlled Origin into Access-Control-Allow-Origin. It
// complements the passive cors-config check: the passive variant catches
// servers that always emit CORS headers, this one catches servers that
// emit them only in response to an Origin request header.
//
// The default probe uses a single canary origin on a reserved (.invalid)
// TLD, so a positive result has effectively zero false-positive risk: a
// legitimate allowlist cannot contain the canary. At LevelAggressive the
// check expands to additional probe shapes that exercise the most common
// allowlist-bypass bugs (null-origin trust, prefix-match collision).
type CORSReflection struct{}

func (CORSReflection) Name() string { return "cors-reflection" }

func (CORSReflection) Level() Level { return LevelDefault }

const (
	// .invalid is reserved by RFC 2606 and can never resolve, so no real
	// server's allowlist will contain it. Any reflection of the canary
	// origin is therefore confirmed reflection, not coincidence.
	corsReflectionCanaryHost = "hyperz-canary.invalid"
	corsReflectionCanary     = "https://" + corsReflectionCanaryHost
	corsReflectionBodyCap    = 4 << 10
)

// reflectionProbe is one (technique, Origin generator, predicate) tuple.
// origin builds the Origin header to send given the target host; confirms
// inspects the response's ACAO value and decides whether the server
// accepted the supplied Origin.
type reflectionProbe struct {
	technique string
	origin    func(targetHost string) string
	confirms  func(acao, origin string) bool
}

// reflectionResult is the per-probe outcome the check turns into evidence
// on the consolidated finding.
type reflectionResult struct {
	technique string
	origin    string
	acao      string
	acac      bool
	req       *http.Request
	resp      *http.Response
	body      []byte
	truncated bool
}

// reflectionProbes returns the probes to run at lvl. LevelDefault sends
// one canary probe - high signal, zero false positive risk. LevelAggressive
// expands to additional shapes that catch common allowlist bugs:
//
//   - null-origin: servers that trust the spec's sandboxed-iframe origin
//     accept any attacker-supplied frame, data: URI, or file: page.
//   - prefix-collision: <targetHost>.hyperz-canary.invalid catches servers
//     that only require Origin to *start* with the target host.
//
// Suffix collision (Origin must end with target host) is skipped: a real
// bypass requires the attacker to control DNS for the target's own domain,
// which is not a realistic precondition.
func reflectionProbes(lvl Level) []reflectionProbe {
	probes := []reflectionProbe{{
		technique: "verbatim",
		origin:    func(string) string { return corsReflectionCanary },
		confirms:  func(acao, origin string) bool { return acao == origin },
	}}
	if lvl < LevelAggressive {
		return probes
	}
	probes = append(probes,
		reflectionProbe{
			technique: "null-origin",
			origin:    func(string) string { return "null" },
			confirms:  func(acao, _ string) bool { return strings.EqualFold(acao, "null") },
		},
		reflectionProbe{
			technique: "prefix-collision",
			origin: func(host string) string {
				return "https://" + host + "." + corsReflectionCanaryHost
			},
			confirms: func(acao, origin string) bool { return acao == origin },
		},
	)
	return probes
}

func (c CORSReflection) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	// Non-passive checks must re-affirm scope before issuing crafted
	// traffic, per the Check.Run contract.
	if !sc.Allows(u) {
		return nil, nil
	}

	var hits []reflectionResult
	var firstErr error
	for _, probe := range reflectionProbes(LevelFrom(ctx)) {
		if ctx.Err() != nil {
			break
		}
		origin := probe.origin(u.Host)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
		if err != nil {
			Report(ctx, fmt.Errorf("cors-reflection build req (%s): %w", probe.technique, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		req.Header.Set("Origin", origin)

		resp, err := client.Do(ctx, req)
		if err != nil {
			Report(ctx, fmt.Errorf("cors-reflection probe %s: %w", probe.technique, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
		if !probe.confirms(acao, origin) {
			resp.Body.Close()
			continue
		}
		acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
		body, truncated, err := httpclient.ReadBodyCapped(resp, corsReflectionBodyCap)
		resp.Body.Close()
		if err != nil {
			Report(ctx, fmt.Errorf("cors-reflection read body (%s): %w", probe.technique, err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		hits = append(hits, reflectionResult{
			technique: probe.technique,
			origin:    origin,
			acao:      acao,
			acac:      acac,
			req:       req,
			resp:      resp,
			body:      body,
			truncated: truncated,
		})
	}

	if len(hits) == 0 {
		// Same wholesale-failure rule open-redirect uses: only surface an
		// error when no probes produced findings, so a single transient
		// failure doesn't erase hits from the other probes.
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, nil
	}
	return []Finding{c.finding(p.URL, hits)}, nil
}

// finding produces one consolidated Finding for every probe that confirmed
// reflection. Severity is high when any technique was paired with ACAC: true
// (cross-origin reads of authenticated responses are possible); otherwise
// medium (the data is still leaked, just not credentialed).
func (c CORSReflection) finding(target string, hits []reflectionResult) Finding {
	sev := SeverityMedium
	for _, h := range hits {
		if h.acac {
			sev = SeverityHigh
			break
		}
	}

	techniques := make([]string, 0, len(hits))
	lines := make([]string, 0, len(hits))
	for _, h := range hits {
		techniques = append(techniques, h.technique)
		lines = append(lines, fmt.Sprintf(
			"- %s: probe sent Origin: %s -> Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %v",
			h.technique, h.origin, h.acao, h.acac))
	}

	// Evidence is built from the first hit so the report has a concrete
	// request/response to display. The detail text enumerates every
	// technique that confirmed, so per-technique exchanges would be
	// redundant on the wire-format side.
	first := hits[0]
	ev := &Evidence{
		Method:     first.req.Method,
		RequestURL: first.req.URL.String(),
		Status:     first.resp.StatusCode,
		Exchange:   RecordExchange(first.req, nil, false, first.resp, first.body, first.truncated),
	}

	return Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      target,
		Severity: sev,
		Title:    fmt.Sprintf("CORS reflects attacker-controlled Origin (%s)", strings.Join(techniques, ", ")),
		Detail: fmt.Sprintf(
			"Confirmed by sending crafted Origin headers against %s. The server echoed each probe Origin into Access-Control-Allow-Origin, so a page hosted on any attacker-controlled origin can issue cross-origin reads against this host.\n%s",
			target, strings.Join(lines, "\n")),
		CWE:         corsCWE,
		OWASP:       corsOWASP,
		Remediation: "Validate the request Origin against a hardcoded allowlist before echoing it. If credentialed cross-origin access is not required, drop Access-Control-Allow-Credentials. Never return Access-Control-Allow-Origin: <whatever the client sent>.",
		Evidence:    ev,
		// Per-host: the same reflection bug at every crawled page is one
		// configuration defect, not one per page.
		DedupeKey: MakeKey(c.Name(), ScopeHost, target, "reflection"),
	}
}
