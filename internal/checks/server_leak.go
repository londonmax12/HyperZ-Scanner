package checks

import (
	"context"
	"fmt"
	"sort"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/scope"
)

// ServerLeak flags response headers that reveal server software or runtime
// version (Server, X-Powered-By). The information itself isn't a vulnerability
// but it narrows an attacker's search space; pairing "nginx/1.18.0" with a
// public CVE list is a one-step lookup. Severity stays Info to reflect that.
type ServerLeak struct{}

func (ServerLeak) Name() string { return "server-leak" }

func (ServerLeak) Level() Level { return LevelPassive }

// serverLeakHeaders is the closed set of headers we report. Both fall under
// CWE-200 (Exposure of Sensitive Information) and OWASP A05:2021.
var serverLeakHeaders = []string{"Server", "X-Powered-By"}

func (c ServerLeak) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, target string) ([]Finding, error) {
	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	finalURL := target
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	hostScope := HostScope(finalURL)
	evidence := BuildEvidence("GET", finalURL, resp.StatusCode, resp.Header, "")

	// Sorted iteration so multi-header responses produce stable output.
	names := append([]string(nil), serverLeakHeaders...)
	sort.Strings(names)

	var findings []Finding
	for _, header := range names {
		value := resp.Header.Get(header)
		if value == "" {
			continue
		}
		findings = append(findings, Finding{
			Check:       c.Name(),
			Target:      target,
			URL:         finalURL,
			Severity:    SeverityInfo,
			Title:       "server software disclosed via " + header,
			Detail:      fmt.Sprintf("%s responded with %s: %s", finalURL, header, value),
			CWE:         "CWE-200",
			OWASP:       "A05:2021 Security Misconfiguration",
			Remediation: "Suppress or generalize the " + header + " header at the server/proxy layer so version details aren't advertised.",
			Evidence:    evidence,
			// Per-host + header: same leak across crawled pages is one issue.
			// Header name in the key keeps Server and X-Powered-By distinct.
			DedupeKey: MakeDedupeKey(c.Name(), hostScope, "leak-header:"+header),
		})
	}
	return findings, nil
}
