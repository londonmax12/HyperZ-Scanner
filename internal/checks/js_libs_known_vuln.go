package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"golang.org/x/net/html"
)

type JSLibsKnownVuln struct{}

func (JSLibsKnownVuln) Name() string { return "js-libs-known-vuln" }

func (JSLibsKnownVuln) Level() Level { return LevelPassive }

func (c JSLibsKnownVuln) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, 1024*1024) // 1MB max body
	if err != nil {
		return nil, err
	}

	// Only process HTML responses.
	if !isHTMLContentType(snap.Headers.Get("Content-Type")) {
		return nil, nil
	}

	if len(snap.Body) == 0 {
		return nil, nil
	}

	detectedLibs := extractLibraries(string(snap.Body))
	if len(detectedLibs) == 0 {
		return nil, nil
	}

	var findings []Finding
	for lib, details := range detectedLibs {
		if len(details.vulnerabilities) == 0 {
			// Library detected but no known vulnerabilities - info level.
			findings = append(findings, Finding{
				Check:       c.Name(),
				Target:      p.URL,
				URL:         p.URL,
				Severity:    SeverityInfo,
				Title:       fmt.Sprintf("detected JavaScript library: %s", lib),
				Detail:      fmt.Sprintf("script analysis detected %s version %s; no known vulnerabilities for this version", lib, details.version),
				CWE:         "CWE-200",
				OWASP:       "A05:2021 Security Misconfiguration",
				Remediation: "Ensure all JavaScript libraries are kept up-to-date. Monitor security advisories for the libraries used.",
				Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
				DedupeKey:   MakeKey(c.Name(), ScopeHost, p.URL, "lib:"+lib),
			})
		} else {
			// Library detected with known vulnerabilities - medium/low level.
			details.vulnerabilities = append([]string{}, details.vulnerabilities...)
			var detail string
			if len(details.vulnerabilities) == 1 {
				detail = fmt.Sprintf("detected %s version %s which has a known vulnerability: %s", lib, details.version, details.vulnerabilities[0])
			} else {
				detail = fmt.Sprintf("detected %s version %s which has known vulnerabilities: %s", lib, details.version, strings.Join(details.vulnerabilities, ", "))
			}

			findings = append(findings, Finding{
				Check:       c.Name(),
				Target:      p.URL,
				URL:         p.URL,
				Severity:    SeverityMedium,
				Title:       fmt.Sprintf("%s (version %s) detected with known vulnerabilities", lib, details.version),
				Detail:      detail,
				CWE:         "CWE-1104",
				OWASP:       "A06:2021 Vulnerable and Outdated Components",
				Remediation: fmt.Sprintf("Update %s to the latest stable version. Check the project's security advisory page for details on what vulnerabilities have been patched.", lib),
				Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
				DedupeKey:   MakeKey(c.Name(), ScopeHost, p.URL, "vuln:"+lib+":"+details.version),
			})
		}
	}

	return findings, nil
}

type libDetails struct {
	version          string
	vulnerabilities  []string
}

// extractLibraries parses HTML to find script tags and identifies known libraries.
func extractLibraries(htmlBody string) map[string]libDetails {
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return nil
	}

	detected := make(map[string]libDetails)

	var walker func(*html.Node)
	walker = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					lib := identifyLibrary(attr.Val)
					if lib != nil {
						detected[lib.name] = libDetails{
							version:         lib.extractVersion(attr.Val),
							vulnerabilities: lib.getVulnerabilities(lib.extractVersion(attr.Val)),
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walker(c)
		}
	}

	walker(doc)
	return detected
}

func identifyLibrary(scriptSrc string) *libPattern {
	lowerSrc := strings.ToLower(scriptSrc)
	for i := range jsLibPatterns {
		if jsLibPatterns[i].pattern.MatchString(lowerSrc) {
			// Return a copy with the matched pattern so we can extract version
			lib := jsLibPatterns[i]
			return &lib
		}
	}
	return nil
}

func (lp *libPattern) extractVersion(scriptSrc string) string {
	matches := lp.pattern.FindStringSubmatch(strings.ToLower(scriptSrc))
	if len(matches) > 1 {
		return matches[1]
	}
	return "unknown"
}

func (lp *libPattern) getVulnerabilities(version string) []string {
	// Try exact match first
	if vulns, ok := lp.vulnerableVersions[version]; ok && len(vulns) > 0 {
		return vulns
	}
	// Try major.minor without patch version
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		majorMinor := strings.Join(parts[:2], ".")
		if vulns, ok := lp.vulnerableVersions[majorMinor]; ok && len(vulns) > 0 {
			return vulns
		}
	}
	return nil
}
