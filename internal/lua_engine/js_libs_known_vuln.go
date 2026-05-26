package lua_engine

import (
	"strings"

	"golang.org/x/net/html"
)

type JSLibsKnownVuln struct{}

type libDetails struct {
	version         string
	vulnerabilities []string
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
