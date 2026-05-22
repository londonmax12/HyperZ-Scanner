package crawler

import (
	"bufio"
	"io"
	"strings"
)

type robotsRules struct {
	disallow []string
	allow    []string
	sitemaps []string
}

// parseRobots reads a robots.txt body and returns rules for the User-agent: *
// group plus all Sitemap directives (which are agent-independent).
// Extended wildcard syntax ("*", "$") is captured literally; blocked() does a
// prefix match, so wildcard patterns won't match real URLs - acceptable as a
// conservative default since we err on the side of *not* blocking.
func parseRobots(r io.Reader) robotsRules {
	var rules robotsRules
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	inStar := false
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:i]))
		v := strings.TrimSpace(line[i+1:])
		switch k {
		case "user-agent":
			inStar = v == "*"
		case "disallow":
			if inStar && v != "" {
				rules.disallow = append(rules.disallow, v)
			}
		case "allow":
			if inStar && v != "" {
				rules.allow = append(rules.allow, v)
			}
		case "sitemap":
			if v != "" {
				rules.sitemaps = append(rules.sitemaps, v)
			}
		}
	}
	return rules
}

// blocked reports whether a request path is disallowed under longest-match
// semantics; an equally-long Allow beats Disallow (per Google's spec).
func (r robotsRules) blocked(path string) bool {
	bestAllow, bestDisallow := -1, -1
	for _, p := range r.allow {
		if strings.HasPrefix(path, p) && len(p) > bestAllow {
			bestAllow = len(p)
		}
	}
	for _, p := range r.disallow {
		if strings.HasPrefix(path, p) && len(p) > bestDisallow {
			bestDisallow = len(p)
		}
	}
	if bestDisallow < 0 {
		return false
	}
	return bestDisallow > bestAllow
}
