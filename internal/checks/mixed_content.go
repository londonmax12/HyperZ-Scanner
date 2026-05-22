package checks

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

// MixedContent scans the HTML body of an HTTPS page for subresources loaded
// over plaintext http://. Active loads (script, iframe, link, form) are
// blocked or downgraded by browsers and rated High; passive loads (img,
// audio, video, etc.) are rated Low.
type MixedContent struct{}

func (MixedContent) Name() string { return "mixed-content" }

func (MixedContent) Level() Level { return LevelPassive }

// mixedContentBodyCap bounds how much of the response we parse. Most HTML
// documents fit comfortably under 2 MiB; past that we accept the risk of
// missing late-document references in exchange for a predictable cost.
const mixedContentBodyCap = 2 << 20

// mixedContentTags lists the HTML elements that load subresources, which
// attribute carries the URL, and whether the load is "active" (executes or
// styles the page) or "passive" (decorative / data-only). Browsers block
// active mixed content by default and either upgrade or warn on passive.
//
// <a href> is intentionally absent;	 anchor links are navigation, not
// subresource loads, so they don't constitute mixed content.
//
// All <link> uses are treated as active. The common cases (stylesheet,
// preload, modulepreload) are active; rel="icon" is technically not, but
// the simpler classification beats parsing rel here.
var mixedContentTags = map[string]struct {
	attr   string
	active bool
}{
	"script": {"src", true},
	"iframe": {"src", true},
	"frame":  {"src", true},
	"link":   {"href", true},
	"form":   {"action", true},
	"img":    {"src", false},
	"video":  {"src", false},
	"audio":  {"src", false},
	"source": {"src", false},
	"embed":  {"src", false},
	"track":  {"src", false},
}

var (
	mixedCommentRE = regexp.MustCompile(`(?s)<!--.*?-->`)
	mixedTagRE     = regexp.MustCompile(`(?is)<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>`)
	mixedAttrRE    = map[string]*regexp.Regexp{
		"src":    regexp.MustCompile(`(?is)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`),
		"href":   regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`),
		"action": regexp.MustCompile(`(?is)\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`),
	}
)

func (c MixedContent) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	// Mixed content only exists on an HTTPS page. On http:// the bigger fix
	// is moving the page itself to HTTPS, surfaced by the missing-HSTS
	// finding from security-headers.
	if !strings.HasPrefix(strings.ToLower(p.URL), "https://") {
		return nil, nil
	}

	snap, err := ensureResponse(ctx, client, p, mixedContentBodyCap)
	if err != nil {
		return nil, err
	}
	// Skip non-HTML responses (images, JSON, binary). Absent Content-Type is
	// treated as possibly-HTML; we'd rather scan an unlabeled HTML page than
	// silently miss it.
	if ct := strings.ToLower(snap.Headers.Get("Content-Type")); ct != "" && !strings.Contains(ct, "html") {
		return nil, nil
	}
	if len(snap.Body) == 0 {
		return nil, nil
	}
	// Strip comments first so commented-out tags don't produce false positives.
	html := mixedCommentRE.ReplaceAllString(string(snap.Body), "")

	hostScope := HostScope(p.URL)
	evidence := BuildEvidence("GET", p.URL, snap.Status, snap.Headers, "")

	// Group by offending URL so a resource referenced N times on the page
	// produces one finding. If both an active and a passive tag reference
	// the same URL, keep the active classification; it's the higher impact.
	type ref struct {
		active bool
		tag    string
	}
	refs := make(map[string]ref)
	for _, m := range mixedTagRE.FindAllStringSubmatch(html, -1) {
		tag := strings.ToLower(m[1])
		spec, ok := mixedContentTags[tag]
		if !ok {
			continue
		}
		attrMatch := mixedAttrRE[spec.attr].FindStringSubmatch(m[2])
		if attrMatch == nil {
			continue
		}
		url := attrMatch[1]
		if url == "" {
			url = attrMatch[2]
		}
		if url == "" {
			url = attrMatch[3]
		}
		if !strings.HasPrefix(strings.ToLower(url), "http://") {
			continue
		}
		existing, seen := refs[url]
		if !seen || (spec.active && !existing.active) {
			refs[url] = ref{active: spec.active, tag: tag}
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}

	urls := make([]string, 0, len(refs))
	for u := range refs {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	findings := make([]Finding, 0, len(urls))
	for _, u := range urls {
		r := refs[u]
		severity, kind := SeverityLow, "passive"
		if r.active {
			severity, kind = SeverityHigh, "active"
		}
		findings = append(findings, Finding{
			Check:       c.Name(),
			Target:      p.URL,
			URL:         p.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("%s mixed content: <%s> loads %s", kind, r.tag, u),
			Detail:      fmt.Sprintf("HTTPS page %s loads %s subresource over plaintext via <%s>: %s", p.URL, kind, r.tag, u),
			CWE:         "CWE-319",
			OWASP:       "A02:2021 Cryptographic Failures",
			Remediation: "Serve the referenced resource over HTTPS, host it locally on the same origin, or remove the reference.",
			Evidence:    evidence,
			// Per-host + offending URL: the same insecure resource shared
			// across many crawled pages is one issue. Tag is excluded from
			// the key, the URL is what actually needs fixing.
			DedupeKey: MakeDedupeKey(c.Name(), hostScope, "url:"+u),
		})
	}
	return findings, nil
}
