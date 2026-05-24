package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// TargetBlankNoopener flags <a target="_blank"> (and <area target="_blank">,
// <form target="_blank">) that do not carry rel="noopener" or rel="noreferrer".
//
// A link that opens a new browsing context hands the destination page a live
// window.opener reference back to the originating tab. Without noopener /
// noreferrer the destination can navigate the opener via
//
//	window.opener.location = "https://phish.example/"
//
// turning a one-click outbound link into reverse-tabnabbing: the user comes
// back to the original tab and finds a convincing phishing page in place of
// what they trusted.
//
// Modern browsers (Chrome 88+, Firefox 79+, Safari 12.1+) default anchors
// and area elements with target="_blank" to noopener, so this check is
// primarily defense-in-depth: older browsers, embedded webviews, and
// <form target="_blank"> (which did not get the same default treatment in
// every engine) all still rely on the explicit attribute. Severity is Low
// for same-origin destinations (the attacker would already control the
// origin) and Medium for cross-origin destinations, where the phishing
// surface is real.
type TargetBlankNoopener struct{}

func (TargetBlankNoopener) Name() string { return "target-blank-noopener" }

func (TargetBlankNoopener) Level() Level { return LevelPassive }

const targetBlankNoopenerBodyCap = 2 << 20

func (c TargetBlankNoopener) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, targetBlankNoopenerBodyCap)
	if err != nil {
		return nil, err
	}
	if !isHTMLContentType(snap.Headers.Get("Content-Type")) {
		return nil, nil
	}
	if len(snap.Body) == 0 {
		return nil, nil
	}

	pageURL, err := url.Parse(p.URL)
	if err != nil || pageURL.Host == "" {
		return nil, nil
	}

	candidates := parseTargetBlankCandidates(snap.Body, pageURL)
	if len(candidates) == 0 {
		return nil, nil
	}

	var findings []Finding
	seen := map[string]struct{}{}

	for _, cand := range candidates {
		key := cand.tag + "|" + cand.resolved.String()
		dedupeKey := MakeKey(c.Name(), ScopePage, p.URL, "ref:"+key)
		if _, dup := seen[dedupeKey]; dup {
			continue
		}
		seen[dedupeKey] = struct{}{}

		crossOrigin := !strings.EqualFold(cand.resolved.Hostname(), pageURL.Hostname())
		severity := SeverityLow
		if crossOrigin {
			severity = SeverityMedium
		}

		findings = append(findings, Finding{
			Check:       c.Name(),
			Target:      p.URL,
			URL:         p.URL,
			Severity:    severity,
			Title:       buildTargetBlankTitle(cand.tag, crossOrigin),
			Detail:      buildTargetBlankDetail(p.URL, cand, crossOrigin),
			CWE:         "CWE-1022",
			OWASP:       "A05:2021 Security Misconfiguration",
			Remediation: buildTargetBlankRemediation(cand.tag),
			Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
			DedupeKey:   dedupeKey,
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].DedupeKey < findings[j].DedupeKey
	})

	return findings, nil
}

// targetBlankCandidate is one (tag, href/action) pair the check should
// report. raw is the attribute as it appeared in the document, resolved is
// the absolute URL the browser would navigate to.
type targetBlankCandidate struct {
	tag      string
	raw      string
	resolved *url.URL
}

// parseTargetBlankCandidates walks body once and returns every <a>, <area>,
// or <form> with target="_blank" that lacks rel="noopener" / "noreferrer"
// and points at a network-scheme URL. baseURL is updated when a <base href>
// is observed so relative URLs resolve against the document base rather
// than the page URL when an explicit base is in play.
func parseTargetBlankCandidates(body []byte, pageURL *url.URL) []targetBlankCandidate {
	z := html.NewTokenizer(bytes.NewReader(body))

	baseURL := *pageURL
	baseURLPtr := &baseURL

	var out []targetBlankCandidate

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		tagName := string(tag)

		switch tagName {
		case "base":
			if href := attrValue(z, hasAttr, "href"); href != "" {
				if u, err := url.Parse(strings.TrimSpace(href)); err == nil {
					baseURLPtr = baseURL.ResolveReference(u)
				}
			}
			continue
		case "a", "area", "form":
		default:
			continue
		}
		if !hasAttr {
			continue
		}

		hrefAttr := "href"
		if tagName == "form" {
			hrefAttr = "action"
		}

		var href, target, rel string
		var haveHref, haveTarget, haveRel bool
		for {
			key, val, more := z.TagAttr()
			switch strings.ToLower(string(key)) {
			case hrefAttr:
				if !haveHref {
					href = string(val)
					haveHref = true
				}
			case "target":
				if !haveTarget {
					target = string(val)
					haveTarget = true
				}
			case "rel":
				if !haveRel {
					rel = string(val)
					haveRel = true
				}
			}
			if !more {
				break
			}
		}

		if !strings.EqualFold(strings.TrimSpace(target), "_blank") {
			continue
		}
		if relHasNoopenerOrNoreferrer(rel) {
			continue
		}
		resolved, ok := resolveNoopenerHref(href, baseURLPtr)
		if !ok {
			continue
		}
		out = append(out, targetBlankCandidate{
			tag:      tagName,
			raw:      href,
			resolved: resolved,
		})
	}
	return out
}

// relHasNoopenerOrNoreferrer reports whether the (space-separated) rel
// attribute contains either token. Matching is case-insensitive per the
// HTML spec.
func relHasNoopenerOrNoreferrer(rel string) bool {
	for _, tok := range strings.Fields(rel) {
		switch strings.ToLower(tok) {
		case "noopener", "noreferrer":
			return true
		}
	}
	return false
}

// resolveNoopenerHref returns the absolute URL the browser would navigate
// to, or (nil, false) for non-network values (empty, javascript:, mailto:,
// tel:, data:, fragment-only). Resolution applies baseURL which may be the
// page URL itself, or a <base href> override.
func resolveNoopenerHref(raw string, baseURL *url.URL) (*url.URL, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "#") {
		return nil, false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, false
	}
	resolved := baseURL.ResolveReference(parsed)
	if resolved.Host == "" {
		return nil, false
	}
	if !strings.EqualFold(resolved.Scheme, "http") && !strings.EqualFold(resolved.Scheme, "https") {
		return nil, false
	}
	return resolved, true
}

func buildTargetBlankTitle(tag string, crossOrigin bool) string {
	origin := "same-origin"
	if crossOrigin {
		origin = "cross-origin"
	}
	return fmt.Sprintf("<%s target=\"_blank\"> to %s URL without rel=\"noopener\"", tag, origin)
}

func buildTargetBlankDetail(pageURL string, cand targetBlankCandidate, crossOrigin bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Page %s contains <%s target=\"_blank\" %s=%q> resolving to %s without rel=\"noopener\" or rel=\"noreferrer\". ",
		pageURL, cand.tag, attrLabelFor(cand.tag), cand.raw, cand.resolved.String())
	b.WriteString("The new browsing context receives a live window.opener handle to this page; ")
	b.WriteString("script in the destination can call window.opener.location = \"...\" to silently navigate this tab to a phishing page (reverse tabnabbing). ")
	if crossOrigin {
		b.WriteString("The destination is cross-origin, so any compromise or hostile content on that origin can pivot back into this site's tab.")
	} else {
		b.WriteString("The destination is same-origin, so direct impact is limited, but the missing attribute is still defense-in-depth worth fixing.")
	}
	return b.String()
}

func buildTargetBlankRemediation(tag string) string {
	switch tag {
	case "form":
		return "Add rel=\"noopener noreferrer\" to the <form> element. Forms with target=\"_blank\" did not get the same browser-default noopener treatment that anchors received, so the explicit attribute is the only portable guarantee."
	default:
		return "Add rel=\"noopener noreferrer\" to the element (e.g. <a href=\"...\" target=\"_blank\" rel=\"noopener noreferrer\">). Modern browsers default anchors with target=\"_blank\" to noopener, but older browsers, embedded webviews, and any code that opens windows via JavaScript still rely on the explicit attribute. noreferrer additionally suppresses the Referer header for cases where the destination should not see where the click came from."
	}
}

func attrLabelFor(tag string) string {
	if tag == "form" {
		return "action"
	}
	return "href"
}
