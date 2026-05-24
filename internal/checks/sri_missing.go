package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// SRIMissing flags executable subresources loaded from a different origin that
// do not carry an integrity="sha…" attribute. Without SRI, an attacker who
// compromises the CDN or sits on the network path can swap the file for a
// malicious version and the browser will execute it.
//
// Scope is deliberately narrow:
//
//   - <script src=...> from a different host - SRI is the defined defense, no
//     SRI is high impact.
//   - <link rel="stylesheet|preload|modulepreload|prefetch" href=...> from a
//     different host - SRI is supported and applicable. Other link rels
//     (icon, canonical, dns-prefetch, manifest, alternate, ...) are excluded:
//     they either don't fetch executable content, don't validate via SRI in
//     any browser, or are navigation hints.
//
// <iframe> is intentionally not covered: there is no integrity mechanism for
// cross-origin iframe src in any current browser, so flagging it would be a
// guaranteed false positive.
type SRIMissing struct{}

func (SRIMissing) Name() string { return "sri-missing" }

func (SRIMissing) Level() Level { return LevelPassive }

// sriMissingBodyCap bounds how much HTML we tokenize. Matches the other
// passive HTML scanners; documents past this size lose late-page <script>
// coverage in exchange for predictable cost.
const sriMissingBodyCap = 2 << 20

// sriLinkRels is the set of <link rel> tokens for which SRI is meaningful.
// A rel attribute may carry multiple space-separated tokens; any match here
// qualifies the link for an SRI check.
var sriLinkRels = map[string]struct{}{
	"stylesheet":    {},
	"preload":       {},
	"modulepreload": {},
	"prefetch":      {},
}

func (c SRIMissing) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, sriMissingBodyCap)
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

	z := html.NewTokenizer(bytes.NewReader(snap.Body))
	var findings []Finding
	seen := map[string]struct{}{}

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		tagName := string(tag)

		var resourceAttr string
		switch tagName {
		case "script":
			resourceAttr = "src"
		case "link":
			resourceAttr = "href"
		default:
			continue
		}

		var resourceURL, integrityAttr, relAttr string
		for {
			key, val, more := z.TagAttr()
			switch strings.ToLower(string(key)) {
			case resourceAttr:
				resourceURL = string(val)
			case "integrity":
				integrityAttr = string(val)
			case "rel":
				relAttr = string(val)
			}
			if !more {
				break
			}
		}

		// <link> only fetches an SRI-eligible resource for specific rels.
		if tagName == "link" && !linkRelIsSRIEligible(relAttr) {
			continue
		}
		if strings.TrimSpace(resourceURL) == "" {
			continue
		}
		if integrityAttr != "" {
			continue
		}

		// Drop non-network schemes; they aren't subresources in any meaningful
		// sense and parsing them as URLs adds noise.
		lower := strings.ToLower(strings.TrimSpace(resourceURL))
		if strings.HasPrefix(lower, "data:") ||
			strings.HasPrefix(lower, "javascript:") ||
			strings.HasPrefix(lower, "blob:") ||
			strings.HasPrefix(lower, "#") {
			continue
		}

		ref, err := url.Parse(resourceURL)
		if err != nil {
			continue
		}
		// Resolve against the page so protocol-relative (//cdn/...) and bare
		// relative URLs land in the right host; matches what the browser does
		// when it goes to fetch the resource.
		resolved := pageURL.ResolveReference(ref)
		if resolved.Host == "" {
			continue
		}
		// Same-origin: the page can already substitute the file at will, SRI
		// adds nothing. Hostname() strips the port so default ports don't
		// look like a different host than an explicit one.
		if strings.EqualFold(resolved.Hostname(), pageURL.Hostname()) {
			continue
		}

		resolvedURL := resolved.String()
		dedupeKey := MakeKey(c.Name(), ScopeHost, p.URL, "url:"+resolvedURL)
		if _, dup := seen[dedupeKey]; dup {
			continue
		}
		seen[dedupeKey] = struct{}{}

		severity := SeverityMedium
		if tagName == "script" {
			severity = SeverityHigh
		}

		findings = append(findings, Finding{
			Check:    c.Name(),
			Target:   p.URL,
			URL:      p.URL,
			Severity: severity,
			Title:    fmt.Sprintf("cross-origin <%s> loaded without Subresource Integrity", tagName),
			Detail: fmt.Sprintf(
				"Page %s loads <%s> from %s without an integrity attribute. "+
					"An attacker who compromises that origin or sits on the network path between the "+
					"browser and the CDN can substitute the file with malicious content and the browser "+
					"will execute it as if it were trusted first-party code.",
				p.URL, tagName, resolvedURL,
			),
			CWE:   "CWE-345",
			OWASP: "A08:2021 Software and Data Integrity Failures",
			Remediation: "Add integrity=\"sha384-<base64-hash>\" (and crossorigin=\"anonymous\" for cross-origin loads) to the tag. " +
				"Most public CDNs (jsDelivr, unpkg, cdnjs) publish SRI hashes alongside their URLs; " +
				"for self-hosted assets generate one with `openssl dgst -sha384 -binary <file> | openssl base64 -A`. " +
				"Alternatively, host the file from the same origin so the integrity question collapses to TLS.",
			Evidence:  BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
			DedupeKey: dedupeKey,
		})
	}

	return findings, nil
}

// linkRelIsSRIEligible reports whether rel - which may carry multiple
// space-separated tokens - names a relationship that fetches a subresource
// SRI applies to. An empty rel falls through to false: a <link> without a
// rel is inert in browsers and not worth flagging.
func linkRelIsSRIEligible(rel string) bool {
	for _, tok := range strings.Fields(rel) {
		if _, ok := sriLinkRels[strings.ToLower(tok)]; ok {
			return true
		}
	}
	return false
}
