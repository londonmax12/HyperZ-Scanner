package checks

import (
	"context"
	"fmt"
	"mime"
	"regexp"
	"sort"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// SecretsInBody scans response bodies for high-confidence credential
// patterns: cloud provider keys, VCS / package registry tokens, payment
// / messaging service keys, AI provider keys, observability tokens,
// SaaS tokens, PEM private key blocks, and JWTs. It is the catch-all
// for "someone shipped a secret in the response" leaks - the canonical
// case is an inline <script> or a JS bundle that bakes a developer's
// API key into client-facing markup, but the same patterns show up in
// JSON error messages, debug dumps, and HTML comments.
//
// The check is intentionally conservative: every pattern is anchored on
// a service-specific prefix or structure (AKIA..., ghp_..., sk-ant-...,
// -----BEGIN ... PRIVATE KEY-----, eyJ...) so the false-positive rate
// stays low without any entropy guessing. Matches are redacted before
// they reach the report so a finding never re-leaks the value it just
// flagged.
//
// Severity scales with how directly the leaked material grants access:
// long-lived production credentials (cloud keys, GitHub PATs, Stripe
// live keys, AI provider keys, Shopify admin tokens, private keys) are
// Critical; scoped service API keys are High; JWTs and DSNs (often
// legitimate session bearers or write-only telemetry endpoints) are
// Medium.
//
// The catalogue itself lives in secrets_in_body_patterns.go; this file
// only owns the runtime - body iteration, dedup, content-type filter,
// redaction.
type SecretsInBody struct{}

func (SecretsInBody) Name() string { return "secrets-in-body" }

func (SecretsInBody) Level() Level { return LevelPassive }

// secretsBodyCap bounds the body we scan. Modern SPA bundles commonly
// hit 3-5 MiB; an undersized cap silently truncates the tail of a
// vendor chunk, exactly where a build-time-baked constant is most
// likely to live. 8 MiB covers the realistic long tail without letting
// a pathological response pin a worker.
const secretsBodyCap = 8 << 20

// secretHit groups every position where one specific secret value was
// found in the body. Multiple occurrences of the same token collapse to
// one hit (with count incremented) so a JS bundle that bakes a key into
// a constant and then references it five times still produces one
// detail entry instead of five.
type secretHit struct {
	pattern secretPattern
	raw     string
	count   int
}

func (c SecretsInBody) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, secretsBodyCap)
	if err != nil {
		return nil, err
	}
	if len(snap.Body) == 0 {
		return nil, nil
	}
	if !isScannableContentType(snap.Headers.Get("Content-Type")) {
		return nil, nil
	}

	body := snap.Body

	// (patternID, raw) -> hit so repeats of the same token across the
	// body collapse to one entry. Cross-pattern duplicates (a JWT also
	// matched by some other pattern's surface form) are kept separate
	// on purpose: the labels would explain different risks.
	type key struct{ id, raw string }
	seen := map[key]*secretHit{}

	for _, pat := range secretPatterns {
		matches := pat.re.FindAllIndex(body, -1)
		for _, m := range matches {
			if pat.contextRE != nil && !hasNearbyContext(body, m[0], m[1], pat.contextRE) {
				continue
			}
			raw := string(body[m[0]:m[1]])
			k := key{id: pat.id, raw: raw}
			if h, ok := seen[k]; ok {
				h.count++
				continue
			}
			seen[k] = &secretHit{pattern: pat, raw: raw, count: 1}
		}
	}

	if len(seen) == 0 {
		return nil, nil
	}

	hits := make([]*secretHit, 0, len(seen))
	for _, h := range seen {
		hits = append(hits, h)
	}
	// Stable, severity-first order so reports diff cleanly and the
	// reviewer sees the worst leak first. Ties break on id (pattern
	// identity) then redacted form so two hits of the same pattern
	// stay grouped.
	sort.SliceStable(hits, func(i, j int) bool {
		ri := SeverityRank(hits[i].pattern.severity)
		rj := SeverityRank(hits[j].pattern.severity)
		if ri != rj {
			return ri > rj
		}
		if hits[i].pattern.id != hits[j].pattern.id {
			return hits[i].pattern.id < hits[j].pattern.id
		}
		return redactSecret(hits[i].raw) < redactSecret(hits[j].raw)
	})

	maxSev := SeverityInfo
	details := make([]string, 0, len(hits))
	idParts := make([]string, 0, len(hits))
	for _, h := range hits {
		if SeverityRank(h.pattern.severity) > SeverityRank(maxSev) {
			maxSev = h.pattern.severity
		}
		red := redactSecret(h.raw)
		occ := ""
		if h.count > 1 {
			occ = fmt.Sprintf(" (%d occurrences)", h.count)
		}
		details = append(details, fmt.Sprintf("%s [%s]: %s%s", h.pattern.label, h.pattern.severity, red, occ))
		// DedupeKey parts mix pattern id with redacted token so two
		// different leaked keys of the same type on the same host stay
		// distinct findings, but the same key surfaced from several
		// crawled pages collapses to one.
		idParts = append(idParts, h.pattern.id+":"+red)
	}

	var title string
	if len(hits) == 1 {
		title = "Response body leaks a credential (" + hits[0].pattern.label + ")"
	} else {
		title = fmt.Sprintf("Response body leaks %d distinct credentials", len(hits))
	}

	leadIn := fmt.Sprintf("Response from %s contains values that match known credential patterns. Each entry below names the credential type and a redacted form of what was found in the body; treat every match as compromised the moment the response was served.", p.URL)

	remediation := "Rotate every leaked credential immediately - assume it is already public from the moment it was served. " +
		"Audit access logs for the affected key during the exposure window. " +
		"Remove the embedded value from the source that generated this response (HTML template, JS bundle, JSON serializer, error/debug handler) and replace it with a server-side lookup or a short-lived, scoped token issued per request. " +
		"For build-time leaks (keys baked into JS bundles), move the secret to an environment variable consumed only by the backend and front the third-party call with a same-origin proxy endpoint."

	dedupeKey := MakeKey(c.Name(), ScopeHost, p.URL, idParts...)

	return []Finding{{
		Check:       c.Name(),
		Target:      p.URL,
		URL:         p.URL,
		Severity:    maxSev,
		Title:       title,
		Detail:      leadIn,
		Details:     details,
		CWE:         "CWE-200, CWE-798",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: remediation,
		Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
		DedupeKey:   dedupeKey,
	}}, nil
}

// isScannableContentType reports whether ct names a body type worth
// scanning for textual secret patterns. Binary types (images, fonts,
// archives, video) are skipped because regex over their bytes is noise
// for no signal. Unknown / unparseable / absent Content-Type defaults
// to scannable: a server that does not declare its type is exactly the
// kind of careless surface that may also ship plaintext credentials,
// and the patterns are anchored tightly enough that scanning a small
// binary blob is harmless.
func isScannableContentType(ct string) bool {
	if ct == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return true
	}
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	// Catch the family of structured types that piggyback on JSON / XML
	// (e.g. application/vnd.api+json, image/svg+xml). Checked BEFORE the
	// image/ / audio/ rejects below so image/svg+xml is still scanned -
	// SVGs routinely embed inline <script> with constants.
	if strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml") {
		return true
	}
	if strings.HasPrefix(mediaType, "image/") ||
		strings.HasPrefix(mediaType, "audio/") ||
		strings.HasPrefix(mediaType, "video/") ||
		strings.HasPrefix(mediaType, "font/") {
		return false
	}
	switch mediaType {
	case "application/json",
		"application/javascript",
		"application/ecmascript",
		"application/xml",
		"application/xhtml+xml",
		"application/ld+json",
		"application/yaml",
		"application/x-yaml",
		"application/graphql",
		"application/x-www-form-urlencoded":
		return true
	case "application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
		"application/x-tar",
		"application/wasm":
		return false
	}
	return false
}

// hasNearbyContext reports whether contextRE matches inside a window of
// [secretContextWindow] bytes on each side of the candidate match
// spanning [start, end). It exists to gate ambiguously-shaped patterns
// (e.g. Mailgun's key-<32hex>) so a hit is kept only when there is a
// vendor-identifying token in the immediate neighbourhood, not anywhere
// in the body.
func hasNearbyContext(body []byte, start, end int, contextRE *regexp.Regexp) bool {
	winStart := start - secretContextWindow
	if winStart < 0 {
		winStart = 0
	}
	winEnd := end + secretContextWindow
	if winEnd > len(body) {
		winEnd = len(body)
	}
	return contextRE.Match(body[winStart:winEnd])
}

// redactSecret produces the short, non-reversible form of raw that is
// safe to embed in a report. The first four and last four characters
// are kept so a reviewer can recognise the same key across two
// findings; everything in the middle becomes a single ellipsis. Very
// short matches and PEM block headers (which carry no secret material
// themselves) are special-cased so the output stays meaningful.
func redactSecret(raw string) string {
	if strings.HasPrefix(raw, "-----BEGIN") {
		// The PEM header line is not itself secret; surface it verbatim
		// so the reviewer knows which key type leaked without us echoing
		// any of the encoded body that follows.
		return raw + " (key body redacted)"
	}
	if len(raw) <= 12 {
		return strings.Repeat("*", len(raw))
	}
	return raw[:4] + "..." + raw[len(raw)-4:]
}
