package checks

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// ContentDiscovery probes a curated wordlist of high-signal paths against
// the target host: version-control metadata (.git/HEAD), environment files
// (.env), framework debug endpoints (/actuator/env, /debug/pprof/),
// database dumps (backup.sql), admin consoles (/phpmyadmin/), and other
// shipped-but-unlinked resources whose presence on the public web is the
// vulnerability.
//
// The hard part is not the wordlist - it is the false-positive defense.
// Modern apps (SPA catch-all routes, 200-on-404 error templates, login
// redirects) make a naive "GET returned 200" detector fire on every
// probed path. ContentDiscovery defeats those by sending two random,
// definitely-nonexistent paths first to learn the host's missing-resource
// signature (status, body length, body hash, content type, redirect
// target) and silently dropping any subsequent probe whose response
// matches it. A probe fires a finding when the response is 401/403
// (resource exists and is auth-gated), shape-distinct from the baseline,
// or - when the wordlist entry ships a content marker - contains the
// marker verbatim (e.g. .git/HEAD hits only when the body starts with
// "ref: refs/heads/").
//
// Run is invoked per page, but the check is per-host: a sync.Mutex-
// guarded map on the receiver guarantees the wordlist sweep fires
// exactly once per scheme://host even when the crawler hands the check
// 200 pages on the same site. Without that gate a 200-page crawl with
// a 60-entry wordlist would balloon into ~12,000 probes.
//
// The sweep runs in two waves. The first dispatches the curated catalog
// plus host-named backup synthetics (/<host>.zip, /<host>.sql, ...) at
// bounded concurrency. Any hit on a trigger path (e.g. /.git/HEAD or
// /actuator) queues a second wave of related probes - the rest of /.git,
// the actuator endpoint family, .env backup variants - so we go deep
// only on the small fraction of hosts where the parent confirmed. Both
// waves share a "probed paths" set so a follow-up entry that overlaps
// the main catalog is silently deduped.
//
// Active (LevelDefault). At LevelDefault only the high-signal entries
// probe (~25 requests per host including host-named backups and the
// baseline canaries); at LevelAggressive the full catalog runs and
// adds admin consoles, dev artifacts, and informational endpoints
// (~60+ requests per host before follow-ups).
type ContentDiscovery struct {
	mu      sync.Mutex
	visited map[string]struct{}
}

func (c *ContentDiscovery) Name() string { return "content-discovery" }

func (c *ContentDiscovery) Level() Level { return LevelDefault }

// Budget grants the per-host sweep enough wall time to clear the
// aggressive catalog at a polite request cadence. DefaultBudget (60s)
// is too tight for ~45 sequential probes under any meaningful rate
// limiter; 4 minutes covers it without pinning a worker slot on a
// genuinely hanging host. Parallel dispatch makes this comfortable
// rather than tight, but follow-ups can extend the sweep so we keep
// the headroom.
func (c *ContentDiscovery) Budget() time.Duration { return 4 * time.Minute }

const (
	// contentDiscoveryBodyCap bounds how much body we read per probe.
	// All markers ride near the top of the file (.git/HEAD is <50
	// bytes; .env rarely exceeds a few KiB), and we never need to read
	// the disclosed file in full to confirm its presence. 16 KiB also
	// keeps the SHA1 fingerprint bounded so a single bad URL streaming
	// a 10 MB response can't pin a worker slot.
	contentDiscoveryBodyCap = 16 << 10

	// contentDiscoveryBaselineProbes is how many random-canary paths we
	// send to learn the host's missing-resource signature. Two probes
	// are enough to fingerprint a deterministic soft-404: matching
	// status+hash across both confirms the response is catch-all-shaped
	// rather than coincidentally aligned with one entry.
	contentDiscoveryBaselineProbes = 2

	// contentDiscoveryLenSlack is the absolute byte slack we allow when
	// comparing a candidate body length to the baseline. Without a
	// floor, a tiny baseline (100 bytes) wouldn't tolerate any drift
	// at all and a single byte of timestamp jitter would look like a
	// real hit.
	contentDiscoveryLenSlack = 64

	// contentDiscoveryLenRelSlack is the relative tolerance applied on
	// top of the absolute floor. 5% catches typical SPA shells that
	// inject a request ID without inflating false positives on pages
	// that genuinely changed shape.
	contentDiscoveryLenRelSlack = 0.05

	// contentDiscoveryConcurrency caps in-flight probe requests per
	// host sweep. 6 is the sweet spot: enough to mask per-request RTT
	// (a default sweep of ~25 probes drops from ~25 * RTT to ~5 * RTT)
	// without burying a small host under simultaneous connections or
	// fighting the shared httpclient rate limiter for slots. Going
	// higher mostly buys queue contention rather than speed.
	contentDiscoveryConcurrency = 6
)

func (c *ContentDiscovery) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if sc != nil && !sc.Allows(u) {
		return nil, nil
	}
	hostRoot := u.Scheme + "://" + u.Host
	if !c.claim(hostRoot) {
		// Another page on this host already triggered the sweep. We
		// emit nothing here - the findings rode out on the first
		// page's invocation and dedupe naturally on (check, host,
		// path).
		return nil, nil
	}

	baseline, err := c.baseline(ctx, client, hostRoot)
	if err != nil {
		return nil, fmt.Errorf("content-discovery baseline: %w", err)
	}
	if len(baseline.statuses) == 0 {
		// ctx canceled before any baseline probe completed; nothing
		// useful to do.
		return nil, nil
	}

	aggressive := LevelFrom(ctx) >= LevelAggressive
	stack := StackFrom(ctx)
	mainEntries := make([]discoveryEntry, 0, len(contentDiscoveryEntries)+8)
	for _, e := range contentDiscoveryEntries {
		if e.Aggressive && !aggressive {
			continue
		}
		// Stack gating: a confirmed-Apache host gets /web.config silently
		// dropped before probe dispatch (the IIS-only constraint), and an
		// unknown stack still probes everything. host-named backups added
		// below are stack-agnostic by construction.
		if !e.appliesTo(stack) {
			continue
		}
		mainEntries = append(mainEntries, e)
	}
	mainEntries = append(mainEntries, hostBackupEntries(u.Hostname())...)

	probed := map[string]struct{}{}
	findings := c.runProbes(ctx, client, sc, hostRoot, baseline, mainEntries, probed)

	// Second wave: expand on any hit whose path triggers a follow-up
	// group. Skipping when nothing fired keeps the cost zero on hosts
	// where the curated catalog drew a blank.
	if followUps := followUpsFor(findings, probed, stack); len(followUps) > 0 && ctx.Err() == nil {
		extra := c.runProbes(ctx, client, sc, hostRoot, baseline, followUps, probed)
		seen := make(map[string]struct{}, len(findings)+len(extra))
		for _, f := range findings {
			seen[f.DedupeKey] = struct{}{}
		}
		for _, f := range extra {
			if _, dup := seen[f.DedupeKey]; dup {
				continue
			}
			seen[f.DedupeKey] = struct{}{}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// runProbes dispatches entries against hostRoot in a bounded worker
// pool. probed is mutated in place: every dispatched path is recorded
// so a second call with the follow-up wave skips paths the main wave
// already covered. The function returns once every dispatched probe
// has settled (or the worker pool drained on ctx cancellation).
//
// Probe ordering inside entries is preserved as best-effort - the
// scheduler dispatches in slice order - but findings come back in
// completion order. Callers that care about ordering should sort
// downstream; the reporter already does.
func (c *ContentDiscovery) runProbes(ctx context.Context, client *httpclient.Client, sc *scope.Scope, hostRoot string, b discoveryBaseline, entries []discoveryEntry, probed map[string]struct{}) []Finding {
	var (
		findings []Finding
		seen     = map[string]struct{}{}
		mu       sync.Mutex
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, contentDiscoveryConcurrency)
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		if _, already := probed[entry.Path]; already {
			continue
		}
		probed[entry.Path] = struct{}{}
		probeURL := hostRoot + entry.Path
		pu, err := url.Parse(probeURL)
		if err != nil || (sc != nil && !sc.Allows(pu)) {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return findings
		}
		wg.Add(1)
		go func(e discoveryEntry, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			f, err := c.probe(ctx, client, hostRoot, b, e, target)
			if err != nil {
				Report(ctx, fmt.Errorf("content-discovery probe %s: %w", e.Path, err))
				return
			}
			if f == nil {
				return
			}
			mu.Lock()
			if _, dup := seen[f.DedupeKey]; !dup {
				seen[f.DedupeKey] = struct{}{}
				findings = append(findings, *f)
			}
			mu.Unlock()
		}(entry, probeURL)
	}
	wg.Wait()
	return findings
}

// followUpsFor walks the configured groups and returns every follow-up
// entry whose trigger appears in findings, skipping entries whose path
// is already in probed or whose stack constraint disagrees with stack.
// Returning a flat slice (rather than per-group) lets the second-wave
// dispatch share runProbes verbatim.
func followUpsFor(findings []Finding, probed map[string]struct{}, stack *fingerprint.Stack) []discoveryEntry {
	if len(findings) == 0 {
		return nil
	}
	hits := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if i := strings.Index(f.URL, "://"); i >= 0 {
			rest := f.URL[i+3:]
			if j := strings.IndexByte(rest, '/'); j >= 0 {
				hits[rest[j:]] = struct{}{}
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	var out []discoveryEntry
	queued := map[string]struct{}{}
	for _, g := range contentDiscoveryFollowUpGroups {
		triggered := false
		for _, t := range g.Triggers {
			if _, ok := hits[t]; ok {
				triggered = true
				break
			}
		}
		if !triggered {
			continue
		}
		for _, e := range g.Entries {
			if _, dup := probed[e.Path]; dup {
				continue
			}
			if _, dup := queued[e.Path]; dup {
				continue
			}
			if !e.appliesTo(stack) {
				continue
			}
			queued[e.Path] = struct{}{}
			out = append(out, e)
		}
	}
	return out
}

// hostBackupEntries synthesizes the host-named backup probes a sweep
// should always try at the document root: /<host>.zip, /<host>.sql,
// /<host>.tar.gz, /<host>.bak, plus the bare-label variants
// (example.com → example) when a label sits before the first dot.
// Backups named after the deployed site are common enough that bolting
// them onto every sweep costs little and routinely catches misplaced
// archives.
//
// Every synthetic carries an ExpectedContentTypes filter so a soft-200
// HTML wrapper served for an unknown extension can't fire the check.
func hostBackupEntries(rawHost string) []discoveryEntry {
	host := strings.ToLower(strings.TrimSpace(rawHost))
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return nil
	}
	// Preserve insertion order so the probe sequence is deterministic
	// across runs; map-only would randomize it.
	var names []string
	seen := map[string]struct{}{}
	add := func(n string) {
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	add(host)
	if dot := strings.IndexByte(host, '.'); dot > 0 {
		add(host[:dot])
	}

	type ext struct {
		suffix string
		cts    []string
	}
	exts := []ext{
		{".zip", []string{"application/zip", "application/x-zip-compressed", "application/octet-stream"}},
		{".tar.gz", []string{"application/gzip", "application/x-gzip", "application/x-tar", "application/octet-stream"}},
		{".sql", []string{"text/plain", "application/sql", "application/x-sql", "application/octet-stream"}},
		{".bak", []string{"application/octet-stream", "text/plain"}},
	}
	out := make([]discoveryEntry, 0, len(names)*len(exts))
	for _, n := range names {
		for _, e := range exts {
			out = append(out, discoveryEntry{
				Path:        "/" + n + e.suffix,
				Severity:    SeverityCritical,
				Title:       fmt.Sprintf("host-named backup reachable (%s%s)", n, e.suffix),
				Detail:      "A backup or archive named after the target host is served at the document root; these typically contain the full site source or database contents.",
				CWE:         "CWE-538",
				OWASP:       "A05:2021 Security Misconfiguration",
				Remediation: "Store backups outside the document root and rotate any credentials present in the archive.",
				ExpectedContentTypes: e.cts,
			})
		}
	}
	return out
}

// claim records hostRoot as swept and reports whether this caller won
// the race. Returns true exactly once per host across the lifetime of
// the receiver.
func (c *ContentDiscovery) claim(hostRoot string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visited == nil {
		c.visited = map[string]struct{}{}
	}
	if _, ok := c.visited[hostRoot]; ok {
		return false
	}
	c.visited[hostRoot] = struct{}{}
	return true
}

// discoveryBaseline captures the missing-resource response shape for one
// host. Probes whose response matches the baseline are silently dropped
// as soft-404s; anything that diverges on status, length, body
// fingerprint, content type, or redirect target is a candidate worth
// surfacing.
type discoveryBaseline struct {
	statuses    map[int]struct{}    // every distinct status the random probes returned
	bodyHashes  map[string]struct{} // sha1-prefix of body samples
	bodyLens    []int               // observed body lengths
	contentType string              // last seen content-type family
	location    string              // last seen Location header on a 3xx
}

func (c *ContentDiscovery) baseline(ctx context.Context, client *httpclient.Client, hostRoot string) (discoveryBaseline, error) {
	b := discoveryBaseline{
		statuses:   map[int]struct{}{},
		bodyHashes: map[string]struct{}{},
	}
	for i := 0; i < contentDiscoveryBaselineProbes; i++ {
		if ctx.Err() != nil {
			break
		}
		// Two canaries plus a benign-looking suffix: "/<canary>-<canary>.bad".
		// The suffix discourages any handler from trying to route on a
		// recognized extension, and the random twin halves make a
		// dictionary or path-template collision effectively impossible.
		path := "/" + NewCanary() + "-" + NewCanary() + ".bad"
		resp, body, _, err := c.fetch(ctx, client, hostRoot+path)
		if err != nil {
			if i > 0 {
				// One probe still gave us a usable baseline; the second
				// failing isn't fatal.
				break
			}
			return discoveryBaseline{}, err
		}
		b.statuses[resp.StatusCode] = struct{}{}
		b.bodyHashes[bodyHashPrefix(body)] = struct{}{}
		b.bodyLens = append(b.bodyLens, len(body))
		if ct := contentTypeFamily(resp.Header.Get("Content-Type")); ct != "" {
			b.contentType = ct
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			b.location = loc
		}
	}
	return b, nil
}

// looksLikeMiss reports whether a candidate response is shape-equivalent
// to the soft-404 baseline. Returning true silently drops the probe.
func (b discoveryBaseline) looksLikeMiss(status int, body []byte, ct, loc string) bool {
	if _, ok := b.statuses[status]; !ok {
		// Different status entirely (e.g. baseline 404, probe 200).
		// Not a baseline match - keep going.
		return false
	}
	switch {
	case status >= 300 && status < 400:
		// Redirect-shaped baseline: same Location means same destination
		// means same catch-all (e.g. all unknown paths redirect to /login).
		return loc != "" && b.location != "" && strings.EqualFold(loc, b.location)
	case status >= 200 && status < 300:
		// 2xx baseline: this is a catch-all. Confirm match by body hash
		// OR by (content-type family + body length proximity), since
		// some catch-alls inject a request ID or timestamp that changes
		// the hash without changing the shape.
		if _, ok := b.bodyHashes[bodyHashPrefix(body)]; ok {
			return true
		}
		if ct != "" && b.contentType != "" && contentTypeFamily(ct) == b.contentType {
			for _, bl := range b.bodyLens {
				if lengthCloseTo(len(body), bl) {
					return true
				}
			}
		}
		return false
	default:
		// 4xx (other than the auth-gated codes we handle separately) and
		// 5xx baseline: status match alone is sufficient evidence that
		// the host treats this probe the same as a known-missing path.
		return true
	}
}

func (c *ContentDiscovery) probe(ctx context.Context, client *httpclient.Client, hostRoot string, b discoveryBaseline, entry discoveryEntry, probeURL string) (*Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, contentDiscoveryBodyCap)
	if err != nil {
		return nil, err
	}
	status := resp.StatusCode
	ct := resp.Header.Get("Content-Type")
	loc := resp.Header.Get("Location")

	verdict, evidenceLine, severity := classifyDiscovery(entry, b, status, body, ct, loc)
	if verdict == "" {
		return nil, nil
	}

	return &Finding{
		Check:       c.Name(),
		Target:      hostRoot,
		URL:         probeURL,
		Severity:    severity,
		Title:       fmt.Sprintf("%s (%s)", entry.Title, verdict),
		Detail:      strings.TrimSpace(entry.Detail + " " + evidenceLine),
		CWE:         entry.CWE,
		OWASP:       entry.OWASP,
		Remediation: entry.Remediation,
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: probeURL,
			Status:     status,
			Snippet:    discoverySnippet(body, entry.Marker),
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		DedupeKey: MakeKey(c.Name(), ScopeHost, hostRoot, "path:"+entry.Path),
	}, nil
}

// classifyDiscovery decides whether the response to entry is a real find
// and what to say about it. Returns ("", "", "") for non-hits. Verdict
// strings ride into the finding title so a triager sees at a glance why
// the check fired (marker-match is high confidence; 200-distinct is the
// shape-only fallback).
func classifyDiscovery(entry discoveryEntry, b discoveryBaseline, status int, body []byte, ct, loc string) (string, string, Severity) {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		// 401/403 confirm the resource exists and is gated. For an
		// admin console or actuator endpoint, that is exactly the
		// finding worth reporting - the credential check is the only
		// thing between an attacker and the gated surface.
		return "auth-gated",
			fmt.Sprintf("Server returned %d, confirming the resource exists behind an authentication check.", status),
			entry.Severity
	}
	switch {
	case status >= 200 && status < 300:
		if entry.Marker != "" {
			if bytes.Contains(body, []byte(entry.Marker)) {
				return "marker-match",
					fmt.Sprintf("Response body contains %q - confirms the file is the genuine artifact, not a catch-all page.", entry.Marker),
					entry.Severity
			}
			// Marker required but absent. The 200 is almost certainly
			// a soft-404; suppressing here keeps high-noise paths
			// (/.env on an SPA-fronted site) from drowning the report.
			return "", "", ""
		}
		if b.looksLikeMiss(status, body, ct, loc) {
			return "", "", ""
		}
		if !contentTypeFamilyAllowed(ct, entry.ExpectedContentTypes) {
			// The entry's extension implies a non-HTML body and the
			// response advertised something else (typically text/html
			// from a soft-200 wrapper). Suppress rather than fire on
			// shape alone.
			return "", "", ""
		}
		return "200-distinct",
			fmt.Sprintf("Server returned %d with a response distinct from the soft-404 baseline (body length %d).", status, len(body)),
			entry.Severity
	case status >= 300 && status < 400:
		if b.looksLikeMiss(status, body, ct, loc) {
			return "", "", ""
		}
		return "redirects",
			fmt.Sprintf("Server returned %d Location: %s - distinct from the soft-404 baseline.", status, loc),
			entry.Severity
	}
	// Other 4xx / any 5xx: the host doesn't confirm presence and
	// often returns these for missing paths too. Don't fire.
	return "", "", ""
}

// discoverySnippet returns a short body excerpt suitable for the finding
// evidence. When the entry carries a marker, the snippet centers on the
// first marker occurrence; otherwise it returns the leading bytes (the
// most useful preview for a previously-unknown file).
func discoverySnippet(body []byte, marker string) string {
	if marker != "" {
		return snippet(body, []byte(marker), false)
	}
	const previewBytes = 512
	if len(body) > previewBytes {
		body = body[:previewBytes]
	}
	return strings.TrimSpace(string(body))
}

func (c *ContentDiscovery) fetch(ctx context.Context, client *httpclient.Client, target string) (*http.Response, []byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, false, err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, contentDiscoveryBodyCap)
	if err != nil {
		return resp, nil, truncated, err
	}
	return resp, body, truncated, nil
}

// bodyHashPrefix returns the leading 16 hex chars of a SHA1 over body.
// 64 bits of fingerprint is enough to make accidental collisions
// astronomically unlikely across a per-host probe sweep, while keeping
// the value short enough to be readable in evidence if we ever surface
// it. SHA1's collision weakness is irrelevant - there is no adversary
// choosing the body content of /etc/passwd to collide with an SPA's
// catch-all hash.
func bodyHashPrefix(body []byte) string {
	h := sha1.Sum(body)
	return hex.EncodeToString(h[:8])
}

// contentTypeFamily strips parameters from a media type, returning the
// bare "type/subtype" in lowercase. text/html;charset=utf-8 collapses
// to text/html so a charset reshuffle doesn't make a catch-all look
// content-type-distinct.
func contentTypeFamily(ct string) string {
	ct = strings.ToLower(ct)
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

// contentTypeFamilyAllowed reports whether a response's content-type is
// permitted under entry.ExpectedContentTypes. An empty allow list means
// "no constraint" (the entry never asked). An empty/missing CT header
// is treated as permissive - some servers genuinely omit Content-Type
// on binary downloads, so requiring it would surface false negatives
// on real /backup.zip exposures.
func contentTypeFamilyAllowed(ct string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	family := contentTypeFamily(ct)
	if family == "" {
		return true
	}
	for _, a := range allowed {
		if family == strings.ToLower(strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

// lengthCloseTo reports whether two byte lengths are within the
// discovery slack. Absolute floor (contentDiscoveryLenSlack) handles
// tiny bodies; relative slack (contentDiscoveryLenRelSlack) handles
// larger ones where a few bytes of timestamp jitter is meaningless.
func lengthCloseTo(a, b int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	if d <= contentDiscoveryLenSlack {
		return true
	}
	if b == 0 {
		return false
	}
	return float64(d)/float64(b) < contentDiscoveryLenRelSlack
}
