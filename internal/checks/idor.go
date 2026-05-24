package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// IDOR probes for Insecure Direct Object Reference flaws by tampering
// with parameters whose values look like resource identifiers and
// observing whether the application still returns a meaningful body
// for the tampered ID. Two cooperating pieces drive the check:
//
//  1. A pattern detection engine (idor_patterns.go) classifies each
//     sink value into an identifier family (numeric, UUID, mongoid,
//     slug, email, username, hex, base64ish) and produces tampering
//     candidates of the same shape - sequential integers for numeric,
//     same-shape UUIDs for UUID, corpus-swapped usernames for username.
//  2. A scan-lifetime Corpus (idor_corpus.go) collects values seen on
//     every crawled page, clusters them by shape signature, and
//     promotes recurring shapes into learned patterns so a sink with
//     a value like `ORD-A12B3C` gets same-shape garbage payloads
//     even though no built-in pattern covers the order-id format.
//
// Each candidate sink is probed in three rounds:
//
//   - Baseline: the request as the crawler observed it. Must return a
//     2xx body of at least minBaselineBodySize bytes; otherwise the
//     sink is skipped (no content to compare against).
//   - Control: the same request with a guaranteed-garbage value of
//     the same shape (controlPayloadFor). The control is the
//     false-positive backstop: if the app returns ~baseline for any
//     garbage ID, the endpoint either ignores the parameter (public
//     resource) or rendered a SPA shell - either way, not IDOR.
//   - Tampered: up to maxTamperedProbes candidates from the
//     pattern's Generate. The first to trigger a verdict ends the
//     sink's probe loop.
//
// idorJudge fires Vulnerable when the tampered response diverges from
// baseline below SimilarityThreshold AND the control either rejected
// or also diverged from baseline. Confidence escalates to High when
// the tampered body carries PII markers (email/name/phone JSON
// fields). All findings ship at SeverityHigh - true cross-tenant
// confirmation requires multi-credential probing, which is out of
// scope here, so the check tops out below Critical.
//
// This is an active check at LevelAggressive. The IDOR struct is
// pointer-registered so its Corpus survives across every Run call in
// a scan; concurrent page workers ingest under one mutex.
type IDOR struct {
	once   sync.Once
	corpus *Corpus
}

func (c *IDOR) Name() string { return "idor" }

func (c *IDOR) Level() Level { return LevelAggressive }

// Budget grants the check enough time to clear the per-sink probe cap
// across a page that exposes several identifier sinks. Five probes per
// sink * eight sinks per page = 40 sequential requests; DefaultBudget
// (60s) is too tight under any meaningful rate limiter, three minutes
// covers it without pinning a worker slot on a pathological page.
func (c *IDOR) Budget() time.Duration { return 3 * time.Minute }

const (
	// idorBodyCap matches the boolean SQLi / NoSQLi cap. The IDOR oracle
	// relies on Similarity scoring across the full body to spot
	// row-content divergence inside a templated wrapper; a smaller cap
	// would let large pages always cluster near the same score.
	idorBodyCap = 64 << 10

	// maxTamperedProbes caps how many candidates the pattern's Generate
	// is allowed to surface per sink. Three probes is enough to cover
	// ±1, ±10, and a corpus swap for numerics; UUIDs draw from corpus
	// plus an all-zero canary. Larger caps mostly burn requests without
	// improving signal because the first divergent response ends the
	// sink's loop.
	maxTamperedProbes = 3

	// maxSinksPerPage caps how many identifier sinks one page is
	// allowed to consume from the per-page probe budget. Sinks are
	// sorted by pattern precedence (numeric / uuid first) so a page
	// with dozens of low-signal slug params still spends its budget
	// on the highest-value targets. Past the cap the rest are
	// reported via Report and skipped.
	maxSinksPerPage = 8

	// minBaselineBodySize is the floor below which a baseline response
	// is treated as "nothing to compare against" - empty pages or pure
	// error stubs leave the Similarity oracle without enough material
	// to distinguish IDOR from noise.
	minBaselineBodySize = 64
)

// idorParamDenylist names params that look identifier-shaped on the
// wire but never carry resource references. Probing them only wastes
// requests and risks false positives (changing `page=1` to `page=2`
// naturally returns different content). The list stays conservative -
// anything not in here gets a chance to pass the pattern classifier,
// which itself rejects values that don't look like identifiers.
var idorParamDenylist = map[string]struct{}{
	"q":       {},
	"query":   {},
	"search":  {},
	"s":       {},
	"page":    {},
	"limit":   {},
	"offset":  {},
	"count":   {},
	"size":    {},
	"per_page": {},
	"sort":    {},
	"order":   {},
	"filter":  {},
	"lang":    {},
	"locale":  {},
	"format":  {},
	"csrf":    {},
	"_csrf":   {},
	"token":   {},
	"_token":  {},
	"hash":    {},
	"sig":     {},
	"signature": {},
	"nonce":   {},
	"_":       {},
	"v":       {},
	"version": {},
	"t":       {},
	"timestamp": {},
	"callback":  {},
	"jsonp":     {},
}

// Run probes every identifier-shaped sink on p for IDOR. The page's
// values are ingested into the scan-lifetime corpus before any probe
// runs, so the page's own values are available as tampering candidates
// for sibling sinks on the same page; values from earlier pages
// remain available too.
func (c *IDOR) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	c.once.Do(func() { c.corpus = NewCorpus() })
	c.corpus.IngestPage(p)

	candidates := c.identifierSinks(p)
	if len(candidates) == 0 {
		return nil, nil
	}
	if len(candidates) > maxSinksPerPage {
		Report(ctx, fmt.Errorf("idor: page %s exposed %d identifier sinks; capping at %d",
			p.URL, len(candidates), maxSinksPerPage))
		candidates = candidates[:maxSinksPerPage]
	}

	var findings []Finding
	for _, cand := range candidates {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		if f, ok := c.probeSink(ctx, client, p.URL, cand); ok {
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// idorCandidate is one identifier-shaped probe target. It carries the
// underlying Sink (already understood by MutateRequest) plus the
// classified Pattern so probeSink can both build requests and draw
// tampering payloads without re-classifying.
type idorCandidate struct {
	sink    Sink
	pattern *Pattern
	// pathSegment is the segment label for path-based sinks rendered
	// from a URL path (e.g. /api/users/42 -> "user_id_path_2"). Empty
	// for query/form/json sinks where Sink.Name is already meaningful.
	pathSegment string
}

// identifierSinks returns every sink on p that looks like a resource
// identifier, sorted by pattern precedence so high-signal types
// (numeric, UUID) probe first when the per-page cap forces a trim.
//
// Both crawler-visible sinks (SinksFor) and heuristic path-segment
// IDs are considered; path segments are synthesized into LocPath
// sinks so MutateRequest can swap them in via its placeholder
// machinery.
func (c *IDOR) identifierSinks(p page.Page) []idorCandidate {
	var out []idorCandidate
	for _, s := range SinksFor(p) {
		switch s.Loc {
		case LocHeader, LocCookie:
			continue
		}
		if _, denied := idorParamDenylist[strings.ToLower(s.Name)]; denied {
			continue
		}
		pat := c.corpus.Classify(s.Name, s.Value)
		if pat == nil {
			continue
		}
		out = append(out, idorCandidate{sink: s, pattern: pat})
	}
	for _, ps := range c.pathSinks(p.URL) {
		out = append(out, ps)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].pattern.Precedence != out[j].pattern.Precedence {
			return out[i].pattern.Precedence > out[j].pattern.Precedence
		}
		return out[i].sink.Name < out[j].sink.Name
	})
	return out
}

// pathSinks scans rawURL for path segments that classify as identifiers
// and synthesizes LocPath sinks for them. The URL is rewritten with a
// `{segN}` placeholder at the target segment so Sink.MutateRequest's
// LocPath case can swap in payloads via its existing path-escape
// machinery.
func (c *IDOR) pathSinks(rawURL string) []idorCandidate {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return nil
	}
	segs := strings.Split(u.EscapedPath(), "/")
	var out []idorCandidate
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			continue
		}
		pat := c.corpus.Classify("__path__", decoded)
		if pat == nil {
			continue
		}
		// Only path-classifiable types are worth probing as path
		// segments. Email / username / slug in a path are usually
		// SEO-friendly URLs whose ID lives in the query string instead.
		switch pat.Name {
		case patternNameNumeric, patternNameUUID, patternNameMongoID, patternNameHex:
		default:
			continue
		}
		segName := fmt.Sprintf("seg%d", i)
		placeholderSegs := make([]string, len(segs))
		copy(placeholderSegs, segs)
		placeholderSegs[i] = "{" + segName + "}"
		placeholderURL := *u
		placeholderURL.RawPath = strings.Join(placeholderSegs, "/")
		placeholderURL.Path = placeholderURL.RawPath
		out = append(out, idorCandidate{
			sink: Sink{
				Method: http.MethodGet,
				URL:    placeholderURL.String(),
				Loc:    LocPath,
				Name:   segName,
				Value:  decoded,
			},
			pattern:     pat,
			pathSegment: fmt.Sprintf("path segment %d", i),
		})
	}
	return out
}

// probeSink runs the baseline / control / tampered triple against one
// candidate and returns a Finding when the oracle decides the
// behaviour is consistent with IDOR.
func (c *IDOR) probeSink(ctx context.Context, client *httpclient.Client, pageURL string, cand idorCandidate) (Finding, bool) {
	baselineReq, baselineSnap, baselineExch, err := c.send(ctx, client, cand.sink, cand.sink.Value)
	if err != nil {
		Report(ctx, fmt.Errorf("idor baseline %s %s=%s: %w", cand.sink.Method, cand.sink.Name, cand.sink.Value, err))
		return Finding{}, false
	}
	_ = baselineReq
	_ = baselineExch
	if !is2xx(baselineSnap.Status) || len(baselineSnap.Body) < minBaselineBodySize {
		return Finding{}, false
	}

	controlPayload := controlPayloadFor(cand.pattern, cand.sink.Value)
	_, controlSnap, _, err := c.send(ctx, client, cand.sink, controlPayload)
	if err != nil {
		Report(ctx, fmt.Errorf("idor control %s %s=%s: %w", cand.sink.Method, cand.sink.Name, controlPayload, err))
		return Finding{}, false
	}

	tamperedCandidates := cand.pattern.Generate(cand.sink.Value, c.corpus, maxTamperedProbes)
	for _, payload := range tamperedCandidates {
		select {
		case <-ctx.Done():
			return Finding{}, false
		default:
		}
		if payload == cand.sink.Value || payload == controlPayload {
			continue
		}
		tamperedReq, tamperedSnap, tamperedExch, err := c.send(ctx, client, cand.sink, payload)
		if err != nil {
			Report(ctx, fmt.Errorf("idor tampered %s %s=%s: %w", cand.sink.Method, cand.sink.Name, payload, err))
			continue
		}
		verdict := idorJudge(baselineSnap, tamperedSnap, controlSnap)
		if !verdict.Vulnerable {
			continue
		}
		return c.makeFinding(pageURL, cand, controlPayload, payload, baselineSnap, controlSnap, tamperedSnap, tamperedReq, tamperedExch, verdict), true
	}
	return Finding{}, false
}

// send issues one probe and returns the request, the snapshot the
// oracle compares on, and the Exchange retained for finding evidence.
func (c *IDOR) send(ctx context.Context, client *httpclient.Client, sink Sink, payload string) (*http.Request, Snapshot, *Exchange, error) {
	req, err := sink.MutateRequest(ctx, payload)
	if err != nil {
		return nil, Snapshot{}, nil, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, Snapshot{}, RecordExchange(req, nil, false, nil, nil, false), err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, idorBodyCap)
	if err != nil {
		return req, Snapshot{}, RecordExchange(req, nil, false, resp, body, truncated), err
	}
	return req,
		Snapshot{Status: resp.StatusCode, Body: body},
		RecordExchange(req, nil, false, resp, body, truncated),
		nil
}

// makeFinding builds the finding payload from the three snapshots and
// the oracle verdict. Severity stays at High - confirming a true
// cross-user data leak requires a second authenticated context which
// hyperz doesn't have today. Confidence rides through the Details
// bullet list so a reader can see whether the engine had control-
// reject evidence and PII markers behind the verdict.
func (c *IDOR) makeFinding(pageURL string, cand idorCandidate, controlPayload, tamperedPayload string,
	baseline, control, tampered Snapshot,
	tamperedReq *http.Request, tamperedExch *Exchange, verdict idorVerdict) Finding {

	loc := string(cand.sink.Loc)
	if cand.pathSegment != "" {
		loc = cand.pathSegment
	}
	patternName := cand.pattern.Name
	if cand.pattern.Learned {
		patternName += " (learned shape)"
	}

	title := fmt.Sprintf("Possible IDOR on %s parameter %q", loc, cand.sink.Name)
	detail := fmt.Sprintf(
		"Tampering the %s value (classified as %s) altered the response in a way consistent with broken authorization: %s",
		loc, patternName, verdict.Detail,
	)

	tamperedBullet := fmt.Sprintf("tampered payload %q: status=%d sim-vs-baseline=%.3f", tamperedPayload, tampered.Status, verdict.TamperedSim)
	if is2xx(control.Status) {
		tamperedBullet += fmt.Sprintf(" sim-vs-control=%.3f", verdict.TamperedControlSim)
	}
	details := []string{
		fmt.Sprintf("baseline: status=%d body=%dB", baseline.Status, len(baseline.Body)),
		fmt.Sprintf("control payload %q: status=%d sim-vs-baseline=%.3f", controlPayload, control.Status, verdict.ControlSim),
		tamperedBullet,
		fmt.Sprintf("confidence: %s", verdict.Confidence),
	}
	for _, hint := range verdict.PIIHints {
		details = append(details, "tampered body PII marker: "+hint)
	}

	tamperedURL := ""
	if tamperedReq != nil && tamperedReq.URL != nil {
		tamperedURL = tamperedReq.URL.String()
	}
	evidence := &Evidence{
		Method:     cand.sink.Method,
		RequestURL: tamperedURL,
		Status:     tampered.Status,
		Exchange:   tamperedExch,
	}

	return Finding{
		Check:    c.Name(),
		Target:   pageURL,
		URL:      pageURL,
		Severity: SeverityHigh,
		Title:    title,
		Detail:   detail,
		Details:  details,
		CWE:      "CWE-639",
		OWASP:    "A01:2021 Broken Access Control",
		Remediation: strings.Join([]string{
			"Enforce object-level authorization on every request: verify the requesting principal owns or is otherwise permitted to access the identified resource before returning it.",
			"Prefer indirect references (per-session opaque tokens) or scoped lookups (`WHERE owner_id = current_user`) over trusting client-supplied IDs.",
			"Add automated tests that swap identifiers across users in CI so regressions cannot reach production unnoticed.",
		}, " "),
		Evidence:  evidence,
		DedupeKey: MakeKey(c.Name(), ScopeParam, pageURL, string(cand.sink.Loc), cand.sink.Name),
	}
}
