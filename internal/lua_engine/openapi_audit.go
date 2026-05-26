package lua_engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/scope"
)

// OpenAPIAudit discovers OpenAPI / Swagger documents at well-known
// per-host paths and audits the document itself for three classes of
// exposure that ship in the spec long before any request hits a real
// endpoint:
//
//  1. Embedded credentials. Specs are routinely committed alongside the
//     code that consumes them, so an inline `example:` value or a
//     `default:` baked into a server variable can promote a real
//     vendor key into the public surface. Every secrets_in_body pattern
//     fires here, with severity carried through from the catalogue.
//  2. Example authorization headers. Operations frequently illustrate
//     usage with `example: Bearer eyJ...` or `example: Basic dXNlcjpw`
//     values. The strings are often dummies, but JWTs and base64 basic-
//     auth blobs occasionally embed a real test account's credentials -
//     and even fully-synthetic examples leak schema and signing
//     algorithm information when they shouldn't.
//  3. Auth-less operations. When the spec declares an authentication
//     scheme via components.securitySchemes (OAS3) or
//     securityDefinitions (Swagger 2) but one or more operations carry
//     no security requirement (no operation-level `security:` AND no
//     global `security:` default), those operations are publicly
//     reachable. That may be intentional (a health probe) or a missing
//     guard; either way the operator should see the list.
//
// Per host: the check probes each well-known path at most once per
// scan, caches the parsed document plus the findings it produced, and
// re-emits those cached findings against subsequent pages on the same
// host with the new page URL stamped onto each finding so the report
// ties the issue to a page the user actually visited.
//
// Passive (LevelPassive) check.
type OpenAPIAudit struct {
	once  sync.Once
	mu    sync.Mutex
	cache map[string]openAPIAuditCacheEntry
}

// openAPIAuditCacheEntry memoizes the per-host probe result. A nil
// facts pointer represents a confirmed negative (well-known paths 404
// or the body wasn't a recognizable spec); a populated facts is re-used
// across every page on the host so the well-known endpoints are probed
// at most once per scan.
type openAPIAuditCacheEntry struct {
	facts *OpenAPIAuditFacts
}

// OpenAPIAuditFacts is the raw scan-facts shape the bridge returns to
// the Lua port. The fields are the probe metadata (URL the spec was
// served from, response status, raw body) the audit policy reads to
// run the secret / example-auth / authless-op passes. The audit lives
// in the .lua file; this struct is the algorithm input, not a finding.
type OpenAPIAuditFacts struct {
	ProbeURL string
	Status   int
	Body     []byte
}

// openAPISpecBodyCap bounds the spec body the check buffers. A real-
// world spec with hundreds of operations and inline schemas can reach
// a couple of megabytes pretty-printed; 4 MiB is a comfortable ceiling
// without letting a misbehaving edge pin a worker on a slow stream.
const openAPISpecBodyCap = 4 << 20

// openAPIWellKnownPaths is the curated list of conventional URLs at
// which frameworks expose OpenAPI / Swagger documents. Probed once per
// host when the check fires; 404 / non-spec responses are silently
// skipped. The list deliberately overlaps the crawler's discovery
// list - this check runs even on operators who disabled the crawler's
// API-discovery feature.
var openAPIWellKnownPaths = []string{
	"/openapi.json",
	"/openapi.yaml",
	"/openapi.yml",
	"/swagger.json",
	"/swagger.yaml",
	"/swagger.yml",
	"/swagger/v1/swagger.json",
	"/v2/api-docs",
	"/v3/api-docs",
	"/api-docs",
	"/api/swagger.json",
	"/api/openapi.json",
}

// DiscoverFacts returns the cached or freshly fetched OpenAPI spec
// facts for the host implied by pageURL, or nil when no well-known
// path served a recognisable spec. Per-host cache lifetime matches
// this receiver's lifetime (one *OpenAPIAudit per scan registration).
//
// The Lua port reads these facts and composes the finding catalog
// itself (title / severity / detail / CWE / OWASP / remediation /
// dedupe key / evidence); the algorithm input (HTTP fetch + version
// gate) stays in Go so per-host work happens at most once per scan
// regardless of which implementation runs at scan time.
func (c *OpenAPIAudit) DiscoverFacts(ctx context.Context, client *httpclient.Client, sc *scope.Scope, pageURL string) (*OpenAPIAuditFacts, error) {
	c.once.Do(func() {
		c.cache = map[string]openAPIAuditCacheEntry{}
	})

	u, err := url.Parse(pageURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}
	hostKey := strings.ToLower(u.Scheme + "://" + u.Host)

	c.mu.Lock()
	entry, cached := c.cache[hostKey]
	c.mu.Unlock()
	if cached {
		return entry.facts, nil
	}

	facts := c.probeHost(ctx, client, sc, u)
	c.mu.Lock()
	c.cache[hostKey] = openAPIAuditCacheEntry{facts: facts}
	c.mu.Unlock()
	return facts, nil
}

// probeHost walks the well-known spec paths on u's host and returns
// the facts for the first path whose body looks like a spec. Subsequent
// paths are not probed once a spec is found - mirror copies of the
// same document at multiple conventional URLs are expected and
// shouldn't produce duplicate findings.
func (c *OpenAPIAudit) probeHost(ctx context.Context, client *httpclient.Client, sc *scope.Scope, u *url.URL) *OpenAPIAuditFacts {
	base := u.Scheme + "://" + u.Host
	for _, path := range openAPIWellKnownPaths {
		probeURL := base + path
		probeU, err := url.Parse(probeURL)
		if err != nil {
			continue
		}
		if !sc.Allows(probeU) {
			continue
		}
		body, status, ok := c.fetchSpec(ctx, client, probeURL)
		if !ok {
			continue
		}
		if !looksLikeOpenAPIDoc(body) {
			continue
		}
		return &OpenAPIAuditFacts{
			ProbeURL: probeURL,
			Status:   status,
			Body:     body,
		}
	}
	return nil
}

// fetchSpec GETs probeURL and returns the response body when the
// response is a 200 the check can read. Returns ok=false on transport
// error, non-200, or empty body. The body is not parsed here so the
// caller can run regex passes that work on YAML and JSON alike.
func (c *OpenAPIAudit) fetchSpec(ctx context.Context, client *httpclient.Client, probeURL string) ([]byte, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, 0, false
	}
	req.Header.Set("Accept", "application/json, application/yaml, */*")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _, _ = httpclient.ReadBodyCapped(resp, 1<<10)
		return nil, resp.StatusCode, false
	}
	body, _, err := httpclient.ReadBodyCapped(resp, openAPISpecBodyCap)
	if err != nil || len(body) == 0 {
		return nil, resp.StatusCode, false
	}
	return body, resp.StatusCode, true
}

// looksLikeOpenAPIDoc reports whether body carries the canonical
// version marker of an OpenAPI 3 or Swagger 2 document. The check
// must avoid auditing generic JSON 404 envelopes, README prose that
// mentions "OpenAPI", or YAML config that happens to carry an
// `openapi:` boolean key. Requiring the version key to be followed by
// a digit (`"openapi":"3.x"` / `openapi: 3.x` / `"swagger":"2.x"`)
// rejects all three false positives while matching every real spec.
func looksLikeOpenAPIDoc(body []byte) bool {
	lo := bytes.ToLower(bytes.TrimSpace(body))
	if len(lo) == 0 {
		return false
	}
	return openAPIVersionRE.Match(lo)
}

// openAPIVersionRE matches the version key of a spec in either format:
// JSON ("openapi": "3.x") and YAML (openapi: 3.x), with or without
// quotes around the version, requiring a leading digit so prose and
// boolean values do not match.
var openAPIVersionRE = regexp.MustCompile(`(?:"?openapi"?|"?swagger"?)\s*:\s*["']?\d`)

// auditDoc runs every audit pass over the facts and returns the union
// of their findings. Each pass is independent so a body that fails
// JSON parsing (e.g. served as YAML) still gets the regex-based
// secret and example-token passes.
func (c *OpenAPIAudit) auditDoc(f *OpenAPIAuditFacts) []Finding {
	var out []Finding
	if fnd := c.findingEmbeddedCredentials(f); fnd != nil {
		out = append(out, *fnd)
	}
	if fnd := c.findingExampleAuthTokens(f); fnd != nil {
		out = append(out, *fnd)
	}
	if fnd := c.findingAuthlessOperations(f); fnd != nil {
		out = append(out, *fnd)
	}
	return out
}

// findingEmbeddedCredentials reuses the secrets_in_body catalogue to
// scan the spec body. Specs ship with examples and defaults that a
// careless author can populate with a real vendor key; every pattern
// in the shared catalogue therefore applies here too. Hits are
// deduplicated by (pattern.id, redacted) so the same key referenced
// from several example blocks collapses to one detail entry.
func (c *OpenAPIAudit) findingEmbeddedCredentials(f *OpenAPIAuditFacts) *Finding {
	probeURL := f.ProbeURL
	status := f.Status
	body := f.Body
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
		return nil
	}

	hits := make([]*secretHit, 0, len(seen))
	for _, h := range seen {
		hits = append(hits, h)
	}
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
		idParts = append(idParts, h.pattern.id+":"+red)
	}

	title := "OpenAPI spec embeds a credential (" + hits[0].pattern.label + ")"
	if len(hits) > 1 {
		title = fmt.Sprintf("OpenAPI spec embeds %d distinct credentials", len(hits))
	}

	leadIn := fmt.Sprintf("The OpenAPI / Swagger document at %s contains values matching known credential patterns. Specs are frequently published alongside the code that consumes them, so any credential value baked into an example or default ships to every reader of the document. Treat each entry as compromised the moment the spec was served.", probeURL)

	remediation := "Remove the embedded credential from the spec and rotate the value immediately - publication of a spec is a public disclosure of every literal value it carries. " +
		"Audit access logs for the affected key during the exposure window. " +
		"Replace any example or default that needs to demonstrate the shape of an authorized request with an obviously-fake placeholder (e.g. `xxxxxxxxxxxx`) and document elsewhere how a reader can obtain real credentials. " +
		"For specs generated from source annotations, scrub the upstream annotations so the next regeneration does not reintroduce the leak."

	return &Finding{
		Check:       "openapi-audit",
		Target:      probeURL,
		URL:         probeURL,
		Severity:    maxSev,
		Title:       title,
		Detail:      leadIn,
		Details:     details,
		CWE:         "CWE-200, CWE-798",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: remediation,
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: probeURL,
			Status:     status,
			Snippet:    snippetJSON(body),
		},
		DedupeKey: MakeKey("openapi-audit", ScopeHost, probeURL, append([]string{"embedded-credentials"}, idParts...)...),
	}
}

// titleAuthScheme normalizes a matched scheme to "Bearer" / "Basic"
// for display. strings.ToTitle / strings.Title both either uppercase
// the whole token or are deprecated; the audit only handles two
// schemes, so the explicit branch is the clearest option.
func titleAuthScheme(raw string) string {
	switch strings.ToLower(raw) {
	case "bearer":
		return "Bearer"
	case "basic":
		return "Basic"
	}
	return raw
}

// openAPIExampleHeaderRe matches `Bearer <token>` and `Basic <base64>`
// values plausibly shaped like a real Authorization header. The 20-
// char value floor is tight enough to skip placeholders like
// "Bearer TOKEN" / "Basic YOUR_KEY" while still catching JWTs and
// base64 blobs that resemble production credentials.
var openAPIExampleHeaderRe = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._+/=-]{20,})`)

// openAPIExampleContextRe matches an OpenAPI key that explains why an
// Authorization-shaped value would appear in a documentation artifact.
// A bearer-shaped string that sits next to one of these keys is the
// thing the check wants to surface; one that does not is more likely
// to be unrelated text the operator already knows about. The optional
// trailing `"` / `'` lets the regex match the JSON shape `"example":`
// as well as the YAML shape `example:` without two separate patterns.
var openAPIExampleContextRe = regexp.MustCompile(`(?i)\b(examples?|default|value|x-example)["']?\s*[:=]`)

// findingExampleAuthTokens reports Authorization-style values that
// appear in example / default / value blocks of the spec. JWTs caught
// here are typically already flagged by the embedded-credentials pass
// (the catalogue has a JWT pattern) but the structured grouping is
// still useful: a reader sees both the credential-leak verdict and
// the documentation-exposure verdict side by side. Basic-auth blobs
// not matched by any vendor pattern surface here exclusively.
func (c *OpenAPIAudit) findingExampleAuthTokens(f *OpenAPIAuditFacts) *Finding {
	probeURL := f.ProbeURL
	status := f.Status
	body := f.Body
	type exampleHit struct {
		scheme   string
		value    string
		redacted string
	}
	matches := openAPIExampleHeaderRe.FindAllSubmatchIndex(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]exampleHit{}
	for _, m := range matches {
		if !hasNearbyContext(body, m[0], m[1], openAPIExampleContextRe) {
			continue
		}
		scheme := titleAuthScheme(string(body[m[2]:m[3]]))
		value := string(body[m[4]:m[5]])
		red := redactSecret(value)
		key := scheme + ":" + red
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = exampleHit{scheme: scheme, value: value, redacted: red}
	}
	if len(seen) == 0 {
		return nil
	}

	hits := make([]exampleHit, 0, len(seen))
	for _, h := range seen {
		hits = append(hits, h)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].scheme != hits[j].scheme {
			return hits[i].scheme < hits[j].scheme
		}
		return hits[i].redacted < hits[j].redacted
	})

	details := make([]string, 0, len(hits))
	idParts := make([]string, 0, len(hits))
	for _, h := range hits {
		details = append(details, fmt.Sprintf("%s example: %s", h.scheme, h.redacted))
		idParts = append(idParts, h.scheme+":"+h.redacted)
	}

	leadIn := fmt.Sprintf("The OpenAPI / Swagger document at %s carries Authorization-header values inside example / default / value blocks. Even fully-synthetic examples leak the signing algorithm and claim shape (for JWTs) or the username portion before the colon (for Basic) to every reader of the spec; an example accidentally populated with a real test-account credential is publicly disclosed.", probeURL)

	remediation := "Replace example Authorization values with obviously-fake placeholders that still demonstrate the wire format (e.g. `Bearer <token>` or `Basic dXNlcjpwYXNz` containing only synthetic data). " +
		"For JWT examples, generate a token with random keys at documentation-build time rather than copying a real one from a development environment. " +
		"For Basic examples, never use a real account's username even if the password portion is fake - the username alone is enough to enumerate the directory."

	return &Finding{
		Check:       "openapi-audit",
		Target:      probeURL,
		URL:         probeURL,
		Severity:    SeverityLow,
		Title:       "OpenAPI spec carries example Authorization tokens",
		Detail:      leadIn,
		Details:     details,
		CWE:         "CWE-200",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: remediation,
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: probeURL,
			Status:     status,
			Snippet:    snippetJSON(body),
		},
		DedupeKey: MakeKey("openapi-audit", ScopeHost, probeURL, append([]string{"example-auth-tokens"}, idParts...)...),
	}
}

// findingAuthlessOperations parses the spec as JSON and reports
// operations that carry no security requirement when the spec
// otherwise declares an authentication scheme. The audit only fires
// when the spec advertises at least one securityScheme - a spec that
// declares no auth at all is a different conversation (the API is
// either intentionally public or the spec author omitted the scheme)
// and is left to the operator. JSON-only because the YAML path in
// the crawler is deliberately URL-only; parsing YAML auth structure
// would require pulling in a real YAML library for one finding.
func (c *OpenAPIAudit) findingAuthlessOperations(f *OpenAPIAuditFacts) *Finding {
	probeURL := f.ProbeURL
	status := f.Status
	body := f.Body
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var doc openAPISecurityDoc
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil
	}
	if !doc.declaresSecurity() {
		return nil
	}
	globalRequired := requirementIsAuthenticated(doc.Security)

	type opEntry struct{ method, path string }
	var unauth []opEntry
	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/") {
			continue
		}
		for _, mo := range item.methods() {
			if operationIsAuthenticated(mo.op, globalRequired) {
				continue
			}
			unauth = append(unauth, opEntry{method: mo.method, path: path})
		}
	}
	if len(unauth) == 0 {
		return nil
	}
	sort.SliceStable(unauth, func(i, j int) bool {
		if unauth[i].path != unauth[j].path {
			return unauth[i].path < unauth[j].path
		}
		return unauth[i].method < unauth[j].method
	})

	details := make([]string, 0, len(unauth))
	idParts := make([]string, 0, len(unauth))
	for _, e := range unauth {
		details = append(details, e.method+" "+e.path)
		idParts = append(idParts, e.method+" "+e.path)
	}

	leadIn := fmt.Sprintf("The OpenAPI / Swagger document at %s declares an authentication scheme (components.securitySchemes / securityDefinitions) but %d operation(s) carry no security requirement and inherit no global default. Those operations are reachable without credentials.", probeURL, len(unauth))

	remediation := "Add an explicit `security:` block to every operation that should require authentication, or set a global `security:` default at the document root that those operations inherit. " +
		"For operations that are genuinely meant to be public (a health probe, a login endpoint), document the intent with `security: []` so the reader can tell at a glance that the empty requirement is deliberate rather than an oversight. " +
		"Audit the listed operations against the application's authentication middleware - the spec and the runtime can diverge, and either side of the divergence is a finding."

	return &Finding{
		Check:       "openapi-audit",
		Target:      probeURL,
		URL:         probeURL,
		Severity:    SeverityMedium,
		Title:       "OpenAPI spec declares auth schemes but exposes unauthenticated operations",
		Detail:      leadIn,
		Details:     details,
		CWE:         "CWE-306",
		OWASP:       "A01:2021 Broken Access Control",
		Remediation: remediation,
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: probeURL,
			Status:     status,
			Snippet:    snippetJSON(body),
		},
		DedupeKey: MakeKey("openapi-audit", ScopeHost, probeURL, append([]string{"authless-operations"}, idParts...)...),
	}
}

// openAPISecurityDoc is the subset of the spec the auth-less audit
// inspects: declared schemes (under either OAS3 or Swagger 2 keys),
// the global security default, and per-operation security. Unknown
// fields are ignored.
type openAPISecurityDoc struct {
	Security            []map[string][]string              `json:"security"`
	Components          openAPIComponents                  `json:"components"`
	SecurityDefinitions map[string]json.RawMessage         `json:"securityDefinitions"`
	Paths               map[string]openAPISecurityPathItem `json:"paths"`
}

type openAPIComponents struct {
	SecuritySchemes map[string]json.RawMessage `json:"securitySchemes"`
}

type openAPISecurityPathItem struct {
	Get     *openAPISecurityOp `json:"get"`
	Post    *openAPISecurityOp `json:"post"`
	Put     *openAPISecurityOp `json:"put"`
	Delete  *openAPISecurityOp `json:"delete"`
	Patch   *openAPISecurityOp `json:"patch"`
	Head    *openAPISecurityOp `json:"head"`
	Options *openAPISecurityOp `json:"options"`
}

// methodOp pairs a method label with the operation pointer so the
// caller can iterate without a branch per method. Returned in the
// canonical method order so the auth-less list is stable across runs.
type methodOp struct {
	method string
	op     *openAPISecurityOp
}

func (it openAPISecurityPathItem) methods() []methodOp {
	all := []methodOp{
		{"GET", it.Get},
		{"POST", it.Post},
		{"PUT", it.Put},
		{"DELETE", it.Delete},
		{"PATCH", it.Patch},
		{"HEAD", it.Head},
		{"OPTIONS", it.Options},
	}
	out := all[:0]
	for _, mo := range all {
		if mo.op == nil {
			continue
		}
		out = append(out, mo)
	}
	return out
}

// openAPISecurityOp captures the operation-level fields the audit
// reads. Security is a pointer to distinguish "not provided" (inherit
// global) from "explicitly empty" (intentional public op); Go's nil
// slice does not preserve that, so we keep the raw shape.
type openAPISecurityOp struct {
	Security *[]map[string][]string `json:"security"`
}

func (d openAPISecurityDoc) declaresSecurity() bool {
	return len(d.Components.SecuritySchemes) > 0 || len(d.SecurityDefinitions) > 0
}

// requirementIsAuthenticated returns true when at least one entry in
// req carries a non-empty scheme name. The empty list and a list
// whose only entry is `{}` both mean "no auth required"; an entry
// with any named scheme means the operation enforces auth.
func requirementIsAuthenticated(req []map[string][]string) bool {
	for _, entry := range req {
		for name := range entry {
			if strings.TrimSpace(name) != "" {
				return true
			}
		}
	}
	return false
}

// operationIsAuthenticated decides whether op enforces authentication.
// An operation with no `security:` field inherits globalRequired; an
// operation that sets `security:` overrides it (including the
// override-to-empty case `security: []`, which is the canonical way
// to document a deliberately-public operation under a globally-
// secured API).
func operationIsAuthenticated(op *openAPISecurityOp, globalRequired bool) bool {
	if op == nil {
		return globalRequired
	}
	if op.Security == nil {
		return globalRequired
	}
	return requirementIsAuthenticated(*op.Security)
}
