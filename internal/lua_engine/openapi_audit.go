package lua_engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
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

