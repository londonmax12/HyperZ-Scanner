package crawler

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/londonball/hyperz/internal/page"
)

// wellKnownSpecPaths is the set of conventional URLs that frameworks expose
// OpenAPI / Swagger documents at. Probed once per seed origin when API
// discovery is enabled. 404s are expected and silently dropped.
var wellKnownSpecPaths = []string{
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

// looksLikeSpec is a cheap pre-filter that decides whether a non-HTML response
// is worth handing to the spec parser. We accept based on Content-Type (json /
// yaml) or based on the URL path suffix, since some servers serve specs as
// text/plain or application/octet-stream.
func looksLikeSpec(contentType, urlPath string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.Contains(ct, "yaml") {
		return true
	}
	p := strings.ToLower(urlPath)
	if strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
		return true
	}
	for _, suffix := range []string{"/api-docs", "/swagger", "/openapi"} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

// extractAPIEndpoints parses body as an OpenAPI 3 or Swagger 2 document
// (JSON or YAML) and returns absolute URLs for every operation in the
// `paths` map. specURL anchors relative server URLs and provides a
// fallback origin when the spec omits servers/host. Returns nil if body
// isn't a recognizable spec.
//
// Callers that need per-operation parameter inventory (input-fuzzing
// checks) should use extractAPIOperations; this helper is kept as a
// thin URL view for the crawler's submit loop and existing tests.
func extractAPIEndpoints(body []byte, specURL *url.URL) []string {
	ops := extractAPIOperations(body, specURL)
	if len(ops) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if _, ok := seen[op.URL]; ok {
			continue
		}
		seen[op.URL] = struct{}{}
		out = append(out, op.URL)
	}
	return out
}

// extractAPIOperations parses body as an OpenAPI 3 or Swagger 2 document
// and returns one entry per documented operation, complete with its
// declared parameter inventory. The YAML path is URL-only - we don't
// run a YAML library here, and the hand-rolled scanner only descends
// far enough to extract `paths:` keys. Specs served as JSON give full
// parameter coverage (query / path / header / cookie / body / formData).
//
// Each operation's URL is path-templated with "1" to be reachable; the
// raw `{param}` template is preserved on op.Tpl so callers building
// path sinks can substitute their own value into the right segment.
func extractAPIOperations(body []byte, specURL *url.URL) []page.SpecOp {
	servers, paths, jsonOps := parseJSONSpec(body)
	if len(paths) == 0 {
		servers, paths = parseYAMLSpec(body)
		jsonOps = nil
	}
	if len(paths) == 0 {
		return nil
	}
	if len(servers) == 0 {
		servers = []string{specOrigin(specURL)}
	}
	return combineServersAndOperations(servers, paths, jsonOps, specURL)
}

// combineServersAndOperations joins each server URL with each path
// template into one page.SpecOp per (server, path, method) triple,
// substituting `{param}` placeholders so the URL is reachable.
// jsonOps may be nil (YAML path) - the result then carries a single
// synthetic GET operation per path with no params, matching the old
// URL-only behavior. Results are deduped on (Method, URL).
func combineServersAndOperations(servers, paths []string, jsonOps map[string][]apiOp, specURL *url.URL) []page.SpecOp {
	type key struct{ method, url string }
	seen := map[key]int{}
	var out []page.SpecOp
	for _, s := range servers {
		base, err := resolveServerURL(s, specURL)
		if err != nil {
			continue
		}
		for _, p := range paths {
			tplURL := joinedURL(base, p, false)
			fullURL := joinedURL(base, p, true)
			ops := jsonOps[p]
			if len(ops) == 0 {
				ops = []apiOp{{Method: "GET"}}
			}
			for _, op := range ops {
				k := key{op.Method, fullURL}
				if _, ok := seen[k]; ok {
					continue
				}
				seen[k] = len(out)
				out = append(out, page.SpecOp{
					Method: op.Method,
					URL:    fullURL,
					Tpl:    tplURL,
					Params: op.Params,
				})
			}
		}
	}
	return out
}

// joinedURL returns the absolute URL for path p anchored at base.
// fillTemplate=true replaces `{param}` segments with "1" via the URL
// machinery so escaping matches the request the crawler will send.
// fillTemplate=false skips url.URL.String() entirely and concatenates
// pieces so OpenAPI `{param}` placeholders survive unescaped - the
// path-templated URL is consumed by SinksFor, not by an HTTP request,
// and percent-encoded braces would break placeholder substitution.
func joinedURL(base *url.URL, p string, fillTemplate bool) string {
	if fillTemplate {
		u := *base
		u.Path = joinPath(base.Path, fillPathTemplate(p))
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	prefix := base.Scheme + "://" + base.Host
	return prefix + joinPath(base.Path, p)
}

// apiOp is the internal per-operation record assembled from one HTTP
// method entry under a path item. Method is uppercase. Params is the
// merged parameter list (path-item-level + operation-level) plus any
// body/formData fields extracted from requestBody (OAS3) or `in: body`
// parameters (Swagger 2).
type apiOp struct {
	Method string
	Params []page.SpecParam
}

func resolveServerURL(server string, specURL *url.URL) (*url.URL, error) {
	su, err := url.Parse(server)
	if err != nil {
		return nil, err
	}
	if su.IsAbs() {
		return su, nil
	}
	if specURL == nil {
		return nil, errEmptyServer
	}
	return specURL.ResolveReference(su), nil
}

var errEmptyServer = &parseError{"server URL is relative and no spec URL available"}

type parseError struct{ msg string }

func (e *parseError) Error() string { return e.msg }

func joinPath(a, b string) string {
	if a == "" {
		return b
	}
	if !strings.HasPrefix(b, "/") {
		b = "/" + b
	}
	return strings.TrimSuffix(a, "/") + b
}

var pathTemplateRe = regexp.MustCompile(`\{[^}]+\}`)

// fillPathTemplate replaces OpenAPI `{param}` placeholders with "1" so the
// resulting URL routes on most servers. Active checks that care about
// parameter types swap their own values in; for passive checks any
// reachable URL is enough.
func fillPathTemplate(p string) string {
	return pathTemplateRe.ReplaceAllString(p, "1")
}

func specOrigin(u *url.URL) string {
	if u == nil {
		return ""
	}
	o := *u
	o.Path = ""
	o.RawQuery = ""
	o.Fragment = ""
	return o.String()
}

// --- JSON ---

type jsonSpec struct {
	Servers  []jsonServer            `json:"servers"`
	Paths    map[string]jsonPathItem `json:"paths"`
	Host     string                  `json:"host"`
	BasePath string                  `json:"basePath"`
	Schemes  []string                `json:"schemes"`
}

type jsonServer struct {
	URL string `json:"url"`
}

// jsonPathItem mirrors the OpenAPI / Swagger path-item shape. Unknown
// keys (summary, description, $ref, servers, etc.) are ignored by
// encoding/json. Parameters declared at the path-item level apply to
// every operation under it; we merge them into each operation's params.
type jsonPathItem struct {
	Parameters []jsonParam     `json:"parameters"`
	Get        *jsonOperation  `json:"get"`
	Post       *jsonOperation  `json:"post"`
	Put        *jsonOperation  `json:"put"`
	Delete     *jsonOperation  `json:"delete"`
	Patch      *jsonOperation  `json:"patch"`
	Head       *jsonOperation  `json:"head"`
	Options    *jsonOperation  `json:"options"`
}

type jsonOperation struct {
	Parameters  []jsonParam      `json:"parameters"`
	RequestBody *jsonRequestBody `json:"requestBody"` // OAS3
}

// jsonParam covers both OAS3 (where in: body never appears - body lives
// on requestBody) and Swagger 2 (where in: body / formData carry the
// body inputs inline). Schema is parsed lazily because its shape varies
// by `in:` and we only walk it for body params.
type jsonParam struct {
	Name    string          `json:"name"`
	In      string          `json:"in"`
	Example string          `json:"example"`
	Schema  json.RawMessage `json:"schema"`
}

type jsonRequestBody struct {
	Content map[string]jsonMediaType `json:"content"`
}

type jsonMediaType struct {
	Schema json.RawMessage `json:"schema"`
}

// jsonSchema is the slice of OpenAPI's schema we care about: top-level
// property names. We deliberately do not recurse into nested objects -
// the goal is to fuzz the request body's surface, and most active checks
// just need a flat list of field names with reasonable mutation targets.
type jsonSchema struct {
	Properties map[string]json.RawMessage `json:"properties"`
}

// parseJSONSpec returns the document's servers, ordered path keys, and
// per-path operations. paths preserves only keys that start with "/"
// (real route templates, not $refs or extension keys). ops is keyed by
// the path string and lists every documented method on it. Returns all
// nil when body isn't a recognizable JSON spec.
func parseJSONSpec(body []byte) (servers, paths []string, ops map[string][]apiOp) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil, nil, nil
	}
	var s jsonSpec
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, nil, nil
	}
	if len(s.Paths) == 0 {
		return nil, nil, nil
	}
	paths = make([]string, 0, len(s.Paths))
	ops = make(map[string][]apiOp, len(s.Paths))
	for p, item := range s.Paths {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		paths = append(paths, p)
		ops[p] = pathItemOperations(item)
	}
	if len(paths) == 0 {
		return nil, nil, nil
	}
	servers = collectJSONServers(&s)
	return servers, paths, ops
}

// pathItemOperations expands one path item into one apiOp per declared
// HTTP method, merging path-item-level parameters with operation-level
// parameters and walking the requestBody (OAS3) or in:body params
// (Swagger 2) for top-level JSON / formData field names.
func pathItemOperations(item jsonPathItem) []apiOp {
	type methodOp struct {
		name string
		op   *jsonOperation
	}
	methods := []methodOp{
		{"GET", item.Get},
		{"POST", item.Post},
		{"PUT", item.Put},
		{"DELETE", item.Delete},
		{"PATCH", item.Patch},
		{"HEAD", item.Head},
		{"OPTIONS", item.Options},
	}
	var out []apiOp
	for _, m := range methods {
		if m.op == nil {
			continue
		}
		params := mergeParams(item.Parameters, m.op.Parameters)
		params = append(params, requestBodyParams(m.op.RequestBody)...)
		out = append(out, apiOp{Method: m.name, Params: params})
	}
	return out
}

// mergeParams produces the combined parameter list for one operation,
// with operation-level params shadowing path-item-level params that
// share the same (in, name) - matches the OpenAPI override rule.
// in:body / formData entries are expanded into one SpecParam per
// top-level property of their schema (Swagger 2 body / form surface).
// Entries missing a name or `in:` are dropped.
func mergeParams(itemLevel, opLevel []jsonParam) []page.SpecParam {
	type key struct{ in, name string }
	seen := map[key]struct{}{}
	var out []page.SpecParam
	add := func(ps []jsonParam) {
		for _, p := range ps {
			if p.In == "" {
				continue
			}
			if p.In == "body" {
				// Swagger 2 body param: walk the schema for top-level
				// JSON field names. Name on the param itself is the
				// schema name (e.g. "user"), not a wire field.
				for _, fp := range jsonSchemaProperties(p.Schema, "body") {
					k := key{fp.In, fp.Name}
					if _, ok := seen[k]; ok {
						continue
					}
					seen[k] = struct{}{}
					out = append(out, fp)
				}
				continue
			}
			if p.Name == "" {
				continue
			}
			k := key{p.In, p.Name}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, page.SpecParam{In: p.In, Name: p.Name, Value: p.Example})
		}
	}
	// Operation-level first so it wins the (in,name) shadow check.
	add(opLevel)
	add(itemLevel)
	return out
}

// requestBodyParams turns an OAS3 requestBody into SpecParams, one per
// top-level property of the JSON schema (or form-urlencoded schema).
// Other media types are ignored - they're either binary (multipart,
// octet-stream) or text the fuzzer would need a body template for,
// neither of which the sink layer handles yet.
func requestBodyParams(rb *jsonRequestBody) []page.SpecParam {
	if rb == nil {
		return nil
	}
	var out []page.SpecParam
	if mt, ok := rb.Content["application/json"]; ok {
		out = append(out, jsonSchemaProperties(mt.Schema, "body")...)
	}
	if mt, ok := rb.Content["application/x-www-form-urlencoded"]; ok {
		out = append(out, jsonSchemaProperties(mt.Schema, "formData")...)
	}
	return out
}

// jsonSchemaProperties returns one SpecParam per top-level property
// name in schema. in is stamped onto each returned param so callers
// don't have to remember whether they walked a body or form schema.
// Nested object / array schemas are intentionally not flattened.
func jsonSchemaProperties(schema json.RawMessage, in string) []page.SpecParam {
	if len(schema) == 0 {
		return nil
	}
	var s jsonSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil
	}
	if len(s.Properties) == 0 {
		return nil
	}
	out := make([]page.SpecParam, 0, len(s.Properties))
	for name := range s.Properties {
		if name == "" {
			continue
		}
		out = append(out, page.SpecParam{In: in, Name: name})
	}
	return out
}

func collectJSONServers(s *jsonSpec) []string {
	var out []string
	for _, sv := range s.Servers {
		if sv.URL != "" {
			out = append(out, sv.URL)
		}
	}
	if len(out) > 0 {
		return out
	}
	if s.Host == "" {
		return nil
	}
	schemes := s.Schemes
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	for _, sch := range schemes {
		out = append(out, sch+"://"+s.Host+s.BasePath)
	}
	return out
}

// --- YAML ---
//
// We do not depend on a YAML library. OpenAPI specs we care about have a
// tiny, predictable shape: a top-level `paths:` map whose keys start with
// "/", and either a `servers:` list of `- url: ...` entries (OpenAPI 3)
// or top-level `host:` / `basePath:` / `schemes:` keys (Swagger 2). A
// focused indentation-aware scan extracts exactly that and ignores the
// rest of the document.

func parseYAMLSpec(body []byte) (servers, paths []string) {
	lo := bytes.ToLower(body)
	if !bytes.Contains(lo, []byte("paths:")) {
		return nil, nil
	}
	if !bytes.Contains(lo, []byte("openapi:")) && !bytes.Contains(lo, []byte("swagger:")) {
		return nil, nil
	}
	paths = extractYAMLPaths(body)
	if len(paths) == 0 {
		return nil, nil
	}
	servers = extractYAMLServers(body)
	return servers, paths
}

// extractYAMLPaths walks the body line by line and returns keys at the
// immediate child level of the top-level `paths:` mapping that start
// with "/". Quoted keys are unquoted; trailing comments are stripped.
// We only accept `paths:` at indent 0 - OpenAPI puts it at the document
// root, and the restriction prevents nested `paths:` keys (e.g. under
// components.examples) from being mistaken for the real one.
func extractYAMLPaths(body []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	inPaths := false
	childIndent := -1
	seen := map[string]struct{}{}
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := leadingIndent(raw)
		if !inPaths {
			if indent == 0 && isPathsKey(trimmed) {
				inPaths = true
				childIndent = -1
			}
			continue
		}
		if indent == 0 {
			// Any top-level key closes the paths block.
			inPaths = false
			continue
		}
		if childIndent == -1 {
			childIndent = indent
		}
		if indent != childIndent {
			continue
		}
		k, ok := yamlMapKey(trimmed)
		if !ok || !strings.HasPrefix(k, "/") {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func isPathsKey(trimmed string) bool {
	if trimmed == "paths:" {
		return true
	}
	if strings.HasPrefix(trimmed, "paths:") {
		// Allow trailing whitespace / comment but reject inline value.
		rest := strings.TrimSpace(trimmed[len("paths:"):])
		return rest == "" || strings.HasPrefix(rest, "#")
	}
	return false
}

// yamlMapKey extracts the key from a "key: value" or "key:" line. Strips
// surrounding quotes. Returns ok=false if the line has no colon.
func yamlMapKey(trimmed string) (string, bool) {
	if i := strings.Index(trimmed, "#"); i >= 0 {
		trimmed = strings.TrimSpace(trimmed[:i])
	}
	idx := strings.Index(trimmed, ":")
	if idx < 0 {
		return "", false
	}
	k := strings.TrimSpace(trimmed[:idx])
	k = strings.Trim(k, `"'`)
	return k, true
}

var (
	yamlServerURLRe   = regexp.MustCompile(`(?m)^\s*-\s*url\s*:\s*["']?([^"'\s]+)["']?`)
	yamlSwaggerHostRe = regexp.MustCompile(`(?m)^host\s*:\s*["']?([^"'\s]+)["']?`)
	yamlSwaggerBaseRe = regexp.MustCompile(`(?m)^basePath\s*:\s*["']?([^"'\s]+)["']?`)
	yamlSchemesRe     = regexp.MustCompile(`(?m)^schemes\s*:\s*\[([^\]]+)\]`)
)

func extractYAMLServers(body []byte) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, m := range yamlServerURLRe.FindAllSubmatch(body, -1) {
		s := string(m[1])
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		return out
	}
	host := firstYAMLMatch(body, yamlSwaggerHostRe)
	if host == "" {
		return nil
	}
	base := firstYAMLMatch(body, yamlSwaggerBaseRe)
	var schemes []string
	if m := yamlSchemesRe.FindSubmatch(body); len(m) >= 2 {
		for _, s := range strings.Split(string(m[1]), ",") {
			s = strings.Trim(strings.TrimSpace(s), `"'`)
			if s != "" {
				schemes = append(schemes, s)
			}
		}
	}
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	for _, sch := range schemes {
		out = append(out, sch+"://"+host+base)
	}
	return out
}

func firstYAMLMatch(body []byte, re *regexp.Regexp) string {
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}

func leadingIndent(s string) int {
	n := 0
	for _, r := range s {
		if r != ' ' && r != '\t' {
			break
		}
		n++
	}
	return n
}
