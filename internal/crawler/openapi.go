package crawler

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
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
func extractAPIEndpoints(body []byte, specURL *url.URL) []string {
	servers, paths := parseJSONSpec(body)
	if len(paths) == 0 {
		servers, paths = parseYAMLSpec(body)
	}
	if len(paths) == 0 {
		return nil
	}
	if len(servers) == 0 {
		servers = []string{specOrigin(specURL)}
	}
	return combineServersAndPaths(servers, paths, specURL)
}

// combineServersAndPaths joins each server URL with each path template,
// substituting `{param}` placeholders so the resulting URL is reachable.
// Results are deduped to avoid the cartesian product blowing up when a
// spec lists multiple equivalent servers.
func combineServersAndPaths(servers, paths []string, specURL *url.URL) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(servers)*len(paths))
	for _, s := range servers {
		base, err := resolveServerURL(s, specURL)
		if err != nil {
			continue
		}
		for _, p := range paths {
			u := *base
			u.Path = joinPath(base.Path, fillPathTemplate(p))
			u.RawQuery = ""
			u.Fragment = ""
			full := u.String()
			if _, ok := seen[full]; ok {
				continue
			}
			seen[full] = struct{}{}
			out = append(out, full)
		}
	}
	return out
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
	Servers  []jsonServer               `json:"servers"`
	Paths    map[string]json.RawMessage `json:"paths"`
	Host     string                     `json:"host"`
	BasePath string                     `json:"basePath"`
	Schemes  []string                   `json:"schemes"`
}

type jsonServer struct {
	URL string `json:"url"`
}

func parseJSONSpec(body []byte) (servers, paths []string) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil, nil
	}
	var s jsonSpec
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, nil
	}
	if len(s.Paths) == 0 {
		return nil, nil
	}
	paths = make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		if strings.HasPrefix(p, "/") {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	servers = collectJSONServers(&s)
	return servers, paths
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
