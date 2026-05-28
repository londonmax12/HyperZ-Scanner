package lua_engine

import (
	"bytes"
	"encoding/json"
	"strings"
)

// This file exposes the openapi-audit check's helpers to the Lua
// bridge. Sibling to openapi_audit.go: forwards into the package-
// private regex anchors, narrow JSON struct, and authentication-
// requirement classifier so the Lua port runs the same authless-
// operations audit the Go check does.

// OpenAPIExampleAuthMatchLua is one Bearer/Basic value found in an
// example / default / value block of an OpenAPI spec body. The scheme
// is normalized to title-case ("Bearer" / "Basic"); raw is the value
// portion as it appears in the source; redacted is the safe-to-render
// version composed with the shared RedactSecret helper.
type OpenAPIExampleAuthMatchLua struct {
	Scheme   string
	Raw      string
	Redacted string
}

// OpenAPIScanExampleAuthMatches walks body for `Bearer <token>` and
// `Basic <base64>` shapes that sit next to an OpenAPI example /
// default / value key, returning the matches in document order. The
// regex + nearby-context filter live in Go because gopher-lua's
// pattern library cannot express the lookbehind window; the Lua port
// owns deduplication / sorting / severity composition.
func OpenAPIScanExampleAuthMatches(body []byte) []OpenAPIExampleAuthMatchLua {
	matches := openAPIExampleHeaderRe.FindAllSubmatchIndex(body, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]OpenAPIExampleAuthMatchLua, 0, len(matches))
	for _, m := range matches {
		if !hasNearbyContext(body, m[0], m[1], openAPIExampleContextRe) {
			continue
		}
		scheme := titleAuthScheme(string(body[m[2]:m[3]]))
		raw := string(body[m[4]:m[5]])
		out = append(out, OpenAPIExampleAuthMatchLua{
			Scheme:   scheme,
			Raw:      raw,
			Redacted: redactSecret(raw),
		})
	}
	return out
}

// OpenAPISecurityFactsLua is the security-relevant subset of an
// OpenAPI / Swagger document the Lua authless-operations audit
// consumes. The bridge surfaces just these fields so the Lua port
// does not need to materialize the entire spec as a Lua table - a
// 4 MiB spec with hundreds of schemas would otherwise force the VM
// to allocate millions of nested table nodes for four fields it
// actually reads.
type OpenAPISecurityFactsLua struct {
	DeclaresSecurity bool
	GlobalRequired   bool
	Operations       []OpenAPISecurityOperationLua
}

// OpenAPISecurityOperationLua is one operation extracted from the
// spec's paths map. HasSecurity reports whether the operation
// carries a `security:` key at all (the marker the Lua side uses to
// distinguish "inherit global" from "override global"); Required
// reports whether that key, if present, demands authentication.
// Required is meaningless when HasSecurity is false.
type OpenAPISecurityOperationLua struct {
	Method      string
	Path        string
	HasSecurity bool
	Required    bool
}

// OpenAPIScanSecurityFacts parses body as an OpenAPI / Swagger JSON
// document via the narrow openAPISecurityDoc struct (so encoding/json
// allocates only the security-relevant subset) and returns the
// fields the .lua port needs to decide which operations are
// authless. Returns nil for bodies that aren't a JSON object or that
// fail to parse - mirrors the Go check's per-pass JSON gate. The
// audit policy (which ops to flag, dedupe / title / severity
// composition) stays in Lua.
func OpenAPIScanSecurityFacts(body []byte) *OpenAPISecurityFactsLua {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var doc openAPISecurityDoc
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil
	}
	out := &OpenAPISecurityFactsLua{
		DeclaresSecurity: doc.declaresSecurity(),
		GlobalRequired:   requirementIsAuthenticated(doc.Security),
	}
	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/") {
			continue
		}
		for _, mo := range item.methods() {
			entry := OpenAPISecurityOperationLua{
				Method: mo.method,
				Path:   path,
			}
			if mo.op.Security != nil {
				entry.HasSecurity = true
				entry.Required = requirementIsAuthenticated(*mo.op.Security)
			}
			out.Operations = append(out.Operations, entry)
		}
	}
	return out
}
