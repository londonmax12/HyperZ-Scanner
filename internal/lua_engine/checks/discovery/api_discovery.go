package discovery

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildDiscoveryTable returns the ctx.discovery helper namespace. The
// surface covers both the content-discovery wordlist sweep and the
// secrets-in-body / source-map-exposure family helpers that used to
// live on ctx.body. Everything in this namespace is a passive body /
// path scanner the discovery checks share, so a single ctx.discovery
// surface keeps them grouped while still being per-family.
//
// Content-discovery entries:
//
//	ctx.discovery.entries(catalogue, aggressive_bool, hostname)
//	  Returns the named wordlist for hostname filtered by level + the
//	  active scan's fingerprint.Stack. Host-named backup synthetics
//	  (when the catalogue defines them) are appended in the order the
//	  Go check produces. catalogue picks the registered wordlist
//	  ("common" for content-discovery; future siblings can register
//	  their own under a different name).
//
//	ctx.discovery.follow_ups(catalogue, hostname, hits_set, probed_set)
//	  Returns the second-wave entries to probe given the set of paths
//	  whose first-wave probes fired (hits_set) and the set already
//	  probed (probed_set). Both sets are flat tables keyed by path
//	  (any non-nil value means "present"). catalogue selects which
//	  registered follow-up rule set to evaluate, mirroring entries().
//
//	ctx.discovery.body_hash_prefix(body) -> string
//	  16-hex-char SHA1 prefix of body. Used by the Lua baseline path
//	  to fingerprint soft-404 bodies for later comparison.
//
//	ctx.discovery.content_type_family(ct) -> string
//	  "text/html;charset=..." -> "text/html". Used by the baseline
//	  match path so charset-jitter doesn't break the soft-404 compare.
//
//	ctx.discovery.content_type_family_allowed(ct, allowed_array) -> bool
//	  Mirrors contentTypeFamilyAllowed: empty allow list = no
//	  constraint; empty CT = permissive; otherwise must match one of
//	  the entries.
//
//	ctx.discovery.length_close_to(a, b) -> bool
//	  Absolute floor (64 bytes) + relative slack (5%). Used to
//	  collapse a soft-404 body whose length jitters per-request.
//
//	ctx.discovery.canary_path() -> string
//	  Fresh "/<canary>-<canary>.bad" path the .lua baseline probes.
//
//	ctx.discovery.baseline_probes() -> int (=2)
//	  How many canary probes the baseline should issue per host.
//
//	ctx.discovery.body_cap() -> int (=16 KiB)
//	  The per-probe body-read cap.
//
// Secrets-in-body entries:
//
//	ctx.discovery.find_secrets(body)
//	  -> array of { id, label, severity, raw, redacted, count }
//
//	ctx.discovery.redact_secret(raw)
//	  -> string. Identical output to the Go check's redactSecret.
//
// Source-map-exposure entries:
//
//	ctx.discovery.source_map_kind(content_type)
//	  -> (kind_string, ok_bool) -> ("js"|"css"|"", false|true).
//
//	ctx.discovery.find_source_map_ref(headers, body, kind)
//	  -> string (the sourceMappingURL value the response advertises).
//
//	ctx.discovery.looks_like_source_map(body)
//	  -> bool. Anchors on the "version" + "sources"/"mappings" triple.
//
// Per-host once-fire is provided by ctx.host.claim_once in api_host.go;
// content-discovery uses it the same way any host-scoped check does.
func buildDiscoveryTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("entries", L.NewFunction(discoveryEntries))
	t.RawSetString("follow_ups", L.NewFunction(discoveryFollowUps))
	t.RawSetString("body_hash_prefix", L.NewFunction(discoveryBodyHashPrefix))
	t.RawSetString("content_type_family", L.NewFunction(discoveryContentTypeFamily))
	t.RawSetString("content_type_family_allowed", L.NewFunction(discoveryContentTypeFamilyAllowed))
	t.RawSetString("length_close_to", L.NewFunction(discoveryLengthCloseTo))
	t.RawSetString("canary_path", L.NewFunction(discoveryCanaryPath))
	t.RawSetString("baseline_probes", L.NewFunction(discoveryBaselineProbes))
	t.RawSetString("body_cap", L.NewFunction(discoveryBodyCap))
	t.RawSetString("find_secrets", L.NewFunction(discoveryFindSecrets))
	t.RawSetString("redact_secret", L.NewFunction(discoveryRedactSecret))
	t.RawSetString("is_scannable_ct", L.NewFunction(discoveryIsScannableCT))
	t.RawSetString("source_map_kind", L.NewFunction(discoverySourceMapKind))
	t.RawSetString("find_source_map_ref", L.NewFunction(discoveryFindSourceMapRef))
	t.RawSetString("looks_like_source_map", L.NewFunction(discoveryLooksLikeSourceMap))
	return t
}

// readStringList accepts a Lua string, an array table of strings, or
// nil, and returns the equivalent []string. Local copy of the same
// helper the root-level bridge keeps; lives here so the discovery
// helpers do not reach into the root for what is otherwise a one-
// screen utility.
func readStringList(v lua.LValue) []string {
	if v == nil || v == lua.LNil {
		return nil
	}
	if s, ok := v.(lua.LString); ok {
		return []string{string(s)}
	}
	if tbl, ok := v.(*lua.LTable); ok {
		n := tbl.Len()
		out := make([]string, 0, n)
		for i := 1; i <= n; i++ {
			out = append(out, lua_engine.LValString(tbl.RawGetInt(i)))
		}
		return out
	}
	return nil
}

// lvalBool coerces a Lua value into a bool using the gopher-lua truth
// table (LFalse and LNil are false; everything else is truthy). Used
// by the optional aggressive-flag slot on the entries helper.
func lvalBool(v lua.LValue) bool {
	if v == nil || v == lua.LNil {
		return false
	}
	if b, ok := v.(lua.LBool); ok {
		return bool(b)
	}
	return true
}

// discoveryEntries reads catalogue + aggressive + hostname from Lua
// and returns the filtered + host-augmented entry list as a Lua array.
// The fingerprint.Stack used for stack-restriction filtering comes
// from the active env's context (set by the scanner via WithStack).
func discoveryEntries(L *lua.LState) int {
	env := lua_engine.CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.discovery.entries called outside a check run")
	}
	catalogue := lua_engine.RequireString(L, 1)
	aggressive := lvalBool(L.Get(2))
	hostname := lua_engine.OptString(L, 3, "")
	stack := lua_engine.StackFrom(env.Ctx)
	out := L.NewTable()
	for i, e := range ContentDiscoveryEntriesLua(catalogue, aggressive, hostname, stack) {
		out.RawSetInt(i+1, pushDiscoveryEntry(L, e))
	}
	L.Push(out)
	return 1
}

// discoveryFollowUps walks the configured groups for the named
// catalogue and returns every follow-up entry whose trigger appears
// in hits and whose path is not in probed and whose stack constraint
// matches.
func discoveryFollowUps(L *lua.LState) int {
	env := lua_engine.CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.discovery.follow_ups called outside a check run")
	}
	catalogue := lua_engine.RequireString(L, 1)
	_ = lua_engine.OptString(L, 2, "")
	hits := readPathSet(L.Get(3))
	probed := readPathSet(L.Get(4))
	stack := lua_engine.StackFrom(env.Ctx)
	out := L.NewTable()
	for i, e := range ContentDiscoveryFollowUpsLua(catalogue, hits, probed, stack) {
		out.RawSetInt(i+1, pushDiscoveryEntry(L, e))
	}
	L.Push(out)
	return 1
}

// readPathSet accepts a Lua table whose keys are paths (values are
// any non-nil truthy values) and returns it as a Go set. Used by
// follow_ups to consume the .lua-side hits and probed maps without
// the caller having to convert them to arrays first.
func readPathSet(v lua.LValue) map[string]struct{} {
	out := map[string]struct{}{}
	tbl, ok := v.(*lua.LTable)
	if !ok {
		return out
	}
	tbl.ForEach(func(k, val lua.LValue) {
		if val == lua.LNil || val == lua.LFalse {
			return
		}
		if s, ok := k.(lua.LString); ok && string(s) != "" {
			out[string(s)] = struct{}{}
		}
	})
	return out
}

// pushDiscoveryEntry converts one Go ContentDiscoveryEntryLua into the
// shape the .lua port iterates. All scalar fields ride as strings; the
// optional expected_content_types is an array (empty when the entry
// imposes no CT constraint).
func pushDiscoveryEntry(L *lua.LState, e ContentDiscoveryEntryLua) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("path", lua.LString(e.Path))
	t.RawSetString("severity", lua.LString(e.Severity))
	t.RawSetString("title", lua.LString(e.Title))
	t.RawSetString("detail", lua.LString(e.Detail))
	t.RawSetString("cwe", lua.LString(e.CWE))
	t.RawSetString("owasp", lua.LString(e.OWASP))
	t.RawSetString("remediation", lua.LString(e.Remediation))
	t.RawSetString("marker", lua.LString(e.Marker))
	t.RawSetString("expected_content_types", lua_engine.PushStringList(L, e.ExpectedContentTypes))
	t.RawSetString("emit", lua.LBool(e.Emit))
	return t
}

func discoveryBodyHashPrefix(L *lua.LState) int {
	L.Push(lua.LString(ContentDiscoveryBodyHashPrefixLua([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func discoveryContentTypeFamily(L *lua.LState) int {
	L.Push(lua.LString(ContentDiscoveryContentTypeFamilyLua(lua_engine.RequireString(L, 1))))
	return 1
}

func discoveryContentTypeFamilyAllowed(L *lua.LState) int {
	ct := lua_engine.OptString(L, 1, "")
	allowed := readStringList(L.Get(2))
	L.Push(lua.LBool(ContentDiscoveryContentTypeFamilyAllowedLua(ct, allowed)))
	return 1
}

func discoveryLengthCloseTo(L *lua.LState) int {
	a := L.CheckInt(1)
	b := L.CheckInt(2)
	L.Push(lua.LBool(ContentDiscoveryLengthCloseToLua(a, b)))
	return 1
}

func discoveryCanaryPath(L *lua.LState) int {
	L.Push(lua.LString(ContentDiscoveryCanaryPathLua()))
	return 1
}

func discoveryBaselineProbes(L *lua.LState) int {
	L.Push(lua.LNumber(ContentDiscoveryBaselineProbes()))
	return 1
}

func discoveryBodyCap(L *lua.LState) int {
	L.Push(lua.LNumber(ContentDiscoveryBodyCap()))
	return 1
}

// discoveryFindSecrets runs the secrets-in-body scanner and returns
// the already-sorted hit list. The pre-redacted value is stamped on
// each entry so the Lua port does not have to call redact_secret again.
func discoveryFindSecrets(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	hits := ScanSecretsInBody([]byte(body))
	out := L.NewTable()
	for i, h := range hits {
		entry := L.NewTable()
		entry.RawSetString("id", lua.LString(h.ID))
		entry.RawSetString("label", lua.LString(h.Label))
		entry.RawSetString("severity", lua.LString(string(h.Severity)))
		entry.RawSetString("raw", lua.LString(h.Raw))
		entry.RawSetString("redacted", lua.LString(lua_engine.RedactSecret(h.Raw)))
		entry.RawSetString("count", lua.LNumber(h.Count))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func discoveryRedactSecret(L *lua.LState) int {
	L.Push(lua.LString(lua_engine.RedactSecret(lua_engine.RequireString(L, 1))))
	return 1
}

func discoveryIsScannableCT(L *lua.LState) int {
	L.Push(lua.LBool(IsScannableContentType(lua_engine.RequireString(L, 1))))
	return 1
}

func discoverySourceMapKind(L *lua.LState) int {
	kind, ok := SourceMapKind(lua_engine.RequireString(L, 1))
	L.Push(lua.LString(kind))
	L.Push(lua.LBool(ok))
	return 2
}

// discoveryFindSourceMapRef accepts a headers userdata + body + kind
// and returns the source-map reference the response advertises. The
// header / body precedence rule lives in Go - this is a thin
// forwarder, not a re-implementation.
func discoveryFindSourceMapRef(L *lua.LState) int {
	var h http.Header
	if hdrs, ok := lua_engine.UnwrapHeaders(L.Get(1)); ok {
		h = hdrs
	}
	body := lua_engine.RequireString(L, 2)
	kind := lua_engine.RequireString(L, 3)
	L.Push(lua.LString(FindSourceMapReference(h, []byte(body), kind)))
	return 1
}

func discoveryLooksLikeSourceMap(L *lua.LState) int {
	L.Push(lua.LBool(LooksLikeSourceMap([]byte(lua_engine.RequireString(L, 1)))))
	return 1
}

func init() {
	lua_engine.RegisterHelperTable("discovery", buildDiscoveryTable)
}
