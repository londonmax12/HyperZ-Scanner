package lua_engine

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/target"
)

// The const-table catalog below is exposed to every Lua check as bare
// Lua globals (cms, framework, server, methods, severity, ...). They
// live in the global table rather than on ctx because the module body
// itself - `local check = { applies_to = { cms = { cms.wordpress } } }` -
// runs at module-load time, before any ctx exists. Putting the
// constants on the globals means meta-table fields (applies_to,
// patched_in, tier, level, scope, consumes) can reference them too,
// not just code inside check.run().
//
// Naming convention: lowercase Lua identifiers map to lowercase wire
// values. A Lua identifier cannot contain `.`, so `asp.net` (a
// fingerprint framework value) is keyed as `aspnet` while the string
// it expands to remains the wire form "asp.net". The string the bridge
// sees from Lua is what we feed to the matchers; the identifier shape
// only matters to the Lua author.

// constTable groups one named Lua global (cms, methods, ...) and the
// (key, value) entries that go on it. Iterating a slice of these in
// installConstGlobals keeps the install path one ranged loop instead
// of fifteen open-coded RawSet stanzas.
type constTable struct {
	name    string
	entries []constEntry
}

type constEntry struct {
	key string
	val lua.LValue
}

func constStr(s string) lua.LValue  { return lua.LString(s) }
func constNum(n float64) lua.LValue { return lua.LNumber(n) }

// buildConstGlobals returns the catalog of constant tables to install
// as Lua globals. Exposed (rather than inlined into installConstGlobals)
// so tests can iterate the catalog without running the install path.
func buildConstGlobals() []constTable {
	return []constTable{
		{name: "severity", entries: []constEntry{
			{"info", constStr(string(SeverityInfo))},
			{"low", constStr(string(SeverityLow))},
			{"medium", constStr(string(SeverityMedium))},
			{"high", constStr(string(SeverityHigh))},
			{"critical", constStr(string(SeverityCritical))},
		}},
		{name: "scopes", entries: []constEntry{
			{"host", constStr("host")},
			{"page", constStr("page")},
			{"param", constStr("param")},
		}},
		{name: "levels", entries: []constEntry{
			{"passive", constStr("passive")},
			{"default", constStr("default")},
			{"aggressive", constStr("aggressive")},
		}},
		{name: "locs", entries: []constEntry{
			{"query", constStr(string(LocQuery))},
			{"form", constStr(string(LocForm))},
			{"header", constStr(string(LocHeader))},
			{"cookie", constStr(string(LocCookie))},
			{"json", constStr(string(LocJSON))},
			{"path", constStr(string(LocPath))},
		}},
		{name: "tiers", entries: []constEntry{
			{"fingerprint", constStr("fingerprint")},
			{"passive", constStr("passive")},
			{"discovery", constStr("discovery")},
			{"active", constStr("active")},
			{"deferred", constStr("deferred")},
		}},
		// Fingerprint axis vocabularies. Values mirror the canonical
		// lowercase strings the matcher in internal/fingerprint stores
		// on Stack so spec.Matches compares string-equal after
		// case-folding. Adding an entry here is a vocabulary listing,
		// not a claim that the matcher already detects that value -
		// see internal/fingerprint/rules.go for the detection rules.
		{name: "cms", entries: []constEntry{
			{"wordpress", constStr("wordpress")},
			{"drupal", constStr("drupal")},
			{"joomla", constStr("joomla")},
			{"magento", constStr("magento")},
			{"ghost", constStr("ghost")},
		}},
		{name: "framework", entries: []constEntry{
			// `.` is not a Lua identifier char, so asp.net / asp.net-mvc
			// get keyed as aspnet / aspnet_mvc; the string values stay
			// in the canonical wire form.
			{"aspnet", constStr("asp.net")},
			{"aspnet_mvc", constStr("asp.net-mvc")},
			{"express", constStr("express")},
			{"nextjs", constStr("nextjs")},
			{"nuxt", constStr("nuxt")},
			{"react", constStr("react")},
			{"django", constStr("django")},
			{"rails", constStr("rails")},
		}},
		{name: "server", entries: []constEntry{
			{"nginx", constStr("nginx")},
			{"openresty", constStr("openresty")},
			{"apache", constStr("apache")},
			{"caddy", constStr("caddy")},
			{"litespeed", constStr("litespeed")},
			{"iis", constStr("iis")},
		}},
		{name: "language", entries: []constEntry{
			{"php", constStr("php")},
			{"dotnet", constStr("dotnet")},
			{"node", constStr("node")},
			{"java", constStr("java")},
			{"python", constStr("python")},
			{"ruby", constStr("ruby")},
			{"go", constStr("go")},
		}},
		{name: "cdn", entries: []constEntry{
			{"cloudflare", constStr("cloudflare")},
			{"akamai", constStr("akamai")},
			{"edgecast", constStr("edgecast")},
			{"cloudfront", constStr("cloudfront")},
			{"fastly", constStr("fastly")},
			{"aws", constStr("aws")},
		}},
		{name: "waf", entries: []constEntry{
			{"cloudflare", constStr("cloudflare")},
			{"sucuri", constStr("sucuri")},
			{"incapsula", constStr("incapsula")},
			{"akamai", constStr("akamai")},
			{"aws", constStr("aws")},
		}},
		// HTTP method vocabulary. Wire values are upper-case to match
		// every other check in the catalog and the Go http package's
		// MethodGet / MethodPost constants.
		{name: "methods", entries: []constEntry{
			{"get", constStr("GET")},
			{"post", constStr("POST")},
			{"put", constStr("PUT")},
			{"patch", constStr("PATCH")},
			{"delete", constStr("DELETE")},
			{"head", constStr("HEAD")},
			{"options", constStr("OPTIONS")},
		}},
		// Common Content-Type / Accept values. Keys are short labels
		// that read naturally inside a headers table - content_types.json
		// versus the bare string "application/json".
		{name: "content_types", entries: []constEntry{
			{"json", constStr("application/json")},
			{"form", constStr("application/x-www-form-urlencoded")},
			{"xml", constStr("application/xml")},
			{"text_xml", constStr("text/xml")},
			{"html", constStr("text/html")},
			{"text", constStr("text/plain")},
			{"multipart", constStr("multipart/form-data")},
		}},
		// Target / discovery kinds. Values come from target.Kind.String
		// so a typo in `consumes = { kinds.paran }` fails at module
		// load (nil indexing on the table), not silently downstream.
		{name: "kinds", entries: []constEntry{
			{"host", constStr(target.KindHost.String())},
			{"page", constStr(target.KindPage.String())},
			{"endpoint", constStr(target.KindEndpoint.String())},
			{"param", constStr(target.KindParam.String())},
		}},
		// Body-cap tiers. Replaces per-check local BODY_CAP constants;
		// each tier corresponds to the rough size class of response a
		// check expects. Passive vendor probes use `passive`; injection
		// / reflection / IDOR probes that need more body to scan use
		// `probe`; stored-XSS corpus scanning uses `corpus`.
		{name: "body_caps", entries: []constEntry{
			{"small", constNum(4 * 1024)},
			{"passive", constNum(32 * 1024)},
			{"probe", constNum(64 * 1024)},
			{"corpus", constNum(256 * 1024)},
		}},
	}
}

// installConstGlobals attaches every constant table as a Lua global
// on L. Called once per VM at bindHyperzAPI time, before any check
// module is instantiated - so the module body sees the globals
// already populated when it evaluates
// `applies_to = { cms = { cms.wordpress } }`.
func installConstGlobals(L *lua.LState) {
	for _, tbl := range buildConstGlobals() {
		t := L.NewTable()
		for _, e := range tbl.entries {
			t.RawSetString(e.key, e.val)
		}
		L.SetGlobal(tbl.name, t)
	}
}

