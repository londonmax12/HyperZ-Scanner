package luabridge

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/page"
)

// buildPageTable converts a page.Page into a Lua table the check
// reads as `ctx.page`. The conversion is shallow - body and headers
// pass through as a Lua string and a headers userdata respectively -
// because we never want to round-trip through a deep Lua copy of a
// possibly-large response body.
//
// Fields:
//
//	url     - string (always present)
//	status  - integer (0 when no fetch has happened yet)
//	headers - headers userdata, or nil if the producer hasn't fetched
//	body    - string (potentially binary; "" when no body captured)
//	forms   - array of form tables
//	fetched - bool ("a producer has attempted the GET for this URL";
//	          see page.Page docs)
//	spec_ops- array of OpenAPI/Swagger operations the spec declared
//	          for this URL (one per method)
//
// The page table is rebuilt per Run; the headers userdata it points
// at wraps the live http.Header on p so re-reading after a binding
// touches it remains coherent (we don't expose a header mutation
// API to Lua, so the live reference is purely a performance choice).
func buildPageTable(L *lua.LState, p page.Page) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("url", lua.LString(p.URL))
	t.RawSetString("status", lua.LNumber(p.Status))
	t.RawSetString("fetched", lua.LBool(p.Fetched))
	if p.Headers != nil {
		t.RawSetString("headers", pushHeaders(L, p.Headers))
	}
	if len(p.Body) > 0 {
		t.RawSetString("body", lua.LString(string(p.Body)))
	} else {
		t.RawSetString("body", lua.LString(""))
	}
	t.RawSetString("forms", buildFormsTable(L, p.Forms))
	t.RawSetString("spec_ops", buildSpecOpsTable(L, p.SpecOps))
	return t
}

// buildFormsTable mirrors page.Form into an array table of form
// tables. Inputs are converted to a deterministic shape (name,
// type, value, options) so a check author iterating `for _, f in
// ipairs(ctx.page.forms) do for _, inp in ipairs(f.inputs) do ... end`
// gets stable structure across calls.
func buildFormsTable(L *lua.LState, forms []page.Form) *lua.LTable {
	t := L.NewTable()
	for i, f := range forms {
		ft := L.NewTable()
		ft.RawSetString("method", lua.LString(f.Method))
		ft.RawSetString("action", lua.LString(f.Action))
		inputs := L.NewTable()
		for j, in := range f.Inputs {
			it := L.NewTable()
			it.RawSetString("name", lua.LString(in.Name))
			it.RawSetString("type", lua.LString(in.Type))
			it.RawSetString("value", lua.LString(in.Value))
			if len(in.Options) > 0 {
				opts := L.NewTable()
				for k, opt := range in.Options {
					opts.RawSetInt(k+1, lua.LString(opt))
				}
				it.RawSetString("options", opts)
			}
			inputs.RawSetInt(j+1, it)
		}
		ft.RawSetString("inputs", inputs)
		t.RawSetInt(i+1, ft)
	}
	return t
}

// buildSpecOpsTable mirrors page.SpecOp into an array table. Params
// are flattened into a sub-array of {in, name, value} tables so
// input-fuzzing checks can iterate over them the same way they
// iterate forms - one Lua control-flow shape covers both surfaces.
func buildSpecOpsTable(L *lua.LState, ops []page.SpecOp) *lua.LTable {
	t := L.NewTable()
	for i, op := range ops {
		ot := L.NewTable()
		ot.RawSetString("method", lua.LString(op.Method))
		ot.RawSetString("url", lua.LString(op.URL))
		ot.RawSetString("tpl", lua.LString(op.Tpl))
		params := L.NewTable()
		for j, pp := range op.Params {
			pt := L.NewTable()
			pt.RawSetString("in", lua.LString(pp.In))
			pt.RawSetString("name", lua.LString(pp.Name))
			pt.RawSetString("value", lua.LString(pp.Value))
			params.RawSetInt(j+1, pt)
		}
		ot.RawSetString("params", params)
		t.RawSetInt(i+1, ot)
	}
	return t
}
