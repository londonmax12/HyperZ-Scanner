package lua_engine

import (
	"net/http"
	"sort"

	lua "github.com/yuin/gopher-lua"
)

// buildSinksTable returns the ctx.sinks helper namespace. The single
// entry point ctx.sinks.for_page reproduces the surface every input-
// fuzzing check needs: the deduped, sorted Sink set the engine
// already mines from page query / forms / spec ops, optionally with
// a canonical-parameter sweep folded in (the gating open-redirect
// does to avoid 14 probes per page on URLs that don't look
// redirect-related).
//
// Sinks come back as userdata wrapping *Sink so Lua-side
// authors can read method / url / loc / name / value as fields and
// call :mutate_request(payload) without ever building an HTTP
// request by hand. The MutateRequest closure runs in Go with the
// active env's context attached, so per-check deadlines and cancel
// signals continue to apply transparently.
func buildSinksTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("for_page", L.NewFunction(sinksForPage))
	t.RawSetString("for_headers", L.NewFunction(sinksForHeaders))
	return t
}

// sinksForPage implements ctx.sinks.for_page(opts?).
//
// opts.sweep_params - optional array of param names to fold in as
// synthetic LocQuery sinks on the page URL. Deduped against the
// real surface so a sweep name that already exists as a query / form
// input does not produce a duplicate probe.
//
// Output is sorted with the same comparator SinksFor uses so
// the Lua-authored probe order matches the Go check's: stable across
// runs and across rule changes that only touch payloads.
func sinksForPage(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.sinks.for_page called outside a check run")
	}
	base := SinksFor(env.Page)

	type key struct {
		method string
		url    string
		loc    Loc
		name   string
	}
	seen := make(map[key]struct{}, len(base))
	out := make([]Sink, 0, len(base))
	for _, s := range base {
		k := key{s.Method, s.URL, s.Loc, s.Name}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}

	if t, ok := L.Get(1).(*lua.LTable); ok {
		for _, name := range stringList(t, "sweep_params") {
			if name == "" {
				continue
			}
			s := Sink{
				Method: http.MethodGet,
				URL:    env.Page.URL,
				Loc:    LocQuery,
				Name:   name,
			}
			k := key{s.Method, s.URL, s.Loc, s.Name}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, s)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		if out[i].Loc != out[j].Loc {
			return out[i].Loc < out[j].Loc
		}
		return out[i].Name < out[j].Name
	})

	arr := L.NewTable()
	for i := range out {
		arr.RawSetInt(i+1, PushSink(L, &out[i]))
	}
	L.Push(arr)
	return 1
}

// sinksForHeaders implements ctx.sinks.for_headers(page_url, {names}).
//
// Builds one LocHeader Sink per name against page_url, returned as
// Sink userdata so callers can use the same :mutate_request /
// field-read surface they get from for_page. The Lua check supplies
// the header list (e.g. SSTI / cmd-injection aggressive-mode header
// fan-out) so the bridge stays generic instead of baking in any
// single check's header set.
func sinksForHeaders(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.sinks.for_headers called outside a check run")
	}
	pageURL := RequireString(L, 1)
	names := L.CheckTable(2)

	n := names.Len()
	out := make([]Sink, 0, n)
	for i := 1; i <= n; i++ {
		name := LValString(names.RawGetInt(i))
		if name == "" {
			continue
		}
		out = append(out, Sink{
			Method: http.MethodGet,
			URL:    pageURL,
			Loc:    LocHeader,
			Name:   name,
		})
	}

	arr := L.NewTable()
	for i := range out {
		arr.RawSetInt(i+1, PushSink(L, &out[i]))
	}
	L.Push(arr)
	return 1
}

// sinkUserData wraps a *Sink. Pointer wrap rather than value
// wrap so a future Lua-callable mutator (set_value, set_name) can
// modify the sink without surprising other references; right now
// the Lua surface is read-only so the choice is moot, but it keeps
// the door open without a userdata shape change later.
type sinkUserData struct {
	s *Sink
}

func PushSink(L *lua.LState, s *Sink) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &sinkUserData{s: s}
	ud.Metatable = ensureSinkMT(L)
	return ud
}

// UnwrapSink returns the *Sink riding inside a Lua userdata value the
// bridge pushed via PushSink. Exported so per-family subpackages can
// reach the underlying Sink without re-declaring the wrapper type.
// Returns (nil, false) when v is not a sink userdata.
func UnwrapSink(v lua.LValue) (*Sink, bool) {
	ud, ok := v.(*lua.LUserData)
	if !ok {
		return nil, false
	}
	wrapper, ok := ud.Value.(*sinkUserData)
	if !ok {
		return nil, false
	}
	return wrapper.s, true
}

// ensureSinkMT builds the per-VM sink metatable. __index is a
// function rather than a methods table because we want both field
// reads (sink.url, sink.method, ...) AND method calls (sink:mutate_request)
// off the same value; a methods table can only do the second.
func ensureSinkMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtSink).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	mt.RawSetString("__index", L.NewFunction(sinkIndex))
	L.G.Registry.RawSetString(mtSink, mt)
	return mt
}

// sinkIndex dispatches sink[key] for both field reads and method
// references. Fields are returned as Lua strings; methods are
// returned as Lua functions, which Lua then invokes via the colon
// syntax (`sink:mutate_request(...)`).
//
// Unknown keys return nil. A typo in a field name (sink.nme rather
// than sink.name) fails at the use site, exactly the way a typo on
// a regular Lua table would; we deliberately do not raise an error
// here so optional-field idioms (`if sink.value ~= "" then`) stay
// natural.
func sinkIndex(L *lua.LState) int {
	v := L.CheckUserData(1).Value
	wrapper, ok := v.(*sinkUserData)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	s := wrapper.s
	key := L.CheckString(2)
	switch key {
	case "method":
		L.Push(lua.LString(s.Method))
	case "url":
		L.Push(lua.LString(s.URL))
	case "loc":
		L.Push(lua.LString(s.Loc))
	case "name":
		L.Push(lua.LString(s.Name))
	case "value":
		L.Push(lua.LString(s.Value))
	case "mutate_request":
		L.Push(L.NewFunction(sinkMutateRequest))
	default:
		L.Push(lua.LNil)
	}
	return 1
}

// sinkMutateRequest implements sink:mutate_request(payload).
// Returns a request userdata or (nil, err). The request is built
// with the active env's context attached so an in-flight probe
// honors check budgets and scanner cancel signals.
func sinkMutateRequest(L *lua.LState) int {
	v := L.CheckUserData(1).Value
	wrapper, ok := v.(*sinkUserData)
	if !ok {
		L.ArgError(1, "expected sink userdata")
	}
	payload := RequireString(L, 2)
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("sink:mutate_request called outside a check run")
	}
	req, err := wrapper.s.MutateRequest(env.Ctx, payload)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(PushRequest(L, req, nil, false))
	return 1
}

func init() {
	RegisterHelperTable("sinks", buildSinksTable)
}
