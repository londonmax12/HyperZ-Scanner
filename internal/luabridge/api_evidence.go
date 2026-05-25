package luabridge

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildEvidenceTable returns the ctx.evidence helper namespace. Both
// builders mint a *checks.Evidence and return it wrapped as a Lua
// userdata; the marshalling code on the Run path knows how to pull
// the underlying *checks.Evidence back out when a finding declares
// `evidence = ev` against the userdata.
//
// Two flavors are exposed:
//
//   ctx.evidence.build{ method, url, status, headers, body }
//     -- Mirrors checks.BuildEvidence: produces a Snippet from
//        headers and body. Use for passive checks that observe a
//        response and want the readable text snapshot.
//
//   ctx.evidence.from_exchange{ request, response, body, truncated }
//     -- Mirrors checks.RecordExchange wrapped in an Evidence:
//        captures the full request/response pair so the report
//        can render an "exact bytes" view. Use for active probes.
func buildEvidenceTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("build", L.NewFunction(evidenceBuild))
	t.RawSetString("from_exchange", L.NewFunction(evidenceFromExchange))
	return t
}

// evidenceBuild marshals ctx.evidence.build{...} into a
// *checks.Evidence. Mandatory fields are url and status; method and
// headers default to "GET" and the empty header set respectively
// when omitted. Headers may arrive as either a Lua table (name ->
// string or array of strings) or the headers userdata exposed on
// ctx.page.headers / response:headers().
func evidenceBuild(L *lua.LState) int {
	opts := L.CheckTable(1)
	method := lvalString(opts.RawGetString("method"))
	if method == "" {
		method = http.MethodGet
	}
	url := lvalString(opts.RawGetString("url"))
	status := lvalInt(opts.RawGetString("status"))
	body := lvalString(opts.RawGetString("body"))
	hdr := readHeaderArg(L, opts.RawGetString("headers"))

	ev := checks.BuildEvidence(method, url, status, hdr, body)
	L.Push(pushEvidence(L, ev))
	return 1
}

// evidenceFromExchange wraps a request / response pair into a
// *checks.Evidence whose .Exchange is populated by RecordExchange.
// Request and response arrive as userdata produced by the client
// binding; body and truncated come back as a string / bool tuple
// (typically from response:read_body_capped).
//
// The function tolerates either piece being absent so a check can
// emit evidence even when only one side is available (e.g. a
// connect failure that returned a *http.Request but no response).
func evidenceFromExchange(L *lua.LState) int {
	opts := L.CheckTable(1)

	var (
		req     *http.Request
		reqBody []byte
		reqTrun bool
		resp    *http.Response
		respBody []byte
		respTrun bool
	)
	if v, ok := opts.RawGetString("request").(*lua.LUserData); ok && v != nil {
		if r, ok := v.Value.(*requestUserData); ok {
			req = r.req
			reqBody = r.bodySnap
			reqTrun = r.bodyTrunc
		}
	}
	if v, ok := opts.RawGetString("response").(*lua.LUserData); ok && v != nil {
		if r, ok := v.Value.(*responseUserData); ok {
			resp = r.resp
			respBody = r.body
			respTrun = r.truncated
		}
	}
	// Explicit body/truncated overrides win - useful for the
	// open-redirect-style flow where Lua read the body via
	// httpclient.ReadBodyCapped and wants those exact bytes in
	// the evidence rather than whatever the response userdata
	// might hold.
	if v := opts.RawGetString("body"); v != lua.LNil {
		respBody = []byte(lvalString(v))
	}
	if v := opts.RawGetString("truncated"); v != lua.LNil {
		respTrun = lvalBool(v)
	}
	if v := opts.RawGetString("request_body"); v != lua.LNil {
		reqBody = []byte(lvalString(v))
	}
	if v := opts.RawGetString("request_truncated"); v != lua.LNil {
		reqTrun = lvalBool(v)
	}

	ex := checks.RecordExchange(req, reqBody, reqTrun, resp, respBody, respTrun)
	ev := &checks.Evidence{Exchange: ex}
	if req != nil {
		ev.Method = req.Method
		if req.URL != nil {
			ev.RequestURL = req.URL.String()
		}
	}
	if resp != nil {
		ev.Status = resp.StatusCode
	}
	// Snippet override path: a check that already knows the human-
	// readable view (e.g. "Location: https://evil.example/...") can
	// supply it directly instead of having a snippet auto-built from
	// the exchange.
	if v := opts.RawGetString("snippet"); v != lua.LNil {
		ev.Snippet = lvalString(v)
	}
	L.Push(pushEvidence(L, ev))
	return 1
}

// readHeaderArg accepts either a Lua table (name -> string | array)
// or a headers userdata and returns the equivalent net/http.Header.
// Used by evidence.build so the same field shape both Lua and Go
// authors are used to (one map of strings) translates 1:1.
func readHeaderArg(L *lua.LState, v lua.LValue) http.Header {
	if v == nil || v == lua.LNil {
		return nil
	}
	if ud, ok := v.(*lua.LUserData); ok {
		if h, ok := ud.Value.(*headersUserData); ok {
			return h.h
		}
	}
	tbl, ok := v.(*lua.LTable)
	if !ok {
		return nil
	}
	h := http.Header{}
	tbl.ForEach(func(k, val lua.LValue) {
		name := lvalString(k)
		if name == "" {
			return
		}
		switch t := val.(type) {
		case lua.LString:
			h.Add(name, string(t))
		case *lua.LTable:
			t.ForEach(func(_, vv lua.LValue) {
				h.Add(name, lvalString(vv))
			})
		default:
			h.Add(name, lvalString(val))
		}
	})
	return h
}

// evidenceUserData is the wrapper the bridge stashes a built
// *checks.Evidence inside so the marshal-findings path can recover
// the typed pointer without re-reading every field through the Lua
// table layer. Authors never see it directly - they only get back
// the userdata and pass it through as `evidence = ev`.
type evidenceUserData struct {
	ev *checks.Evidence
}

func pushEvidence(L *lua.LState, ev *checks.Evidence) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &evidenceUserData{ev: ev}
	return ud
}

// evidenceFromArg extracts a *checks.Evidence from a Lua value that
// is either the bridge's evidenceUserData or a plain table (older
// authoring shape). Returns nil when neither matches; the caller
// (finding marshal) treats nil as "no evidence" rather than an error
// since not every finding requires evidence.
func evidenceFromArg(v lua.LValue) *checks.Evidence {
	if v == nil || v == lua.LNil {
		return nil
	}
	if ud, ok := v.(*lua.LUserData); ok {
		if e, ok := ud.Value.(*evidenceUserData); ok {
			return e.ev
		}
	}
	tbl, ok := v.(*lua.LTable)
	if !ok {
		return nil
	}
	return &checks.Evidence{
		Method:     lvalString(tbl.RawGetString("method")),
		RequestURL: lvalString(tbl.RawGetString("request_url")),
		Status:     lvalInt(tbl.RawGetString("status")),
		Snippet:    lvalString(tbl.RawGetString("snippet")),
	}
}
