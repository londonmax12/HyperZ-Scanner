package luabridge

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// requestUserData wraps an *http.Request the bridge built (typically
// from Sink.MutateRequest) so a Lua check can read its method/URL
// and pass it back to the client. The wrapper keeps the request
// pristine - Lua-side accessors only read fields - because the
// request goes back into the Go transport stack untouched for
// execution.
type requestUserData struct {
	req     *http.Request
	bodySnap []byte
	bodyTrunc bool
}

// pushRequest exposes req as a userdata with a methods metatable. The
// optional bodySnap is the captured outgoing-body snapshot used for
// evidence (see httpclient.SnapshotRequestBody and RecordExchange);
// pass nil/false when the request has no body or the caller did not
// capture one.
func pushRequest(L *lua.LState, req *http.Request, bodySnap []byte, truncated bool) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &requestUserData{req: req, bodySnap: bodySnap, bodyTrunc: truncated}
	ud.Metatable = ensureRequestMT(L)
	return ud
}

func ensureRequestMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtRequest).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("url", L.NewFunction(requestURL))
	methods.RawSetString("method", L.NewFunction(requestMethod))
	methods.RawSetString("headers", L.NewFunction(requestHeaders))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtRequest, mt)
	return mt
}

func requestFromArg(L *lua.LState, pos int) *requestUserData {
	v := L.CheckUserData(pos).Value
	r, ok := v.(*requestUserData)
	if !ok {
		L.ArgError(pos, "expected request userdata")
	}
	return r
}

func requestURL(L *lua.LState) int {
	r := requestFromArg(L, 1)
	if r.req.URL == nil {
		L.Push(lua.LString(""))
	} else {
		L.Push(lua.LString(r.req.URL.String()))
	}
	return 1
}

func requestMethod(L *lua.LState) int {
	r := requestFromArg(L, 1)
	L.Push(lua.LString(r.req.Method))
	return 1
}

func requestHeaders(L *lua.LState) int {
	r := requestFromArg(L, 1)
	L.Push(pushHeaders(L, r.req.Header))
	return 1
}

// responseUserData wraps a *http.Response plus its already-read body.
// We capture the body inside the wrapper rather than handing the
// http.Response.Body to Lua because Lua-side body access is going to
// be repeated (read status, read header, read body) and we want one
// http.Body.Close call at the binding boundary, not per access.
//
// truncated reports whether the body read hit the cap; bindings that
// surface body to Lua (response:body, evidence builders) pass it
// through so the report can flag a cut-off snippet.
type responseUserData struct {
	resp      *http.Response
	body      []byte
	truncated bool
	closed    bool
}

func pushResponse(L *lua.LState, resp *http.Response, body []byte, truncated bool) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &responseUserData{resp: resp, body: body, truncated: truncated}
	ud.Metatable = ensureResponseMT(L)
	return ud
}

func ensureResponseMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtResp).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("status", L.NewFunction(responseStatus))
	methods.RawSetString("headers", L.NewFunction(responseHeaders))
	methods.RawSetString("body", L.NewFunction(responseBody))
	methods.RawSetString("truncated", L.NewFunction(responseTruncated))
	methods.RawSetString("read_body_capped", L.NewFunction(responseReadBodyCapped))
	methods.RawSetString("close", L.NewFunction(responseClose))
	methods.RawSetString("request_url", L.NewFunction(responseRequestURL))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtResp, mt)
	return mt
}

func responseFromArg(L *lua.LState, pos int) *responseUserData {
	v := L.CheckUserData(pos).Value
	r, ok := v.(*responseUserData)
	if !ok {
		L.ArgError(pos, "expected response userdata")
	}
	return r
}

func responseStatus(L *lua.LState) int {
	r := responseFromArg(L, 1)
	L.Push(lua.LNumber(r.resp.StatusCode))
	return 1
}

func responseHeaders(L *lua.LState) int {
	r := responseFromArg(L, 1)
	L.Push(pushHeaders(L, r.resp.Header))
	return 1
}

// responseBody returns the already-buffered body. When the response
// hasn't had its body read yet (do_no_follow returns the response
// before reading), Lua-side authors typically call read_body_capped
// first; calling :body() on an unread response returns "".
func responseBody(L *lua.LState) int {
	r := responseFromArg(L, 1)
	L.Push(lua.LString(string(r.body)))
	return 1
}

func responseTruncated(L *lua.LState) int {
	r := responseFromArg(L, 1)
	L.Push(lua.LBool(r.truncated))
	return 1
}

// responseReadBodyCapped buffers up to max bytes from the response
// body and stashes the result on the userdata so subsequent :body()
// calls return the same bytes. Returns (body_string, truncated_bool)
// or (nil, nil, err) on error - the err slot is third because Lua's
// multi-return naturally aligns with `local body, trunc, err =
// resp:read_body_capped(N)`.
func responseReadBodyCapped(L *lua.LState) int {
	r := responseFromArg(L, 1)
	max := L.CheckInt64(2)
	if r.closed {
		L.Push(lua.LString(string(r.body)))
		L.Push(lua.LBool(r.truncated))
		return 2
	}
	body, truncated, err := httpclient.ReadBodyCapped(r.resp, max)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 3
	}
	r.body = body
	r.truncated = truncated
	r.closed = true
	L.Push(lua.LString(string(body)))
	L.Push(lua.LBool(truncated))
	return 2
}

// responseClose closes the underlying http.Response.Body. The bridge
// calls this automatically when a Run's release path tears down per-
// call resources; exposing it to Lua is for the rare check that
// wants to short-circuit closure after extracting only the status
// (e.g. a probe that ignores body on success).
// responseRequestURL returns the URL of the request that produced
// the response, AFTER redirects. For a chain that hopped from
// https://a/script.js to a CDN at https://b/script.js, the value is
// the latter. Source-map-style probes use this to re-check scope
// after a follow-redirect probe so a chain that lands off-scope is
// treated as a non-finding rather than a confirmed leak.
func responseRequestURL(L *lua.LState) int {
	r := responseFromArg(L, 1)
	if r.resp == nil || r.resp.Request == nil || r.resp.Request.URL == nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(r.resp.Request.URL.String()))
	return 1
}

func responseClose(L *lua.LState) int {
	r := responseFromArg(L, 1)
	if !r.closed && r.resp != nil && r.resp.Body != nil {
		_ = r.resp.Body.Close()
	}
	r.closed = true
	return 0
}

// clientUserData wraps an *httpclient.Client. The userdata exposes a
// narrow subset of the Go client (Get, Do, DoNoFollow) - everything a
// check needs to issue probes - without exposing the configuration
// surface (rate limiter, jar) that the engine, not the rule author,
// is supposed to own.
type clientUserData struct {
	c *httpclient.Client
}

func pushClient(L *lua.LState, c *httpclient.Client) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &clientUserData{c: c}
	ud.Metatable = ensureClientMT(L)
	return ud
}

func ensureClientMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtClient).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("get", L.NewFunction(clientGet))
	methods.RawSetString("do", L.NewFunction(clientDo))
	methods.RawSetString("do_no_follow", L.NewFunction(clientDoNoFollow))
	methods.RawSetString("do_timed", L.NewFunction(clientDoTimed))
	methods.RawSetString("new_request", L.NewFunction(clientNewRequest))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtClient, mt)
	return mt
}

func clientFromArg(L *lua.LState, pos int) *clientUserData {
	v := L.CheckUserData(pos).Value
	c, ok := v.(*clientUserData)
	if !ok {
		L.ArgError(pos, "expected client userdata")
	}
	return c
}

// clientGet implements client:get(url). Returns a response userdata
// (unread body) or (nil, err). The active context is taken from the
// running env so the request honors the per-check deadline and the
// scanner's cancel signal automatically.
func clientGet(L *lua.LState) int {
	c := clientFromArg(L, 1)
	rawurl := requireString(L, 2)
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("client:get called outside a check run")
	}
	resp, err := c.c.Get(env.ctx, rawurl)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(pushResponse(L, resp, nil, false))
	return 1
}

func clientDo(L *lua.LState) int       { return clientDispatch(L, false) }
func clientDoNoFollow(L *lua.LState) int { return clientDispatch(L, true) }

// clientDoTimed dispatches the request and returns (response_userdata,
// latency_seconds) on success, or (nil, nil, err) on transport failure.
// Latency is measured around c.Do so it includes connection setup, TLS,
// and any internal retries - i.e. what an attacker would observe. The
// per-check timing oracles (cmd-injection, sqli-time) need this to
// compare against baseline + sleep margins; gopher-lua has no native
// monotonic clock that would let a Lua-authored check measure latency
// itself with the same fidelity.
func clientDoTimed(L *lua.LState) int {
	c := clientFromArg(L, 1)
	r := requestFromArg(L, 2)
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("client:do_timed called outside a check run")
	}
	start := time.Now()
	resp, err := c.c.Do(env.ctx, r.req)
	latency := time.Since(start)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 3
	}
	L.Push(pushResponse(L, resp, nil, false))
	L.Push(lua.LNumber(latency.Seconds()))
	return 2
}

// clientDispatch is the shared implementation behind client:do and
// client:do_no_follow. The redirect-following choice is the only
// difference; pulling them apart keeps the Lua method names tied to
// the underlying httpclient.Client API while sharing the request
// unwrap / response wrap path.
func clientDispatch(L *lua.LState, noFollow bool) int {
	c := clientFromArg(L, 1)
	r := requestFromArg(L, 2)
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("client:do called outside a check run")
	}
	var (
		resp *http.Response
		err  error
	)
	if noFollow {
		resp, err = c.c.DoNoFollow(env.ctx, r.req)
	} else {
		resp, err = c.c.Do(env.ctx, r.req)
	}
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(pushResponse(L, resp, nil, false))
	return 1
}

// clientNewRequest builds an http.Request from a Lua table. Used by
// checks that want full control over the request shape rather than
// going through sink:mutate_request. Argument table fields:
//
//	method - string ("GET" default)
//	url    - string (required)
//	headers - optional table of name -> value (single string) or
//	          name -> array of strings (repeated header)
//	body   - optional string
//
// Returns (request_userdata) or (nil, err).
func clientNewRequest(L *lua.LState) int {
	_ = clientFromArg(L, 1)
	opts := L.CheckTable(2)
	method := strings.ToUpper(lvalString(opts.RawGetString("method")))
	if method == "" {
		method = http.MethodGet
	}
	rawurl := lvalString(opts.RawGetString("url"))
	if rawurl == "" {
		L.Push(lua.LNil)
		L.Push(lua.LString("client:new_request: missing url"))
		return 2
	}
	if _, err := url.Parse(rawurl); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	bodyStr := lvalString(opts.RawGetString("body"))
	var bodyReader *strings.Reader
	if bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}
	env := currentEnv(L)
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(env.ctx, method, rawurl, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(env.ctx, method, rawurl, nil)
	}
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	if hv, ok := opts.RawGetString("headers").(*lua.LTable); ok {
		hv.ForEach(func(k, v lua.LValue) {
			name := lvalString(k)
			if name == "" {
				return
			}
			switch val := v.(type) {
			case lua.LString:
				req.Header.Set(name, string(val))
			case *lua.LTable:
				val.ForEach(func(_, vv lua.LValue) {
					req.Header.Add(name, lvalString(vv))
				})
			default:
				req.Header.Set(name, lvalString(v))
			}
		})
	}
	// `host` override sets req.Host (the value Go's transport sends as
	// the Host: header on the wire). Necessary for host-header-injection
	// probes: a bare Header.Set("Host", ...) is stripped by net/http
	// because the transport reads from req.Host, not req.Header.
	if hv := opts.RawGetString("host"); hv != lua.LNil {
		if hostStr := lvalString(hv); hostStr != "" {
			req.Host = hostStr
		}
	}
	var snap []byte
	var trunc bool
	if bodyStr != "" {
		snap = []byte(bodyStr)
	}
	L.Push(pushRequest(L, req, snap, trunc))
	return 1
}
