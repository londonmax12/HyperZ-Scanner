package lua_engine

import (
	"fmt"
	"strings"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/target"
)

// ctxDiscover implements ctx.discover(table) for Lua-authored checks.
// The Lua surface:
//
//	ctx.discover{
//	  kind = "page",                       -- required: host|page|endpoint|param
//	  url  = "https://...",                 -- required for every kind
//	  method = "POST",                      -- endpoint kind
//	  content_type = "application/json",    -- endpoint kind
//	  param = "redirect_url",               -- param kind
//	  location = "query",                   -- param kind (query|body|header|cookie|path)
//	  note = "...",                         -- opaque payload the dispatcher does not interpret
//	}
//
// The scanner-side core.Discoverer is responsible for tagging Origin
// with the emitting check's name and threading the target through the
// worklist's dedupe / scope / host-budget / self-loop filter. Lua
// authors emit liberally; the dispatcher decides what queues.
//
// Calling outside a check run raises a Lua error so an authoring
// mistake (calling ctx.discover at module-load time) fails fast.
// Calling under a ctx that has no Discoverer attached is a no-op,
// matching the permissive contract that ctx:report and ctx.oob use
// for optional engine dependencies.
func ctxDiscover(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx.discover called outside a check run")
	}
	tbl, ok := L.Get(2).(*lua.LTable)
	if !ok {
		L.ArgError(1, "ctx.discover expects a table argument")
	}

	kindStr := lvalString(tbl.RawGetString("kind"))
	if kindStr == "" {
		L.ArgError(1, "discover table missing required field `kind` (host|page|endpoint|param)")
	}
	kind, err := parseTargetKind(kindStr)
	if err != nil {
		L.ArgError(1, err.Error())
	}

	url := lvalString(tbl.RawGetString("url"))
	if url == "" {
		L.ArgError(1, "discover table missing required field `url`")
	}

	method := lvalString(tbl.RawGetString("method"))
	if method != "" {
		method = strings.ToUpper(method)
	}

	disc := target.Target{
		Kind:          kind,
		URL:           url,
		Method:        method,
		ContentType:   lvalString(tbl.RawGetString("content_type")),
		Param:         lvalString(tbl.RawGetString("param")),
		ParamLocation: strings.ToLower(lvalString(tbl.RawGetString("location"))),
		Note:          lvalString(tbl.RawGetString("note")),
	}
	core.Discover(env.ctx, disc)
	return 0
}

// parseTargetKind maps the Lua-side kind label onto a target.Kind.
// Unknown labels produce an error; this is stricter than the Lua
// idiom of "anything goes" because a typo would silently drop the
// emission rather than surface as a hit on the dispatcher's
// canonical-key map.
func parseTargetKind(s string) (target.Kind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "host":
		return target.KindHost, nil
	case "page":
		return target.KindPage, nil
	case "endpoint":
		return target.KindEndpoint, nil
	case "param":
		return target.KindParam, nil
	}
	return 0, fmt.Errorf("invalid discover kind %q (want host, page, endpoint, or param)", s)
}
