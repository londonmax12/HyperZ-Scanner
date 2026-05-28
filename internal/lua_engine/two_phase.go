package lua_engine

import (
	"context"
	"fmt"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// luaTwoPhase wraps a *LuaCheck whose module declares the two-phase
// shape (a `plant` function plus the catalog meta `phase = "two-phase"`).
// The scanner picks it up via type assertion to TwoPhaseCheck and
// runs Plant at the check's declared tier (TierActive by default)
// then Detect at TierDeferred against a freshly-fetched body. The
// embedded *LuaCheck continues to satisfy Check unconditionally, so
// a two-phase module is still discoverable in `hyperz checks list`
// alongside the single-phase catalog.
//
// Wrapping rather than always implementing TwoPhaseCheck on every
// *LuaCheck is deliberate: when ANY two-phase check is registered
// the scanner walks every target to TierDeferred for a re-fetch.
// Single-phase Lua checks must therefore not appear as
// TwoPhaseCheck implementations, or every scan with the default
// catalog would burn 2x the request count for no extra signal.
type luaTwoPhase struct {
	*LuaCheck
}

// Plant dispatches to `check.plant(ctx)` in the Lua module. The
// RunEnv mirrors the per-Run shape Run uses so the bridge's
// per-call helpers (ctx.client, ctx.page, ctx.sinks, ctx.stored_xss
// state) all work the same way they do in single-phase checks. A
// module without a plant function returns nil findings (no error)
// to keep the dispatch tolerant of catalog drift during edits.
func (c *luaTwoPhase) Plant(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	return c.dispatchPhaseFn(ctx, client, sc, p, "plant")
}

// Detect dispatches to `check.detect(ctx)` in the Lua module on the
// re-fetched body at TierDeferred. p carries the freshly-fetched
// response body the bridge passes through ctx.page; the module
// reads ctx.page.body and looks up canaries it planted earlier.
func (c *luaTwoPhase) Detect(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	return c.dispatchPhaseFn(ctx, client, sc, p, "detect")
}

// dispatchPhaseFn is the shared body Plant / Detect use: borrow a VM,
// look up the named function on the module table, push a per-call
// ctx userdata, PCall, marshal findings out. Mirrors Run's lifecycle
// (VM-poison guard, env install / clear) so a panicking phase-2 call
// discards the VM the same way a panicking Run does.
func (c *luaTwoPhase) dispatchPhaseFn(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page, fnName string) (findings []Finding, runErr error) {
	L, mod, err := c.borrow()
	if err != nil {
		return nil, err
	}
	keepVM := true
	defer func() {
		if r := recover(); r != nil {
			keepVM = false
			runErr = fmt.Errorf("%s: lua panic: %v", c.name, r)
		}
		c.release(L, mod, keepVM)
	}()

	fnV := mod.RawGetString(fnName)
	if fnV == lua.LNil {
		return nil, nil
	}
	if _, ok := fnV.(*lua.LFunction); !ok {
		return nil, fmt.Errorf("%s: module.%s is %s, not a function", c.name, fnName, fnV.Type())
	}

	envCtx := &RunEnv{
		Ctx:    ctx,
		Client: client,
		Scope:  sc,
		Page:   p,
		Check:  c.LuaCheck,
	}
	ctxUD := buildCtxUserdata(L, envCtx)
	L.SetContext(ctx)
	L.Push(fnV)
	L.Push(ctxUD)
	if err := L.PCall(1, 2, nil); err != nil {
		keepVM = false
		return nil, fmt.Errorf("%s: %s: %w", c.name, fnName, err)
	}
	defer L.SetTop(0)

	errV := L.Get(-1)
	findV := L.Get(-2)
	if errV != lua.LNil {
		return nil, fmt.Errorf("%s: %s: %s", c.name, fnName, LValString(errV))
	}
	if findV == lua.LNil {
		return nil, nil
	}
	tbl, ok := findV.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("%s: %s() must return a table of findings (got %s)", c.name, fnName, findV.Type())
	}
	return c.marshalFindings(tbl, envCtx)
}
