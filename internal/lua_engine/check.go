package lua_engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"strings"

	lua "github.com/yuin/gopher-lua"
	luaparse "github.com/yuin/gopher-lua/parse"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// LuaCheck adapts a compiled Lua module to the Check interface.
// One LuaCheck is shared across all goroutines that scan with it; the
// inner sync.Pool hands each goroutine its own *lua.LState because
// gopher-lua VMs are not goroutine-safe.
//
// The check's metadata (name, level, scope, cwe, ...) is read off the
// returned module table once at Load time and frozen on the struct -
// individual findings inherit those defaults unless they override them
// in their own table. Per-Run, only `check.run(ctx)` is invoked, with
// `ctx` carrying the page artifact and a façade over the engine's
// helpers (HTTP client, scope, OOB server, payload library, ...).
//
// isTwoPhase reports whether the module declared `phase = "two-phase"`
// (and accordingly carries a `plant` function). Set at Load time; the
// loader wraps two-phase checks in luaTwoPhase before handing them to
// the scanner so type assertion to TwoPhaseCheck only succeeds
// for modules that actually opted in.
type LuaCheck struct {
	name         string
	level        Level
	defaultScope Scope
	cwe          string
	owasp        string
	remediation  string
	budget       time.Duration
	isTwoPhase   bool
	pollute      bool

	proto  *lua.FunctionProto
	source string

	pool sync.Pool

	// aux is per-check auxiliary state that bridge helpers need to keep
	// alive for the lifetime of this LuaCheck (one entry per helper that
	// asks for one, keyed by an opaque helper-private struct{} type).
	// Used so a stateful Go-side evaluator (the subdomain-takeover DNS
	// cache) gets one instance per registered check - the same shape as
	// the Go check, which is registered as a single *SubdomainTakeover
	// shared across all the goroutines that scan with it. Keeping the
	// state here rather than as a package-level singleton means the
	// engine can be reloaded mid-process without re-using stale caches.
	aux sync.Map
}

// AuxOrCreate returns the per-LuaCheck auxiliary value stored under
// key, building it with the supplied factory on first use. The build
// function may be called more than once under contention (LoadOrStore
// semantics); only one of the built values is retained, the rest are
// discarded by the GC. Used by bridge helpers that need a long-lived
// Go-side struct (e.g. the subdomain-takeover evaluator) whose
// lifetime should match this LuaCheck, not the host process.
func (c *LuaCheck) AuxOrCreate(key any, build func() any) any {
	if v, ok := c.aux.Load(key); ok {
		return v
	}
	v, _ := c.aux.LoadOrStore(key, build())
	return v
}

// Load parses src as a Lua check module, validates the metadata it
// exports, and returns a ready-to-run LuaCheck. name is the source
// identifier used in error messages (typically the .lua filename) and
// is unrelated to the check's runtime name (which comes from
// module.name).
//
// The module is compiled to bytecode here and the FunctionProto is
// reused by every VM the pool spins up; loading does not retain a
// live LState. A single throwaway VM is instantiated solely to read
// the module's metadata table, then immediately closed.
func Load(name string, src []byte) (*LuaCheck, error) {
	proto, err := compile(name, src)
	if err != nil {
		return nil, err
	}

	// Spin up a one-shot VM to read metadata. The pool's per-goroutine
	// VMs each re-instantiate the module independently; we only need
	// this one to inspect the table shape and surface friendly load-
	// time errors before any scan starts.
	L := newVM()
	defer L.Close()
	tbl, err := instantiateModule(L, proto)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	meta, err := readCheckMeta(tbl)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	c := &LuaCheck{
		name:         meta.name,
		level:        meta.level,
		defaultScope: meta.scope,
		cwe:          meta.cwe,
		owasp:        meta.owasp,
		remediation:  meta.remediation,
		budget:       meta.budget,
		isTwoPhase:   meta.twoPhase,
		pollute:      meta.pollute,
		proto:        proto,
		source:       name,
	}
	return c, nil
}

// compile parses src into a FunctionProto. The parser already accepts
// a chunk name, which gopher-lua surfaces in stack traces - we pass
// the source filename through so a Lua runtime error in
// `server_leak.lua` reads as `server_leak.lua:42` not `<unknown>:42`.
func compile(name string, src []byte) (*lua.FunctionProto, error) {
	chunk, err := luaparse.Parse(strings.NewReader(string(src)), name)
	if err != nil {
		return nil, fmt.Errorf("%s: parse: %w", name, err)
	}
	proto, err := lua.Compile(chunk, name)
	if err != nil {
		return nil, fmt.Errorf("%s: compile: %w", name, err)
	}
	return proto, nil
}

// checkMeta is the parsed metadata view of a Lua module's top-level
// table. Kept private; LuaCheck stores the fields it cares about
// directly so the rest of the package never re-reads the table.
type checkMeta struct {
	name        string
	level       Level
	scope       Scope
	cwe         string
	owasp       string
	remediation string
	budget      time.Duration
	twoPhase    bool
	pollute     bool
}

func readCheckMeta(t *lua.LTable) (checkMeta, error) {
	var m checkMeta
	m.name = lvalString(t.RawGetString("name"))
	if m.name == "" {
		return m, errors.New("module table missing required field `name`")
	}
	levelStr := lvalString(t.RawGetString("level"))
	if levelStr == "" {
		return m, fmt.Errorf("%s: module table missing required field `level`", m.name)
	}
	lvl, err := ParseLevel(levelStr)
	if err != nil {
		return m, fmt.Errorf("%s: %w", m.name, err)
	}
	m.level = lvl

	scopeStr := lvalString(t.RawGetString("scope"))
	if scopeStr == "" {
		scopeStr = "page"
	}
	sc, err := parseScope(scopeStr)
	if err != nil {
		return m, fmt.Errorf("%s: %w", m.name, err)
	}
	m.scope = sc

	m.cwe = lvalString(t.RawGetString("cwe"))
	m.owasp = lvalString(t.RawGetString("owasp"))
	m.remediation = lvalString(t.RawGetString("remediation"))

	if b, ok := t.RawGetString("budget_seconds").(lua.LNumber); ok && b > 0 {
		m.budget = time.Duration(float64(b) * float64(time.Second))
	}
	// phase opts a module into the TwoPhaseCheck wrapper. Two-phase
	// is opt-in because the scanner re-fetches the visited URL set
	// during phase 2 the moment any TwoPhaseCheck is registered;
	// silently promoting every module would burn the request budget.
	phase := lvalString(t.RawGetString("phase"))
	switch phase {
	case "", "single":
		m.twoPhase = false
	case "two-phase":
		m.twoPhase = true
	default:
		return m, fmt.Errorf("%s: invalid phase %q (want \"single\" or \"two-phase\")", m.name, phase)
	}
	// pollute opts a module into the --pollute gate: state-mutating or
	// otherwise disruptive checks (stored XSS plants, JWT brute force,
	// raw-socket smuggling probes, race-condition fan-out, prototype
	// pollution) declare `pollute = true` so the catalog filters them
	// out by default. Operators opt in with --pollute at scan time.
	if v, ok := t.RawGetString("pollute").(lua.LBool); ok {
		m.pollute = bool(v)
	}
	return m, nil
}

// Pollute reports whether the module declared `pollute = true`. The
// catalog uses this to gate state-mutating / disruptive checks behind
// --pollute so a default scan stays read-only.
func (c *LuaCheck) Pollute() bool { return c.pollute }

// Drain executes the optional check.drain(ctx) Lua entry point and
// returns its findings. Drain exists for OOB-using checks (ssti,
// cmd-injection-blind, ssrf, ...) whose detection signal arrives
// asynchronously after Run returned: the scanner calls Drain once the
// per-target Run sweep completes so each registered canary that
// observed a callback gets folded into a finding.
//
// The Lua module declares this branch as `function check.drain(ctx)`
// and returns a table-of-findings the same way Run does. Modules that
// do not declare drain return no findings; Drain still runs (the
// LuaCheck unconditionally satisfies OOBCheck so the scanner does
// not need to know which modules use it) but the cost is one
// table lookup against the loaded module.
//
// Errors from the Lua drain path are not propagated through the
// (single-return) OOBCheck.Drain signature; they surface via the
// shared per-call Report channel just like a Run-time sub-error.
func (c *LuaCheck) Drain(ctx context.Context) []Finding {
	L, mod, err := c.borrow()
	if err != nil {
		Report(ctx, fmt.Errorf("%s: drain borrow: %w", c.name, err))
		return nil
	}
	keepVM := true
	defer func() {
		if r := recover(); r != nil {
			keepVM = false
			Report(ctx, fmt.Errorf("%s: drain panic: %v", c.name, r))
		}
		c.release(L, mod, keepVM)
	}()

	drainFn := mod.RawGetString("drain")
	if drainFn == lua.LNil {
		return nil
	}
	if _, ok := drainFn.(*lua.LFunction); !ok {
		Report(ctx, fmt.Errorf("%s: drain field is %s, not a function", c.name, drainFn.Type()))
		return nil
	}

	envCtx := &runEnv{ctx: ctx, check: c}
	ctxUD := buildCtxUserdata(L, envCtx)
	L.SetContext(ctx)
	L.Push(drainFn)
	L.Push(ctxUD)
	if err := L.PCall(1, 1, nil); err != nil {
		keepVM = false
		Report(ctx, fmt.Errorf("%s: drain: %w", c.name, err))
		return nil
	}
	defer L.SetTop(0)

	v := L.Get(-1)
	if v == lua.LNil {
		return nil
	}
	tbl, ok := v.(*lua.LTable)
	if !ok {
		Report(ctx, fmt.Errorf("%s: drain returned %s, not a findings table", c.name, v.Type()))
		return nil
	}
	out, err := c.marshalFindings(tbl, envCtx)
	if err != nil {
		Report(ctx, fmt.Errorf("%s: drain marshal: %w", c.name, err))
		return nil
	}
	return out
}

// Name satisfies Check.
func (c *LuaCheck) Name() string { return c.name }

// Level satisfies Check.
func (c *LuaCheck) Level() Level { return c.level }

// Budget reports the per-check deadline declared in the Lua module
// via `budget_seconds`. Returning 0 leaves the scanner on its default
// (DefaultBudget). The Budgeted interface is satisfied
// unconditionally; the scanner falls back to DefaultBudget on the
// non-positive return so this stays safe even for checks that omit
// the field.
func (c *LuaCheck) Budget() time.Duration { return c.budget }

// Run executes check.run(ctx) inside a pooled VM.
//
// One VM = one goroutine: gopher-lua LStates carry mutable globals and
// stacks, so two concurrent Run calls must never share one. The pool
// solves this by handing each goroutine its own pre-initialized LState
// (with the check module already loaded and the bridge API bound) and
// taking it back when Run returns. A panic or runtime error inside
// Lua means the VM's stack is in an unknown shape; rather than try to
// salvage it we discard the VM and let the next caller spin up a fresh
// one. This trades a tiny re-init cost (compile is cached; only
// module instantiation re-runs) for not propagating poisoned VM state
// across worker boundaries.
func (c *LuaCheck) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) (findings []Finding, runErr error) {
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

	runFn := mod.RawGetString("run")
	if runFn == lua.LNil {
		return nil, fmt.Errorf("%s: module has no run function", c.name)
	}
	if _, ok := runFn.(*lua.LFunction); !ok {
		return nil, fmt.Errorf("%s: module.run is %s, not a function", c.name, runFn.Type())
	}

	envCtx := &runEnv{
		ctx:    ctx,
		client: client,
		scope:  sc,
		page:   p,
		check:  c,
	}
	ctxUD := buildCtxUserdata(L, envCtx)

	L.SetContext(ctx)
	L.Push(runFn)
	L.Push(ctxUD)
	if err := L.PCall(1, 2, nil); err != nil {
		keepVM = false
		return nil, fmt.Errorf("%s: %w", c.name, err)
	}
	defer L.SetTop(0)

	// Return shape mirrors Go's (findings, error) tuple:
	//   return findings        -- nil err implied
	//   return findings, nil
	//   return nil, "message"  -- string errors are coerced to error
	// We read the error slot first; on error, findings are discarded
	// to match how the Go check interface is consumed by the scanner.
	errV := L.Get(-1)
	findV := L.Get(-2)
	if errV != lua.LNil {
		return nil, fmt.Errorf("%s: %s", c.name, lvalString(errV))
	}
	if findV == lua.LNil {
		return nil, nil
	}
	tbl, ok := findV.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("%s: run() must return a table of findings (got %s)", c.name, findV.Type())
	}
	return c.marshalFindings(tbl, envCtx)
}

// borrow takes a VM out of the pool (or builds a fresh one), running
// the module once on creation so the returned `mod` is the live
// check-module table inside that LState. The module table can not
// be cached across LStates - each VM owns its own copy with its own
// closures - which is why we return both halves bound together.
func (c *LuaCheck) borrow() (*lua.LState, *lua.LTable, error) {
	if v := c.pool.Get(); v != nil {
		entry := v.(*pooledVM)
		return entry.L, entry.module, nil
	}
	L := newVM()
	mod, err := instantiateModule(L, c.proto)
	if err != nil {
		L.Close()
		return nil, nil, fmt.Errorf("%s: %w", c.name, err)
	}
	return L, mod, nil
}

// release returns a VM to the pool when keep is true, otherwise
// discards it. The caller flips keep=false on any path where the VM
// might be poisoned (panic in a binding, PCall error that left the
// stack in an unknown state) so the next borrower starts on solid
// ground.
func (c *LuaCheck) release(L *lua.LState, mod *lua.LTable, keep bool) {
	if !keep {
		L.Close()
		return
	}
	L.SetTop(0)
	c.pool.Put(&pooledVM{L: L, module: mod})
}

// pooledVM pairs an LState with the check module already loaded inside
// it. Stored as a single value in the pool so a Get returns both
// halves together without a second lookup.
type pooledVM struct {
	L      *lua.LState
	module *lua.LTable
}

// runEnv is the Go-side bag of values that the Lua ctx userdata
// exposes to the running check. Holding it as a struct keeps the
// binding code one indirection away from the scanner's call shape; if
// the engine adds another per-Run input (a baseline diff handle, a
// shared cache) the binding extends the struct rather than threading
// another parameter through every API surface.
type runEnv struct {
	ctx    context.Context
	client *httpclient.Client
	scope  *scope.Scope
	page   page.Page
	check  *LuaCheck
}

// parseScope mirrors ParseSeverity for the Scope enum. Kept
// private to the bridge because the Go side already uses typed Scope
// constants directly - this conversion only matters when the value
// arrives as a string from Lua.
func parseScope(s string) (Scope, error) {
	switch s {
	case "host":
		return ScopeHost, nil
	case "page":
		return ScopePage, nil
	case "param":
		return ScopeParam, nil
	}
	return 0, fmt.Errorf("invalid scope %q (want host, page, or param)", s)
}
