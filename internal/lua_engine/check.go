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

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
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

	// appliesTo is the parsed `applies_to` table. An empty spec (no
	// declared constraints) is permissive: the check runs against every
	// stack, matching the default for checks that omit the field. When
	// at least one allow-list is populated, the check is StackGated
	// and the scanner skips dispatch on non-matching hosts.
	appliesTo fingerprint.AppliesSpec

	// patchedIn is the parsed `patched_in` table mapping lowercased
	// stack field names to version strings. It is metadata, not a gate:
	// the check still runs regardless of banner version (banners are
	// unreliable and a trip is the strongest signal we have). When the
	// check fires, Run cross-references PatchedIn against the live
	// Stack and appends info-level "version inferred" / "patched but
	// fired" observations as additional findings.
	patchedIn fingerprint.PatchedIn

	// tier is the parsed `tier` field declaring where the check sits
	// in the worklist dispatch pipeline. Zero (the unset default)
	// satisfies core.Targeted by returning the zero Tier; the scanner's
	// checkTier helper clamps that to TierActive, matching the
	// pre-tier behavior where every check ran as one batch at the
	// active stage.
	tier core.Tier

	// consumes is the parsed `consumes` field listing which target
	// kinds the check accepts dispatch against. nil / empty (the
	// unset default) is treated by the scanner as a permissive
	// KindPage-only allow-list, matching the pre-tier behavior.
	consumes []target.Kind

	// settings is the per-check config bag the operator supplied
	// via the YAML config's `checks.settings[<name>]` block. The
	// bridge exposes it inside Lua as `ctx.config`; the engine does
	// not interpret the values, so the schema each check accepts
	// stays owned by the .lua file. nil means "no settings", which
	// the Lua side sees as an empty table.
	settings map[string]any

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
		appliesTo:    meta.appliesTo,
		patchedIn:    meta.patchedIn,
		tier:         meta.tier,
		consumes:     meta.consumes,
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
	appliesTo   fingerprint.AppliesSpec
	patchedIn   fingerprint.PatchedIn
	tier        core.Tier
	consumes    []target.Kind
}

func readCheckMeta(t *lua.LTable) (checkMeta, error) {
	var m checkMeta
	m.name = LValString(t.RawGetString("name"))
	if m.name == "" {
		return m, errors.New("module table missing required field `name`")
	}
	levelStr := LValString(t.RawGetString("level"))
	if levelStr == "" {
		return m, fmt.Errorf("%s: module table missing required field `level`", m.name)
	}
	lvl, err := ParseLevel(levelStr)
	if err != nil {
		return m, fmt.Errorf("%s: %w", m.name, err)
	}
	m.level = lvl

	scopeStr := LValString(t.RawGetString("scope"))
	if scopeStr == "" {
		scopeStr = "page"
	}
	sc, err := parseScope(scopeStr)
	if err != nil {
		return m, fmt.Errorf("%s: %w", m.name, err)
	}
	m.scope = sc

	m.cwe = LValString(t.RawGetString("cwe"))
	m.owasp = LValString(t.RawGetString("owasp"))
	m.remediation = LValString(t.RawGetString("remediation"))

	if b, ok := t.RawGetString("budget_seconds").(lua.LNumber); ok && b > 0 {
		m.budget = time.Duration(float64(b) * float64(time.Second))
	}
	// phase opts a module into the TwoPhaseCheck wrapper. Two-phase
	// is opt-in because the scanner re-fetches the visited URL set
	// during phase 2 the moment any TwoPhaseCheck is registered;
	// silently promoting every module would burn the request budget.
	phase := LValString(t.RawGetString("phase"))
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

	// applies_to gates vendor-specific checks to hosts whose detected
	// fingerprint matches the declared spec. Empty / missing field
	// leaves the check stack-agnostic (the default). See
	// fingerprint.AppliesSpec for the semantic contract.
	if at := t.RawGetString("applies_to"); at != lua.LNil {
		atTbl, ok := at.(*lua.LTable)
		if !ok {
			return m, fmt.Errorf("%s: applies_to must be a table, got %s", m.name, at.Type())
		}
		spec, err := parseAppliesTo(atTbl)
		if err != nil {
			return m, fmt.Errorf("%s: %w", m.name, err)
		}
		m.appliesTo = spec
	}

	// patched_in is metadata for derived version-inference
	// observations the engine emits when this check fires. Keys are
	// lowercased stack field names (cms, framework, server, ...);
	// values are the version at which the upstream vendor patched the
	// underlying issue. See fingerprint.PatchedIn.
	if pi := t.RawGetString("patched_in"); pi != lua.LNil {
		piTbl, ok := pi.(*lua.LTable)
		if !ok {
			return m, fmt.Errorf("%s: patched_in must be a table, got %s", m.name, pi.Type())
		}
		pin, err := parsePatchedIn(piTbl)
		if err != nil {
			return m, fmt.Errorf("%s: %w", m.name, err)
		}
		m.patchedIn = pin
	}

	// tier places the check on the worklist's dispatch pipeline.
	// Omitting the field leaves m.tier at zero, which the scanner's
	// checkTier clamps to TierActive - matching the pre-tier default
	// where every check ran as one batch at the active stage. A typo
	// in the value is an error rather than silently falling back, so
	// `tier = "passsive"` does not silently disable a passive check's
	// ordering guarantee.
	if tierStr := LValString(t.RawGetString("tier")); tierStr != "" {
		tier, err := parseTier(tierStr)
		if err != nil {
			return m, fmt.Errorf("%s: %w", m.name, err)
		}
		m.tier = tier
	}

	// consumes lists the target kinds the check accepts dispatch
	// against. A check that probes a specific (param, location) tuple
	// declares `consumes = {"param"}` so the scanner only dispatches
	// it against KindParam targets; the default (omitted field or
	// empty list) is the legacy KindPage-only contract. Accepts either
	// a single string ("param") or an array of strings; an unknown
	// kind name is an error for the same reason a typo in tier is.
	if con := t.RawGetString("consumes"); con != lua.LNil {
		kinds, err := parseConsumes(con)
		if err != nil {
			return m, fmt.Errorf("%s: %w", m.name, err)
		}
		m.consumes = kinds
	}
	return m, nil
}

// parseTier maps the Lua-side tier label to a core.Tier. Unknown
// labels error so a typo cannot silently downgrade a check to the
// default active tier.
func parseTier(s string) (core.Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fingerprint":
		return core.TierFingerprint, nil
	case "passive":
		return core.TierPassive, nil
	case "discovery":
		return core.TierDiscovery, nil
	case "active":
		return core.TierActive, nil
	case "deferred":
		return core.TierDeferred, nil
	}
	return 0, fmt.Errorf("invalid tier %q (want fingerprint, passive, discovery, active, or deferred)", s)
}

// parseConsumes reads the `consumes` field as either a single string
// or an array-of-strings, returning the corresponding target.Kind
// list. The single-string form is sugar for a one-element array, the
// common case for param-tampering checks. Returns an empty slice for
// an empty array literal (`consumes = {}`); callers treat that the
// same as the omitted-field case.
func parseConsumes(v lua.LValue) ([]target.Kind, error) {
	switch val := v.(type) {
	case lua.LString:
		k, err := parseTargetKind(string(val))
		if err != nil {
			return nil, fmt.Errorf("consumes: %w", err)
		}
		return []target.Kind{k}, nil
	case *lua.LTable:
		var out []target.Kind
		var firstErr error
		val.ForEach(func(_, item lua.LValue) {
			if firstErr != nil {
				return
			}
			s, ok := item.(lua.LString)
			if !ok {
				firstErr = fmt.Errorf("consumes entries must be strings, got %s", item.Type())
				return
			}
			k, err := parseTargetKind(string(s))
			if err != nil {
				firstErr = fmt.Errorf("consumes: %w", err)
				return
			}
			out = append(out, k)
		})
		if firstErr != nil {
			return nil, firstErr
		}
		return out, nil
	}
	return nil, fmt.Errorf("consumes must be a string or table of strings, got %s", v.Type())
}

// parseAppliesTo reads an applies_to sub-table:
//
//	applies_to = { cms = {"wordpress"}, server = {"nginx", "apache"} }
//
// Per-field values may be a single string or an array-of-strings; the
// single-string form is sugar for a one-element array, common for
// vendor checks that name exactly one CMS or framework. Unknown field
// names are an error: a typo (e.g. "stack" instead of "framework")
// would otherwise silently disable the gate.
func parseAppliesTo(t *lua.LTable) (fingerprint.AppliesSpec, error) {
	var spec fingerprint.AppliesSpec
	var firstErr error
	t.ForEach(func(k, v lua.LValue) {
		if firstErr != nil {
			return
		}
		keyV, ok := k.(lua.LString)
		if !ok {
			firstErr = fmt.Errorf("applies_to keys must be strings, got %s", k.Type())
			return
		}
		key := strings.ToLower(string(keyV))
		var values []string
		switch vv := v.(type) {
		case lua.LString:
			values = []string{string(vv)}
		case *lua.LTable:
			n := vv.Len()
			for i := 1; i <= n; i++ {
				if s := LValString(vv.RawGetInt(i)); s != "" {
					values = append(values, s)
				}
			}
		default:
			firstErr = fmt.Errorf("applies_to.%s must be a string or table of strings, got %s",
				key, v.Type())
			return
		}
		switch key {
		case "server":
			spec.Server = values
		case "language":
			spec.Language = values
		case "framework":
			spec.Framework = values
		case "cms":
			spec.CMS = values
		case "cdn":
			spec.CDN = values
		case "waf":
			spec.WAF = values
		default:
			firstErr = fmt.Errorf("applies_to has unknown field %q (want server, language, framework, cms, cdn, or waf)", key)
		}
	})
	return spec, firstErr
}

// parsePatchedIn reads a patched_in sub-table:
//
//	patched_in = { cms = "6.2", framework = "4.18.0" }
//
// Values must be non-empty strings; the version syntax itself is
// validated lazily at finding-emit time via fingerprint.Stack's
// CompareVersion (loose parse: leading digits per segment). Unknown
// field names are an error for the same reason as applies_to - a typo
// would silently drop the inference signal.
func parsePatchedIn(t *lua.LTable) (fingerprint.PatchedIn, error) {
	out := fingerprint.PatchedIn{}
	var firstErr error
	t.ForEach(func(k, v lua.LValue) {
		if firstErr != nil {
			return
		}
		keyV, ok := k.(lua.LString)
		if !ok {
			firstErr = fmt.Errorf("patched_in keys must be strings, got %s", k.Type())
			return
		}
		key := strings.ToLower(string(keyV))
		switch key {
		case "server", "language", "framework", "cms", "cdn", "waf":
		default:
			firstErr = fmt.Errorf("patched_in has unknown field %q (want server, language, framework, cms, cdn, or waf)", key)
			return
		}
		val := LValString(v)
		if val == "" {
			firstErr = fmt.Errorf("patched_in.%s must be a non-empty version string", key)
			return
		}
		out[key] = val
	})
	if firstErr != nil {
		return nil, firstErr
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Pollute reports whether the module declared `pollute = true`. The
// catalog uses this to gate state-mutating / disruptive checks behind
// --pollute so a default scan stays read-only.
func (c *LuaCheck) Pollute() bool { return c.pollute }

// SetSettings stores the per-check config bag this LuaCheck should
// expose to Lua as `ctx.config`. Pass nil to clear. The catalog is
// expected to call this once after load, before any Run / Plant is
// invoked; nothing synchronizes concurrent SetSettings against a
// running Run because in practice settings are configured at scan
// startup and frozen for the duration of the scan.
func (c *LuaCheck) SetSettings(bag map[string]any) {
	c.settings = bag
}

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

	envCtx := &RunEnv{Ctx: ctx, Check: c}
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

// AppliesTo satisfies fingerprint.StackGated. Returns true when the
// check's declared `applies_to` spec matches stack, or unconditionally
// when no spec was declared (the empty spec is permissive). Checks
// without the field are stack-agnostic and run against every host.
func (c *LuaCheck) AppliesTo(stack *fingerprint.Stack) bool {
	return c.appliesTo.Matches(stack)
}

// Tier satisfies core.Targeted. Returns the parsed `tier` field or
// the zero Tier if the field was omitted; the scanner's checkTier
// clamps the zero return to core.TierActive so omitting `tier`
// preserves the legacy dispatch-as-active default.
func (c *LuaCheck) Tier() core.Tier { return c.tier }

// Consumes satisfies core.Targeted. Returns the parsed `consumes`
// field or nil if the field was omitted; the scanner's consumesKind
// treats nil / empty as the KindPage-only allow-list, matching the
// pre-tier dispatch contract.
func (c *LuaCheck) Consumes() []target.Kind { return c.consumes }

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

	envCtx := &RunEnv{
		Ctx:    ctx,
		Client: client,
		Scope:  sc,
		Page:   p,
		Check:  c,
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
		return nil, fmt.Errorf("%s: %s", c.name, LValString(errV))
	}
	if findV == lua.LNil {
		return nil, nil
	}
	tbl, ok := findV.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("%s: run() must return a table of findings (got %s)", c.name, findV.Type())
	}
	marshalled, marshalErr := c.marshalFindings(tbl, envCtx)
	if marshalErr != nil {
		return nil, marshalErr
	}
	return c.applyPatchedInInference(ctx, marshalled), nil
}

// applyPatchedInInference cross-references the check's patched_in
// metadata against the stack attached to ctx and appends derived
// info-level observations for each (field, version) pair that
// warrants one. Returns findings unchanged when the check declared no
// patched_in, when no source findings fired (nothing to be inferred
// from), or when no stack is attached.
//
// Derived observations dedupe at host scope per field, so a 50-page
// crawl on a vulnerable WordPress site produces one "version inferred"
// observation per patched_in field, not 50. The dedupe key folds the
// emitting check name so two distinct vendor checks both declaring
// patched_in for the same field produce two independent observations
// (each with its own evidence chain) rather than silently collapsing.
func (c *LuaCheck) applyPatchedInInference(ctx context.Context, findings []Finding) []Finding {
	if len(findings) == 0 || len(c.patchedIn) == 0 {
		return findings
	}
	stack := StackFrom(ctx)
	obs := c.patchedIn.Infer(stack)
	if len(obs) == 0 {
		return findings
	}
	// The source row drives target / URL on the derived observation;
	// any of the firing findings works because the inference is
	// host-scoped, but using the first preserves a recognizable URL
	// in reports.
	src := findings[0]
	out := make([]Finding, len(findings), len(findings)+len(obs))
	copy(out, findings)
	for _, o := range obs {
		out = append(out, c.buildInferenceFinding(src, o))
	}
	return out
}

// buildInferenceFinding renders one fingerprint.VersionInference
// observation as a Finding. The user-visible strings live here in the
// engine, not in the check's .lua source - the check declares
// patched_in as a structured fact; the engine owns rendering. Info
// severity for both kinds: the source finding already carries the
// vuln's actual severity, the derived observation only adds version
// context.
func (c *LuaCheck) buildInferenceFinding(src Finding, o fingerprint.VersionInference) Finding {
	var title, detail string
	switch o.Kind {
	case "inferred":
		title = fmt.Sprintf("%s version inferred below %s", o.DetectedName, o.PatchedVersion)
		detail = fmt.Sprintf(
			"Vendor-specific check %q fired against this host. The vendor patched the underlying issue in %s %s; the host's response banner did not advertise a %s version, so the deployed build is inferred to be older than %s.",
			c.name, o.DetectedName, o.PatchedVersion, o.DetectedName, o.PatchedVersion)
	case "patched_but_fired":
		title = fmt.Sprintf("%s reports version %s but vendor check fired anyway", o.DetectedName, o.BannerVersion)
		detail = fmt.Sprintf(
			"Vendor-specific check %q fired against this host. The vendor patched the underlying issue in %s %s, yet the host's response banner advertises %s %s. Either the patch was regressed in this deployment, the patch is partial, or the version banner is spoofed.",
			c.name, o.DetectedName, o.PatchedVersion, o.DetectedName, o.BannerVersion)
	}
	return Finding{
		Check:       c.name,
		Target:      src.Target,
		URL:         src.URL,
		Severity:    SeverityInfo,
		Title:       title,
		Detail:      detail,
		CWE:         "CWE-1104",
		OWASP:       "A06:2021 Vulnerable and Outdated Components",
		Remediation: "Upgrade " + o.DetectedName + " to " + o.PatchedVersion + " or later, then re-scan to confirm the source finding clears.",
		DedupeKey:   MakeKey(c.name, ScopeHost, src.URL, "patched_in", o.Field, o.Kind),
	}
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

// RunEnv is the Go-side bag of values that the Lua ctx userdata
// exposes to the running check. Holding it as a struct keeps the
// binding code one indirection away from the scanner's call shape; if
// the engine adds another per-Run input (a baseline diff handle, a
// shared cache) the binding extends the struct rather than threading
// another parameter through every API surface.
//
// Exported so a future api/ or checks/<family>/ subpackage can read
// these fields directly without an accessor wrapper per use; CurrentEnv
// is the only entry point a binding ever needs.
type RunEnv struct {
	Ctx    context.Context
	Client *httpclient.Client
	Scope  *scope.Scope
	Page   page.Page
	Check  *LuaCheck
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
