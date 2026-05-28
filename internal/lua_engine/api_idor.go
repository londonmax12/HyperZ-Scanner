package lua_engine

import (
	"net/http"
	"net/url"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// buildIDORTable returns the ctx.idor helper namespace. IDOR keeps a
// scan-lifetime *Corpus alive on the LuaCheck via AuxOrCreate
// so cross-page ingest survives between Run calls the same way the Go
// check's `&IDOR{}` registration does. The Lua side gets a
// handle (corpus userdata) and methods to ingest the active page,
// classify a candidate value, and read the per-pattern history.
//
// Pure-function primitives sit alongside the corpus accessors:
//
//	ctx.idor.judge(baseline, tampered, control)
//	   - Verdict shape mirroring idorJudge: { vulnerable, confidence,
//	     detail, tampered_sim, control_sim, tampered_control_sim,
//	     pii_hints[] }.
//
//	ctx.idor.path_sinks(page_url, classify_fn)
//	   - Synthesizes LocPath sinks for ID-looking path segments. Takes
//	     a Lua callback that classifies a (name, value) pair so the
//	     bridge does not need to second-guess corpus state.
//
// The Lua port owns: probe order, per-sink budget, control payload
// shape (it calls ctx.idor.control_payload to defer to the same Go
// table the Go check uses), finding composition, and the deny-list.
// The bridge owns: stateful pattern classification, Go-private
// generators that need crypto/rand, oracle math.
func buildIDORTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("corpus", L.NewFunction(idorCorpus))
	t.RawSetString("judge", L.NewFunction(idorJudgeFn))
	t.RawSetString("control_payload", L.NewFunction(idorControlPayload))
	t.RawSetString("path_sinks", L.NewFunction(idorPathSinks))
	return t
}

// idorCorpusKey identifies the per-LuaCheck slot the *Corpus
// lives in. Zero-size unique type so AuxOrCreate's map cannot collide
// with another helper's key.
type idorCorpusKey struct{}

// corpusUserData wraps the *Corpus the active LuaCheck owns
// for this scan. One-per-check by AuxOrCreate; the userdata is
// thin-wrapped so multiple Lua callsites can request the handle
// without each one rebuilding the corpus.
type corpusUserData struct {
	c *Corpus
}

func idorCorpus(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.idor.corpus called outside a check run")
	}
	c := env.Check.AuxOrCreate(idorCorpusKey{}, func() any {
		return NewCorpus()
	}).(*Corpus)
	ud := L.NewUserData()
	ud.Value = &corpusUserData{c: c}
	ud.Metatable = ensureCorpusMT(L)
	L.Push(ud)
	return 1
}

const mtCorpus = "__hyperz_mt_corpus"

func ensureCorpusMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtCorpus).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("ingest_page", L.NewFunction(corpusIngestPage))
	methods.RawSetString("classify", L.NewFunction(corpusClassify))
	methods.RawSetString("generate", L.NewFunction(corpusGenerate))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtCorpus, mt)
	return mt
}

func corpusFromArg(L *lua.LState, pos int) *corpusUserData {
	v := L.CheckUserData(pos).Value
	c, ok := v.(*corpusUserData)
	if !ok {
		L.ArgError(pos, "expected idor corpus userdata")
	}
	return c
}

// corpusIngestPage folds the active page's sinks plus path segments
// into the corpus. Same effect as Corpus.IngestPage; the Lua port
// calls this at the top of every Run so cross-page learning works
// the same as in the Go check.
func corpusIngestPage(L *lua.LState) int {
	c := corpusFromArg(L, 1)
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("corpus:ingest_page called outside a check run")
	}
	c.c.IngestPage(env.Page)
	return 0
}

// corpusClassify returns a pattern descriptor for (name, value) or
// nil if the value does not look like an identifier the check should
// probe. The returned table carries name / precedence / learned plus
// a synthetic `_handle` field whose userdata is the corpus pointer +
// the pattern name; pattern:generate reads both back from the handle
// to find the right Pattern in either the built-in or learned set on
// every call (the built-in set is stable; the learned set may have
// grown since classify ran, but that is fine - generate looks up by
// name).
func corpusClassify(L *lua.LState) int {
	c := corpusFromArg(L, 1)
	name := requireString(L, 2)
	value := requireString(L, 3)
	p := c.c.Classify(name, value)
	if p == nil {
		L.Push(lua.LNil)
		return 1
	}
	out := L.NewTable()
	out.RawSetString("name", lua.LString(p.Name))
	out.RawSetString("precedence", lua.LNumber(p.Precedence))
	out.RawSetString("learned", lua.LBool(p.Learned))
	L.Push(out)
	return 1
}

// corpusGenerate returns up to `want` tampering candidates for seed
// against the named pattern. Looks the pattern up by name from the
// corpus's built-in + learned set so a learned pattern promoted after
// the call to classify is still resolvable. Returns an empty table
// when the pattern is unknown rather than raising, so a typo in the
// Lua caller fails as "no candidates" rather than a Lua-level error.
func corpusGenerate(L *lua.LState) int {
	c := corpusFromArg(L, 1)
	name := requireString(L, 2)
	seed := requireString(L, 3)
	want := L.CheckInt(4)
	if want <= 0 {
		L.Push(L.NewTable())
		return 1
	}
	pat := findPatternByName(c.c, name)
	if pat == nil {
		L.Push(L.NewTable())
		return 1
	}
	L.Push(pushStringList(L, pat.Generate(seed, c.c, want)))
	return 1
}

// findPatternByName resolves a pattern name to its *Pattern,
// looking through both the built-in set and the corpus's learned
// patterns. Returns nil for an unknown name; the caller treats that
// as "no candidates" rather than as an error.
func findPatternByName(c *Corpus, name string) *Pattern {
	for _, p := range c.BuiltinPatterns() {
		if p.Name == name {
			pp := p
			return &pp
		}
	}
	for _, p := range c.LearnedPatterns() {
		if p.Name == name {
			pp := p
			return &pp
		}
	}
	return nil
}

// idorJudgeFn mirrors IDORJudge: takes baseline / tampered /
// control snapshot tables and returns a verdict table. Kept verbatim
// so the Lua port produces byte-identical decisions to the Go check
// on the same wire.
func idorJudgeFn(L *lua.LState) int {
	baseline := readSnapshotArg(L.Get(1))
	tampered := readSnapshotArg(L.Get(2))
	control := readSnapshotArg(L.Get(3))
	v := IDORJudge(baseline, tampered, control)
	out := L.NewTable()
	out.RawSetString("vulnerable", lua.LBool(v.Vulnerable))
	out.RawSetString("confidence", lua.LString(v.Confidence))
	out.RawSetString("detail", lua.LString(v.Detail))
	out.RawSetString("tampered_sim", lua.LNumber(v.TamperedSim))
	out.RawSetString("control_sim", lua.LNumber(v.ControlSim))
	out.RawSetString("tampered_control_sim", lua.LNumber(v.TamperedControlSim))
	out.RawSetString("pii_hints", pushStringList(L, v.PIIHints))
	L.Push(out)
	return 1
}

// idorControlPayload returns the sentinel garbage value for the
// named pattern + seed. Wraps the Go-side controlPayloadFor so the
// Lua port and the Go check fall into the same sentinel string for a
// given pattern, which keeps dedupe keys and false-positive backstop
// behavior aligned across both impls.
func idorControlPayload(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.idor.control_payload called outside a check run")
	}
	name := requireString(L, 1)
	seed := requireString(L, 2)
	c := env.Check.AuxOrCreate(idorCorpusKey{}, func() any {
		return NewCorpus()
	}).(*Corpus)
	pat := findPatternByName(c, name)
	if pat == nil {
		L.Push(lua.LString(seed + "_hyperz_canary"))
		return 1
	}
	L.Push(lua.LString(IDORControlPayload(pat, seed)))
	return 1
}

// idorPathSinks scans page_url for ID-looking segments and returns a
// list of Sink userdata describing each, ready for sink:mutate_request.
// Classification routes through the active corpus so a learned shape
// promoted earlier in the scan is honored.
//
// Only path-classifiable patterns (numeric / uuid / mongoid / hex) are
// surfaced. Email / username / slug in a URL path are usually SEO-
// friendly URLs whose real ID lives in the query string; probing the
// slug burns requests without adding signal. The filter matches the
// Go check's identifierSinks pathSinks branch.
func idorPathSinks(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.idor.path_sinks called outside a check run")
	}
	pageURL := requireString(L, 1)
	u, err := url.Parse(pageURL)
	if err != nil || u.Path == "" {
		L.Push(L.NewTable())
		return 1
	}
	c := env.Check.AuxOrCreate(idorCorpusKey{}, func() any {
		return NewCorpus()
	}).(*Corpus)
	segs := strings.Split(u.EscapedPath(), "/")
	out := L.NewTable()
	idx := 0
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			continue
		}
		pat := c.Classify("__path__", decoded)
		if pat == nil {
			continue
		}
		switch pat.Name {
		case "numeric", "uuid", "mongoid", "hex":
		default:
			continue
		}
		segName := pathSegName(i)
		placeholderSegs := make([]string, len(segs))
		copy(placeholderSegs, segs)
		placeholderSegs[i] = "{" + segName + "}"
		s := &Sink{
			Method: http.MethodGet,
			URL:    joinPathPlaceholderURL(u, placeholderSegs),
			Loc:    LocPath,
			Name:   segName,
			Value:  decoded,
		}
		entry := L.NewTable()
		entry.RawSetString("sink", pushSink(L, s))
		entry.RawSetString("pattern", lua.LString(pat.Name))
		entry.RawSetString("learned", lua.LBool(pat.Learned))
		entry.RawSetString("precedence", lua.LNumber(pat.Precedence))
		entry.RawSetString("segment_index", lua.LNumber(i))
		idx++
		out.RawSetInt(idx, entry)
	}
	L.Push(out)
	return 1
}

func pathSegName(i int) string {
	return "seg" + intToStr(i)
}

// joinPathPlaceholderURL re-serializes u with its path segments replaced by
// segs. The URL is assembled by hand because url.URL.String() would
// percent-encode the braces around any `{segN}` placeholder in segs,
// leaving the resulting sink with a URL like /user/%7Bseg2%7D that
// Sink.MutateRequest's literal-placeholder lookup can't match. Segs other
// than the placeholder are already in escaped form (they came from
// EscapedPath); the placeholder is intended to round-trip verbatim until
// MutateRequest substitutes a value.
func joinPathPlaceholderURL(u *url.URL, segs []string) string {
	var sb strings.Builder
	if u.Scheme != "" {
		sb.WriteString(u.Scheme)
		sb.WriteString("://")
	}
	if u.User != nil {
		sb.WriteString(u.User.String())
		sb.WriteByte('@')
	}
	sb.WriteString(u.Host)
	sb.WriteString(strings.Join(segs, "/"))
	if u.RawQuery != "" {
		sb.WriteByte('?')
		sb.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		sb.WriteByte('#')
		sb.WriteString(u.EscapedFragment())
	}
	return sb.String()
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

func init() {
	registerHelperTable("idor", buildIDORTable)
}
