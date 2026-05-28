package lua_engine

import (
	"bytes"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"
	"golang.org/x/net/html"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/target"
)

// buildStoredXSSTable returns the ctx.stored_xss helper namespace. The
// single state() entry point returns the per-LuaCheck StoredXSSState
// the module uses to coordinate Plant -> DetectURLs -> Detect across
// the phases. The state object exposes the cross-phase data
// structures (sink dedupe set, canary -> plant record map, harvested
// URL set, fired-sink set) so the Lua-side check decides which sink
// to plant, what payload to mint, whether a re-fetched body shows
// evidence of a plant, and how to compose the resulting finding.
//
// Body-link harvesting and canary regex extraction live in Go because
// both rely on tokenisation routines (html.NewTokenizer, RE2 regex)
// that Lua would re-implement at significant cost without adding any
// rule-level expressivity.
func buildStoredXSSTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("state", L.NewFunction(storedXSSStateFn))
	t.RawSetString("new_canary", L.NewFunction(storedXSSNewCanary))
	return t
}

// storedXSSStateKey identifies the per-LuaCheck slot the
// StoredXSSState lives in. Zero-size unique type so AuxOrCreate's
// map cannot collide with another helper's key.
type storedXSSStateKey struct{}

// sinkKey identifies a (method, url, loc, name) sink across pages.
// The same form discovered on N crawled pages is one attack surface;
// keying dedupe on this composite collapses the N back to 1 plant set.
type sinkKey struct {
	method string
	url    string
	loc    string
	name   string
}

// storedXSSPlant records what one canary's plant carried so the
// Detect pass can rebuild the finding from a canary echo. payload is
// the rendered wire bytes (the breakout shell around the canary);
// payloadCtx / payloadName label the breakout shape for the finding
// detail text.
type storedXSSPlant struct {
	sink        sinkKey
	sinkValue   string
	payload     string
	payloadName string
	payloadCtx  string
	plantURL    string
}

// StoredXSSState is the per-LuaCheck scan-lifetime store backing the
// stored-xss Lua port. Concurrent Plant calls across page workers all
// take the same mutex; Detect calls do too. The structure mirrors the
// Go stored-xss check's internal map set (plantedSinks, canaries,
// detectFired) so the Lua port can produce byte-aligned findings
// against the same wire input. URLs surfaced during Plant flow
// directly to the worklist at TierDeferred via core.DiscoverAt and
// no longer live on the state; the post-fold TwoPhaseCheck contract
// has no DetectURLs() round-trip.
type StoredXSSState struct {
	mu           sync.Mutex
	plantedSinks map[sinkKey]struct{}
	canaries     map[string]*storedXSSPlant
	detectFired  map[sinkKey]struct{}
}

// canaryRe matches the wire form NewCanary mints: the fixed prefix
// plus 12 lowercase hex chars. Detect uses this to extract every
// plant-shaped token from a re-fetched body in one pass.
var canaryRe = regexp.MustCompile(`hpzc[0-9a-f]{12}`)

// PlantOnce records a first-time plant for the (method, url, loc,
// name) composite. Returns true when this is the first observation
// of the sink across all pages in the scan; false when an earlier
// Plant call already covered it. The Lua-side check should skip the
// payload fanout on a false return.
func (s *StoredXSSState) PlantOnce(method, url, loc, name string) bool {
	k := sinkKey{method: method, url: url, loc: loc, name: name}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.plantedSinks == nil {
		s.plantedSinks = map[sinkKey]struct{}{}
	}
	if _, dup := s.plantedSinks[k]; dup {
		return false
	}
	s.plantedSinks[k] = struct{}{}
	return true
}

// RecordCanary stashes a (canary -> plant record) entry. Detect
// later consults this map for every canary-shaped match in a re-
// fetched body.
func (s *StoredXSSState) RecordCanary(canary, method, url, loc, name, sinkValue, payload, payloadName, payloadCtx, plantURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canaries == nil {
		s.canaries = map[string]*storedXSSPlant{}
	}
	s.canaries[canary] = &storedXSSPlant{
		sink:        sinkKey{method: method, url: url, loc: loc, name: name},
		sinkValue:   sinkValue,
		payload:     payload,
		payloadName: payloadName,
		payloadCtx:  payloadCtx,
		plantURL:    plantURL,
	}
}

// LookupCanary returns the plant record for canary, or nil when the
// token never made it into the recorded map (an unrelated hpzc-shaped
// string in a body the check did not plant).
func (s *StoredXSSState) LookupCanary(canary string) *storedXSSPlant {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canaries == nil {
		return nil
	}
	return s.canaries[canary]
}

// harvestPlantResponseURLs walks the same-origin URLs surfaced in a
// plant response - Location header (the POST-redirect-GET destination
// most write endpoints return) plus body links the application
// rendered in the immediate response - and hands each to emit. Cross-
// origin URLs are dropped here so an unrelated CDN reference in a
// 200 body does not get added to the re-fetch list. Pure helper; no
// scan state is mutated, so callers can route the emitted URLs
// wherever (the post-fold path pushes them at TierDeferred via
// core.DiscoverAt).
func harvestPlantResponseURLs(plantURL, locationHeader string, body []byte, emit func(string)) {
	base, err := url.Parse(plantURL)
	if err != nil {
		return
	}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			return
		}
		if !strings.EqualFold(resolved.Host, base.Host) {
			return
		}
		resolved.Fragment = ""
		emit(resolved.String())
	}
	if locationHeader != "" {
		add(locationHeader)
	}
	if len(body) > 0 {
		harvestBodyLinks(body, add)
	}
}

// DetectFireOnce records the (method, url, loc, name) sink as having
// produced a finding on this scan; returns true when this call is
// the first to fire it. Cross-call dedupe so two different detect
// pages that both render the same stored payload do not double-
// report.
func (s *StoredXSSState) DetectFireOnce(method, url, loc, name string) bool {
	k := sinkKey{method: method, url: url, loc: loc, name: name}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.detectFired == nil {
		s.detectFired = map[sinkKey]struct{}{}
	}
	if _, dup := s.detectFired[k]; dup {
		return false
	}
	s.detectFired[k] = struct{}{}
	return true
}

// harvestBodyLinks tokenises body and feeds add() with every
// navigable same-origin URL it finds: <a href>, <form action>, and
// the url= field inside <meta http-equiv="refresh">. Other link
// sources (img / script src, link rel) are intentionally skipped;
// the goal is to find pages where stored content might be rendered,
// not every asset.
func harvestBodyLinks(body []byte, add func(string)) {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				return
			}
			return
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		switch string(name) {
		case "a":
			for {
				k, v, more := z.TagAttr()
				if string(k) == "href" {
					add(string(v))
				}
				if !more {
					break
				}
			}
		case "form":
			for {
				k, v, more := z.TagAttr()
				if string(k) == "action" {
					add(string(v))
				}
				if !more {
					break
				}
			}
		case "meta":
			var equiv, content string
			for {
				k, v, more := z.TagAttr()
				switch string(k) {
				case "http-equiv":
					equiv = string(v)
				case "content":
					content = string(v)
				}
				if !more {
					break
				}
			}
			if strings.EqualFold(equiv, "refresh") {
				if u := parseMetaRefreshURL(content); u != "" {
					add(u)
				}
			}
		}
	}
}

// parseMetaRefreshURL extracts the url= field from a meta-refresh
// content attribute. The shape is "N; url=DEST" where N is a seconds
// count and url= is case-insensitive.
func parseMetaRefreshURL(content string) string {
	for _, part := range strings.Split(content, ";") {
		part = strings.TrimSpace(part)
		if len(part) < 4 {
			continue
		}
		if strings.EqualFold(part[:4], "url=") {
			return strings.Trim(part[4:], `"' `)
		}
	}
	return ""
}

// storedXSSStateUserData wraps *StoredXSSState. Pointer wrap so the
// Lua userdata and the LuaCheck aux entry share identity; modifying
// the state through Lua mutates the same struct DetectURLs reads
// from later.
type storedXSSStateUserData struct {
	s *StoredXSSState
}

func storedXSSStateFn(L *lua.LState) int {
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("ctx.stored_xss.state called outside a check run")
	}
	state := env.Check.AuxOrCreate(storedXSSStateKey{}, func() any {
		return &StoredXSSState{}
	}).(*StoredXSSState)
	ud := L.NewUserData()
	ud.Value = &storedXSSStateUserData{s: state}
	ud.Metatable = ensureStoredXSSStateMT(L)
	L.Push(ud)
	return 1
}

func storedXSSNewCanary(L *lua.LState) int {
	L.Push(lua.LString(NewCanary()))
	return 1
}

const mtStoredXSSState = "__hyperz_mt_stored_xss_state"

func ensureStoredXSSStateMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtStoredXSSState).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("plant_once", L.NewFunction(storedXSSStatePlantOnce))
	methods.RawSetString("record_canary", L.NewFunction(storedXSSStateRecordCanary))
	methods.RawSetString("lookup_canary", L.NewFunction(storedXSSStateLookupCanary))
	methods.RawSetString("absorb_detect_urls", L.NewFunction(storedXSSStateAbsorbDetectURLs))
	methods.RawSetString("detect_fire_once", L.NewFunction(storedXSSStateDetectFireOnce))
	methods.RawSetString("find_canaries", L.NewFunction(storedXSSStateFindCanaries))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtStoredXSSState, mt)
	return mt
}

func storedXSSStateFromArg(L *lua.LState, pos int) *StoredXSSState {
	v := L.CheckUserData(pos).Value
	w, ok := v.(*storedXSSStateUserData)
	if !ok {
		L.ArgError(pos, "expected stored_xss state userdata")
	}
	return w.s
}

func storedXSSStatePlantOnce(L *lua.LState) int {
	s := storedXSSStateFromArg(L, 1)
	method := RequireString(L, 2)
	urlStr := RequireString(L, 3)
	loc := RequireString(L, 4)
	name := RequireString(L, 5)
	L.Push(lua.LBool(s.PlantOnce(method, urlStr, loc, name)))
	return 1
}

func storedXSSStateRecordCanary(L *lua.LState) int {
	s := storedXSSStateFromArg(L, 1)
	canary := RequireString(L, 2)
	opts := L.CheckTable(3)
	s.RecordCanary(
		canary,
		lvalString(opts.RawGetString("method")),
		lvalString(opts.RawGetString("url")),
		lvalString(opts.RawGetString("loc")),
		lvalString(opts.RawGetString("name")),
		lvalString(opts.RawGetString("value")),
		lvalString(opts.RawGetString("payload")),
		lvalString(opts.RawGetString("payload_name")),
		lvalString(opts.RawGetString("payload_ctx")),
		lvalString(opts.RawGetString("plant_url")),
	)
	return 0
}

func storedXSSStateLookupCanary(L *lua.LState) int {
	s := storedXSSStateFromArg(L, 1)
	token := RequireString(L, 2)
	p := s.LookupCanary(token)
	if p == nil {
		L.Push(lua.LNil)
		return 1
	}
	out := L.NewTable()
	out.RawSetString("method", lua.LString(p.sink.method))
	out.RawSetString("url", lua.LString(p.sink.url))
	out.RawSetString("loc", lua.LString(p.sink.loc))
	out.RawSetString("name", lua.LString(p.sink.name))
	out.RawSetString("value", lua.LString(p.sinkValue))
	out.RawSetString("payload", lua.LString(p.payload))
	out.RawSetString("payload_name", lua.LString(p.payloadName))
	out.RawSetString("payload_ctx", lua.LString(p.payloadCtx))
	out.RawSetString("plant_url", lua.LString(p.plantURL))
	L.Push(out)
	return 1
}

// storedXSSStateAbsorbDetectURLs harvests same-origin URLs from the
// plant response and emits each as a KindPage discovery at
// TierDeferred via core.DiscoverAt. The scanner's per-check
// Discoverer pushes them into the worklist; the barrier guarantees
// they receive only the Detect pass (not a fresh Plant).
//
// Receiver `s` is unused on the state itself - the URL harvest is a
// pure transform on the plant response - but the method is kept on
// the state userdata so existing Lua call sites
// (`state:absorb_detect_urls(...)`) continue to work without
// touching the Lua-level surface.
func storedXSSStateAbsorbDetectURLs(L *lua.LState) int {
	_ = storedXSSStateFromArg(L, 1)
	env := CurrentEnv(L)
	if env == nil {
		L.RaiseError("absorb_detect_urls called outside a check run")
	}
	plantURL := RequireString(L, 2)
	loc := optString(L, 3, "")
	body := optString(L, 4, "")
	harvestPlantResponseURLs(plantURL, loc, []byte(body), func(u string) {
		core.DiscoverAt(env.Ctx, target.Page(u, ""), core.TierDeferred)
	})
	return 0
}

func storedXSSStateDetectFireOnce(L *lua.LState) int {
	s := storedXSSStateFromArg(L, 1)
	method := RequireString(L, 2)
	urlStr := RequireString(L, 3)
	loc := RequireString(L, 4)
	name := RequireString(L, 5)
	L.Push(lua.LBool(s.DetectFireOnce(method, urlStr, loc, name)))
	return 1
}

func storedXSSStateFindCanaries(L *lua.LState) int {
	_ = storedXSSStateFromArg(L, 1)
	body := RequireString(L, 2)
	L.Push(PushStringList(L, canaryRe.FindAllString(body, -1)))
	return 1
}

func init() {
	RegisterHelperTable("stored_xss", buildStoredXSSTable)
}
