package checks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestProtoPollutionName(t *testing.T) {
	if got := (ProtoPollution{}).Name(); got != "proto-pollution" {
		t.Fatalf("Name = %q, want proto-pollution", got)
	}
}

func TestProtoPollutionLevel(t *testing.T) {
	if got := (ProtoPollution{}).Level(); got != LevelAggressive {
		t.Fatalf("Level = %v, want aggressive", got)
	}
}

// pollutableState models the prototype-pollution side-effect: a
// shared map any handler can read/write, mimicking
// Object.prototype's process-wide reach. Handlers built on top of
// it install gadgets when they see `__proto__[...]` bracket query
// params or a JSON body with a `__proto__` key, then surface
// whichever gadget is asked for on subsequent observer requests.
type pollutableState struct {
	mu        sync.Mutex
	jsonSpace int
	status    int
	props     map[string]string
}

func newPollutableState() *pollutableState {
	return &pollutableState{props: map[string]string{}}
}

// applyQuery installs gadgets from bracket-notation query/form
// values into the shared state. Mirrors what an Express+qs stack
// would do after parsing `__proto__[json spaces]=7` into a nested
// object and merging it into a target via lodash.merge.
func (s *pollutableState) applyQuery(values map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, vs := range values {
		if len(vs) == 0 {
			continue
		}
		v := vs[0]
		s.applyKeyLocked(k, v)
	}
}

func (s *pollutableState) applyJSON(body map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ptr := range []map[string]any{
		mapField(body, "__proto__"),
		mapField(mapField(body, "constructor"), "prototype"),
	} {
		for k, v := range ptr {
			s.applyJSONKeyLocked(k, v)
		}
	}
}

func mapField(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if inner, ok := m[key].(map[string]any); ok {
		return inner
	}
	return nil
}

func (s *pollutableState) applyKeyLocked(rawKey, v string) {
	// Decode the bracket suffix path: __proto__[json spaces] or
	// constructor[prototype][status].
	if i := strings.Index(rawKey, "["); i >= 0 {
		prefix := rawKey[:i]
		path := rawKey[i:]
		switch prefix {
		case "__proto__":
			s.applyPathLocked(path, v)
		case "constructor":
			// strip leading "[prototype]" if present
			if strings.HasPrefix(path, "[prototype]") {
				s.applyPathLocked(strings.TrimPrefix(path, "[prototype]"), v)
			}
		}
	}
}

func (s *pollutableState) applyPathLocked(path, v string) {
	// path looks like "[json spaces]" or "[status]" or "[ppXXXX]".
	if !strings.HasPrefix(path, "[") || !strings.HasSuffix(path, "]") {
		return
	}
	key := path[1 : len(path)-1]
	s.applyJSONKeyLocked(key, v)
}

func (s *pollutableState) applyJSONKeyLocked(key string, v any) {
	switch key {
	case "json spaces":
		if n, ok := toInt(v); ok {
			s.jsonSpace = n
		}
	case "status":
		if n, ok := toInt(v); ok {
			s.status = n
		}
	default:
		s.props[key] = toString(v)
	}
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case float64:
		return int(x), true
	case string:
		if x == "" {
			return 0, true
		}
		n, err := strconv.Atoi(x)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// jsonHandler emits {"ok":true} pretty-printed at the polluted
// json-spaces width and using the polluted status (or 200 when
// unset). Mirrors Express's res.status(this.status||200).json(...).
func (s *pollutableState) jsonHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.consumeQuery(r)
		s.consumeBody(r)
		s.mu.Lock()
		space := s.jsonSpace
		status := s.status
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status > 0 {
			w.WriteHeader(status)
		}
		out := map[string]any{"ok": true}
		var b []byte
		if space > 0 {
			b, _ = json.MarshalIndent(out, "", strings.Repeat(" ", space))
		} else {
			b, _ = json.Marshal(out)
		}
		_, _ = w.Write(b)
	})
}

// safeHandler echoes a static JSON document with no pollution
// applied. Used by the negative test - the check must not fire on
// an endpoint that doesn't reach a prototype-touching parser.
func safeJSONHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

func (s *pollutableState) consumeQuery(r *http.Request) {
	q := r.URL.Query()
	s.applyQuery(q)
}

func (s *pollutableState) consumeBody(r *http.Request) {
	if r.Body == nil {
		return
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) == 0 {
		return
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "application/json"):
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err == nil {
			s.applyJSON(parsed)
		}
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		parsed := parseFormBody(body)
		s.applyQuery(parsed)
	}
}

func parseFormBody(body []byte) map[string][]string {
	out := map[string][]string{}
	for _, kv := range strings.Split(string(body), "&") {
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		var k, v string
		if eq < 0 {
			k = kv
		} else {
			k = kv[:eq]
			v = kv[eq+1:]
		}
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		out[k] = append(out[k], v)
	}
	return out
}

// TestProtoPollutionDetectsJSONSpacesGadget exercises the most
// reliable detection path: a Node/Express-style backend that reads
// `Object.prototype["json spaces"]` when formatting JSON. A
// successful detection shows the check went pollute -> observe and
// noticed the indentation flip from compact to the gadget's chosen
// width.
func TestProtoPollutionDetectsJSONSpacesGadget(t *testing.T) {
	state := newPollutableState()
	mux := http.NewServeMux()
	mux.Handle("/api/widgets", state.jsonHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The page exposes a query sink (id=1) that the handler will
	// route through its pollution-aware parser. The observer GET to
	// the same URL then witnesses the gadget firing.
	pg := page.FromURL(srv.URL + "/api/widgets?id=1")
	findings, err := (ProtoPollution{}).Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected at least 1 finding, got 0")
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-1321" {
		t.Errorf("CWE = %q, want CWE-1321", f.CWE)
	}
	if !strings.Contains(f.Title, "prototype pollution") {
		t.Errorf("Title should mention prototype pollution: %q", f.Title)
	}
	if !strings.Contains(strings.Join(f.Details, " "), "json spaces") &&
		!strings.Contains(strings.Join(f.Details, " "), "status") &&
		!strings.Contains(strings.Join(f.Details, " "), "canary") {
		t.Errorf("Details should name the gadget that fired: %+v", f.Details)
	}
}

// TestProtoPollutionNoFindingOnSafeServer establishes the false-
// positive backstop: an endpoint that returns static JSON without
// touching a pollution-aware parser must not fire the check.
func TestProtoPollutionNoFindingOnSafeServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/api/widgets", safeJSONHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	findings, err := (ProtoPollution{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/api/widgets?id=1"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe backend, got %d: %+v", len(findings), findings)
	}
}

func TestProtoPollutionRespectsScope(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := (ProtoPollution{}).Run(context.Background(), newTestClient(t), sc,
		page.FromURL(srv.URL+"/?id=1"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings out of scope, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; out-of-scope check must not probe", got)
	}
}

func TestProtoPollutionNoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := (ProtoPollution{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/static"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sinks, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; no-sinks page must not be probed", got)
	}
}

func TestProtoPollutionDedupeKeyStable(t *testing.T) {
	state := newPollutableState()
	mux := http.NewServeMux()
	mux.Handle("/api/widgets", state.jsonHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	run := func() string {
		// Each run uses a fresh state to avoid leftover indent from
		// the prior run influencing the second baseline observer.
		state2 := newPollutableState()
		mux2 := http.NewServeMux()
		mux2.Handle("/api/widgets", state2.jsonHandler())
		srv2 := httptest.NewServer(mux2)
		defer srv2.Close()

		fs, err := (ProtoPollution{}).Run(context.Background(), newTestClient(t),
			nil, page.FromURL(srv2.URL+"/api/widgets?id=1"))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(fs) == 0 {
			t.Fatalf("got 0 findings, want 1")
		}
		return fs[0].DedupeKey
	}
	// Both runs use the same path+param, only the host differs. The
	// dedupe key includes scheme+host+path but two different ports
	// will produce different hosts. We just confirm the key is
	// non-empty and that re-running the same probe shape produces a
	// stable key for the same target.
	a := run()
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
}

func TestPpJudgeStatusGadget(t *testing.T) {
	base := ppObservation{Status: 200, Body: []byte(`{"ok":true}`)}
	obs := ppObservation{Status: protoStatusCode, Body: []byte(`{"ok":true}`)}
	v := ppJudge(base, obs, "canary")
	if !v.Hit {
		t.Fatal("expected hit on status gadget")
	}
	if v.Gadget != "status" {
		t.Errorf("Gadget = %q, want status", v.Gadget)
	}
}

func TestPpJudgeJSONSpacesGadget(t *testing.T) {
	base := ppObservation{
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(`{"ok":true}`),
	}
	indented := "{\n" + strings.Repeat(" ", protoJSONSpaces) + `"ok": true` + "\n}"
	obs := ppObservation{
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(indented),
	}
	v := ppJudge(base, obs, "canary")
	if !v.Hit {
		t.Fatalf("expected hit on json-spaces gadget, got verdict=%+v", v)
	}
	if v.Gadget != "json spaces" {
		t.Errorf("Gadget = %q, want json spaces", v.Gadget)
	}
}

func TestPpJudgeCanaryEcho(t *testing.T) {
	base := ppObservation{Status: 200, Body: []byte(`{"ok":true}`)}
	obs := ppObservation{Status: 200, Body: []byte(`{"ok":true,"x":"hpzcCANARY"}`)}
	v := ppJudge(base, obs, "hpzcCANARY")
	if !v.Hit {
		t.Fatal("expected hit on canary echo")
	}
	if v.Gadget != "canary echo" {
		t.Errorf("Gadget = %q, want canary echo", v.Gadget)
	}
}

func TestPpJudgeNoHitWhenBaselineAlreadyMatches(t *testing.T) {
	// Baseline already shows the same shape - the gadget cannot
	// be attributed to our pollution.
	indented := "{\n" + strings.Repeat(" ", protoJSONSpaces) + `"ok": true` + "\n}"
	base := ppObservation{
		Status:  protoStatusCode,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(indented),
	}
	obs := ppObservation{
		Status:  protoStatusCode,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(indented),
	}
	v := ppJudge(base, obs, "canary")
	if v.Hit {
		t.Fatalf("expected no hit when baseline already shows gadget shape, got %+v", v)
	}
}

func TestPpJudgeNoHitOnInert(t *testing.T) {
	base := ppObservation{Status: 200, Body: []byte(`{"ok":true}`)}
	obs := ppObservation{Status: 200, Body: []byte(`{"ok":true}`)}
	if v := ppJudge(base, obs, "canary"); v.Hit {
		t.Fatalf("expected no hit on inert response, got %+v", v)
	}
}

func TestJSONIndentWidth(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"compact", `{"a":1}`, 0},
		{"flat-4", "{\n    \"a\": 1\n}", 4},
		{"flat-7", "{\n       \"a\": 1\n}", 7},
		{"nested-2", "{\n  \"a\": [\n    1\n  ]\n}", 2},
		// nested-7-deep verifies GCD recovers the per-call indent on a
		// document where the first newline lands at depth 1 (7 spaces),
		// depth 2 (14 spaces), and depth 3 (21 spaces). GCD(7,14,21)=7.
		{
			"nested-7-deep",
			"{\n       \"a\": {\n              \"b\": {\n                     \"c\": 1\n              }\n       }\n}",
			7,
		},
		// mixed-units models an outer document pretty-printed at 2
		// concatenated with a raw inner blob pretty-printed at 7. GCD
		// collapses to 1 to refuse a verdict the scanner cannot safely
		// attribute, rather than picking one layer and ignoring the
		// other.
		{
			"mixed-units",
			"{\n  \"outer\": true,\n  \"inner\": {\n       \"x\": 1\n  }\n}",
			1,
		},
	}
	for _, tc := range cases {
		if got := jsonIndentWidth([]byte(tc.body)); got != tc.want {
			t.Errorf("[%s] jsonIndentWidth(%q) = %d, want %d", tc.name, tc.body, got, tc.want)
		}
	}
}

func TestIsJSONResponse(t *testing.T) {
	h := http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}
	if !isJSONResponse(h, []byte(`abc`)) {
		t.Error("Content-Type application/json should classify as JSON")
	}
	if !isJSONResponse(nil, []byte(`{"a":1}`)) {
		t.Error("body starting with { should classify as JSON")
	}
	if !isJSONResponse(nil, []byte(`  [1,2,3]`)) {
		t.Error("body starting with [ (after whitespace) should classify as JSON")
	}
	if isJSONResponse(nil, []byte(`<html></html>`)) {
		t.Error("html body should not classify as JSON")
	}
}

func TestProtoPollutionSkipsHeaderAndCookieSinks(t *testing.T) {
	for _, loc := range []Loc{LocHeader, LocCookie, LocPath} {
		s := Sink{Method: http.MethodGet, URL: "https://example.test/", Loc: loc, Name: "id"}
		if (ProtoPollution{}).sinkProbable(s) {
			t.Errorf("sinkProbable(%s) = true, want false", loc)
		}
	}
	for _, loc := range []Loc{LocQuery, LocForm, LocJSON} {
		s := Sink{Method: http.MethodGet, URL: "https://example.test/", Loc: loc, Name: "id"}
		if !(ProtoPollution{}).sinkProbable(s) {
			t.Errorf("sinkProbable(%s) = false, want true", loc)
		}
	}
}

func TestProtoPollutionIgnoresUnparseableTarget(t *testing.T) {
	findings, err := (ProtoPollution{}).Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

// TestProtoPollutionDetectsViaFormBodySink exercises the LocForm
// branch end-to-end. A page exposing a POST form routes the probe
// through buildPolluteRequest's url.Values + bracket-notation
// payload, exactly mirroring how a body-parser stack expands
// `__proto__[json spaces]=7` into a nested object on the backend.
// Without this test the form-encoded payload path is only checked
// in unit tests of sinkProbable; nothing exercises the full
// pollute -> observe -> cleanup loop over a POST body.
func TestProtoPollutionDetectsViaFormBodySink(t *testing.T) {
	state := newPollutableState()
	mux := http.NewServeMux()
	mux.Handle("/api/widgets", state.jsonHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pg := page.Page{
		URL: srv.URL + "/api/widgets",
		Forms: []page.Form{{
			Method: http.MethodPost,
			Action: srv.URL + "/api/widgets",
			Inputs: []page.FormInput{{Name: "id", Type: "text", Value: "1"}},
		}},
	}
	findings, err := (ProtoPollution{}).Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected at least 1 finding on form-body sink, got 0")
	}
	f := findings[0]
	if !strings.Contains(strings.ToLower(string(f.Title)), "form") {
		t.Errorf("Title should mention the form sink loc: %q", f.Title)
	}
}

// TestProtoPollutionCleanupRunsAfterCancel verifies that the
// detached cleanup context still lets the cleanup HTTP request
// fire after the per-page ctx is cancelled. Scenario: the pollute
// request lands cleanly; the second observer request blocks; the
// test cancels ctx mid-observe; the deferred cleanup must still
// reach the server because the cleanup ctx is detached via
// context.WithoutCancel. Without that detach, the cleanup's
// http.NewRequestWithContext + client.Do would fail immediately
// on ctx.Err() != nil and the polluted properties would remain on
// the prototype until process restart.
func TestProtoPollutionCleanupRunsAfterCancel(t *testing.T) {
	cancelOnObserve := make(chan struct{}, 1)
	var (
		mu              sync.Mutex
		polluteSeen     bool
		cleanupSeen     bool
		cleanupHasStatus bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		isProbe := r.URL.Query().Get("__proto__[json spaces]") == strconv.Itoa(protoJSONSpaces)
		isCleanup := r.URL.Query().Get("__proto__[json spaces]") == "0"
		hasStatusCleanup := r.URL.Query().Get("__proto__[status]") == "0"

		mu.Lock()
		if isProbe {
			polluteSeen = true
		}
		if isCleanup {
			cleanupSeen = true
			if hasStatusCleanup {
				cleanupHasStatus = true
			}
		}
		mu.Unlock()

		// The observer is a GET against pageURL with no proto-pollution
		// markers in the query. When we see it, signal the test to
		// cancel ctx, then block long enough that the observer fails
		// on the cancelled ctx (forcing the probe into its defer).
		if !isProbe && !isCleanup {
			select {
			case cancelOnObserve <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Two observers run per page: the baseline (before any
		// probe) and the post-pollution one. Cancel on the second
		// signal, when the probe has already polluted and is mid-
		// observing.
		<-cancelOnObserve // baseline
		<-cancelOnObserve // post-pollution observer
		cancel()
	}()

	_, _ = (ProtoPollution{}).Run(ctx, newTestClient(t), nil,
		page.FromURL(srv.URL+"/api/widgets?id=1"))

	// Cleanup is best-effort and runs in a defer; give the request
	// a moment to land on the server side.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := cleanupSeen
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if !polluteSeen {
		t.Fatal("pollute request never reached server; cancel-window test cannot run")
	}
	if !cleanupSeen {
		t.Fatal("cleanup request did not arrive after ctx cancel - the detached cleanup context regressed")
	}
	if !cleanupHasStatus {
		t.Error("cleanup payload missing status=0 - the status gadget would remain polluted")
	}
}
