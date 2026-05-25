package checks_lua

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findProtoPollution(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "proto-pollution" {
			return c
		}
	}
	t.Fatal("proto-pollution Lua check not found")
	return nil
}

// pollutableMock mirrors the Go check's pollutableState test helper:
// a shared map any handler reads/writes, mimicking Object.prototype's
// process-wide reach. When a `__proto__[...]` query param or JSON
// body lands the gadget gets installed, and subsequent observer
// requests reflect it.
type pollutableMock struct {
	mu        sync.Mutex
	jsonSpace int
	status    int
	props     map[string]string
}

func newPollutableMock() *pollutableMock {
	return &pollutableMock{props: map[string]string{}}
}

func (s *pollutableMock) applyQuery(values map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, vs := range values {
		if len(vs) == 0 {
			continue
		}
		s.applyKeyLocked(k, vs[0])
	}
}

func (s *pollutableMock) applyJSON(body map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ptr := range []map[string]any{
		mockMapField(body, "__proto__"),
		mockMapField(mockMapField(body, "constructor"), "prototype"),
	} {
		for k, v := range ptr {
			s.applyJSONKeyLocked(k, v)
		}
	}
}

func mockMapField(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if inner, ok := m[key].(map[string]any); ok {
		return inner
	}
	return nil
}

func (s *pollutableMock) applyKeyLocked(rawKey, v string) {
	if i := strings.Index(rawKey, "["); i >= 0 {
		prefix := rawKey[:i]
		path := rawKey[i:]
		switch prefix {
		case "__proto__":
			s.applyPathLocked(path, v)
		case "constructor":
			if strings.HasPrefix(path, "[prototype]") {
				s.applyPathLocked(strings.TrimPrefix(path, "[prototype]"), v)
			}
		}
	}
}

func (s *pollutableMock) applyPathLocked(path, v string) {
	if !strings.HasPrefix(path, "[") || !strings.HasSuffix(path, "]") {
		return
	}
	key := path[1 : len(path)-1]
	s.applyJSONKeyLocked(key, v)
}

func (s *pollutableMock) applyJSONKeyLocked(key string, v any) {
	switch key {
	case "json spaces":
		if n, ok := mockToInt(v); ok {
			s.jsonSpace = n
		}
	case "status":
		if n, ok := mockToInt(v); ok {
			s.status = n
		}
	default:
		s.props[key] = mockToString(v)
	}
}

func mockToInt(v any) (int, bool) {
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

func mockToString(v any) string {
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

func (s *pollutableMock) consumeQuery(r *http.Request) {
	s.applyQuery(r.URL.Query())
}

func (s *pollutableMock) consumeBody(r *http.Request) {
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
		parsed := mockParseFormBody(body)
		s.applyQuery(parsed)
	}
}

func mockParseFormBody(body []byte) map[string][]string {
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
		if dk, err := mockQueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := mockQueryUnescape(v); err == nil {
			v = dv
		}
		out[k] = append(out[k], v)
	}
	return out
}

func mockQueryUnescape(s string) (string, error) {
	out := strings.ReplaceAll(s, "+", " ")
	return mockPercentDecode(out)
}

func mockPercentDecode(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}

func (s *pollutableMock) handler() http.Handler {
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

// reset clears the polluted state so a fresh probe run sees a clean
// baseline. The Go and Lua sides run sequentially on one server so
// the dedupe keys (which include scheme://host/path) match.
func (s *pollutableMock) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jsonSpace = 0
	s.status = 0
	s.props = map[string]string{}
}

// TestLuaProtoPollutionGadgetParity runs the Go check + Lua port
// sequentially against the same pollutable JSON endpoint, resetting
// state between runs. Sharing the server means the dedupe scope
// (scheme://host/path) is byte-identical so the resulting keys MUST
// match if both implementations use the same (loc, param) parts.
func TestLuaProtoPollutionGadgetParity(t *testing.T) {
	state := newPollutableMock()
	mux := http.NewServeMux()
	mux.Handle("/api/widgets", state.handler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pageURL := srv.URL + "/api/widgets?id=1"
	p := page.FromURL(pageURL)
	client := newTestClient(t)

	state.reset()
	goFs, err := (checks.ProtoPollution{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) == 0 {
		t.Fatalf("go: expected at least one finding, got 0")
	}
	goFinding := goFs[0]

	state.reset()
	luaCheck := findProtoPollution(t)
	luaFs, err := luaCheck.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) == 0 {
		t.Fatalf("lua: expected at least one finding, got 0")
	}
	luaFinding := luaFs[0]

	if goFinding.Severity != luaFinding.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goFinding.Severity, luaFinding.Severity)
	}
	if goFinding.CWE != luaFinding.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goFinding.CWE, luaFinding.CWE)
	}
	if goFinding.OWASP != luaFinding.OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goFinding.OWASP, luaFinding.OWASP)
	}
	if !strings.Contains(goFinding.Title, "prototype pollution") ||
		!strings.Contains(luaFinding.Title, "prototype pollution") {
		t.Errorf("title should mention prototype pollution\ngo=%q\nlua=%q",
			goFinding.Title, luaFinding.Title)
	}
	if goFinding.DedupeKey != luaFinding.DedupeKey {
		t.Errorf("dedupe key drift:\ngo=%q\nlua=%q", goFinding.DedupeKey, luaFinding.DedupeKey)
	}
}

// TestLuaProtoPollutionCleanPage asserts neither implementation fires
// on an endpoint that emits static JSON without touching any
// pollution-aware parser.
func TestLuaProtoPollutionCleanPage(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/api/widgets", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := page.FromURL(srv.URL + "/api/widgets?id=1")
	client := newTestClient(t)

	goFs, err := (checks.ProtoPollution{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d: %+v", len(goFs), goFs)
	}

	luaC := findProtoPollution(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d: %+v", len(luaFs), luaFs)
	}
}

// TestLuaProtoPollutionNoSinksNoProbes asserts both implementations
// skip an endpoint with no query / form / JSON sinks. The handler
// records hits; both implementations must produce zero traffic.
func TestLuaProtoPollutionNoSinksNoProbes(t *testing.T) {
	var hits sync.Mutex
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Lock()
		count++
		hits.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.FromURL(srv.URL + "/static")
	client := newTestClient(t)

	goFs, err := (checks.ProtoPollution{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d", len(goFs))
	}
	hits.Lock()
	count = 0
	hits.Unlock()

	luaC := findProtoPollution(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d", len(luaFs))
	}
	hits.Lock()
	got := count
	hits.Unlock()
	if got != 0 {
		t.Fatalf("server hit %d times; no-sinks page must not be probed", got)
	}
}
