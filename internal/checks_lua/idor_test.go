package checks_lua

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findIDOR(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "idor" {
			return c
		}
	}
	t.Fatal("idor Lua check not found")
	return nil
}

// vulnIDORHandlerLua duplicates the Go-side checks/idor_test fixture:
// an endpoint that returns each user's record for a small numeric
// user_id but 404s for obviously-out-of-range IDs. This shape lets the
// control probe (999999999999) reject while the tampered probes (41,
// 43) still find user content - the canonical IDOR signal idorJudge
// fires on.
func vulnIDORHandlerLua(reqCount *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(reqCount, 1)
		raw := r.URL.Query().Get("user_id")
		id, err := strconv.Atoi(raw)
		if err != nil || id < 0 || id > 100000 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": "user not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body := fmt.Sprintf(
			`{"id": %d, "first_name": "User%d", "email": "user%d@example.test", "address_line_1": "%d Main Street"}`,
			id, id, id, id,
		)
		body += strings.Repeat(" filler", 64)
		_, _ = w.Write([]byte(body))
	})
}

// TestLuaIDORDetectsVulnerableNumericParam locks in the IDOR-positive
// path on both impls: vulnerable handler => one High finding with
// CWE-639, byte-identical Severity / CWE / dedupe key across Go and
// Lua, and the Lua port surfacing the same high-confidence PII bullet
// the Go check does when the tampered body carries name/email fields.
func TestLuaIDORDetectsVulnerableNumericParamParity(t *testing.T) {
	var goReqs, luaReqs int32
	goSrv := httptest.NewServer(vulnIDORHandlerLua(&goReqs))
	defer goSrv.Close()
	luaSrv := httptest.NewServer(vulnIDORHandlerLua(&luaReqs))
	defer luaSrv.Close()

	goPg := page.FromURL(goSrv.URL + "/profile?user_id=42")
	luaPg := page.FromURL(luaSrv.URL + "/profile?user_id=42")

	goFs, err := (&checks.IDOR{}).Run(context.Background(), newTestClient(t), nil, goPg)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findIDOR(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, luaPg)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 1 || len(luaFs) != 1 {
		t.Fatalf("expected 1 finding each: go=%d lua=%d", len(goFs), len(luaFs))
	}
	if goFs[0].Severity != luaFs[0].Severity {
		t.Errorf("severity drift: go=%q lua=%q", goFs[0].Severity, luaFs[0].Severity)
	}
	if goFs[0].CWE != luaFs[0].CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goFs[0].CWE, luaFs[0].CWE)
	}
	if goFs[0].OWASP != luaFs[0].OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goFs[0].OWASP, luaFs[0].OWASP)
	}
	// Dedupe keys differ because the test servers run on different
	// ports, so the page URL differs. What we lock in is the SHAPE -
	// both impls must use scope=param + loc + param-name parts. We
	// rebuild the key from the same shape and assert each side matches
	// its own rebuild.
	wantGo := checks.MakeKey("idor", checks.ScopeParam, goPg.URL, "query", "user_id")
	wantLua := checks.MakeKey("idor", checks.ScopeParam, luaPg.URL, "query", "user_id")
	if goFs[0].DedupeKey != wantGo {
		t.Errorf("go dedupe key drift: got=%q want=%q", goFs[0].DedupeKey, wantGo)
	}
	if luaFs[0].DedupeKey != wantLua {
		t.Errorf("lua dedupe key drift: got=%q want=%q", luaFs[0].DedupeKey, wantLua)
	}
	if !strings.Contains(luaFs[0].Title, "user_id") {
		t.Errorf("lua title should name the param: %q", luaFs[0].Title)
	}
	// PII-marker => high confidence bullet on both impls.
	for label, fs := range map[string][]checks.Finding{"go": goFs, "lua": luaFs} {
		var confidence string
		for _, d := range fs[0].Details {
			if strings.HasPrefix(d, "confidence:") {
				confidence = d
			}
		}
		if !strings.Contains(confidence, "high") {
			t.Errorf("%s: expected high confidence bullet, got %q (all: %v)", label, confidence, fs[0].Details)
		}
	}
}

// TestLuaIDORDoesNotFireOnSPAFallbackParity locks in the false-positive
// backstop: an endpoint that returns the same shell for any URL must
// not produce a finding on either impl. baseline ~ control ~ tampered
// puts the verdict in the suppression branch.
func TestLuaIDORDoesNotFireOnSPAFallbackParity(t *testing.T) {
	shell := `<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>`
	shell += strings.Repeat(" filler", 64)
	mk := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(shell))
		}))
	}
	goSrv := mk()
	defer goSrv.Close()
	luaSrv := mk()
	defer luaSrv.Close()

	goFs, err := (&checks.IDOR{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(goSrv.URL+"/profile?user_id=42"))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findIDOR(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(luaSrv.URL+"/profile?user_id=42"))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 0 || len(luaFs) != 0 {
		t.Errorf("SPA fallback must produce 0 findings on both: go=%d lua=%d", len(goFs), len(luaFs))
	}
}

// TestLuaIDORSkipsDenylistedParamParity asserts both impls skip params
// on the denylist (search "q", pagination "page", auth tokens, ...).
// The handler would otherwise look IDOR-shaped on body variance, so a
// drift between impls here would surface immediately.
func TestLuaIDORSkipsDenylistedParamParity(t *testing.T) {
	mk := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			body := fmt.Sprintf("results for %s", r.URL.Query().Get("q"))
			body += strings.Repeat(" filler", 64)
			_, _ = w.Write([]byte(body))
		}))
	}
	goSrv := mk()
	defer goSrv.Close()
	luaSrv := mk()
	defer luaSrv.Close()

	goFs, err := (&checks.IDOR{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(goSrv.URL+"/search?q=alpha"))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findIDOR(t)
	luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(luaSrv.URL+"/search?q=alpha"))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 0 || len(luaFs) != 0 {
		t.Errorf("denylisted param must produce 0 findings on both: go=%d lua=%d", len(goFs), len(luaFs))
	}
}
