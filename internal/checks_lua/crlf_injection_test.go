package checks_lua

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findCRLFInjection(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "crlf-injection" {
			return c
		}
	}
	t.Fatal("crlf-injection Lua check not found")
	return nil
}

// vulnCRLFHijack reproduces a response-splitting handler: the `next`
// query param is spliced directly into the Location header via the
// raw connection so CR/LF survive intact (net/http would normally
// refuse such header values). terminator picks how the handler ends
// the spliced Location line.
func vulnCRLFHijack(t *testing.T, terminator string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatalf("test server does not support hijacking")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close()
		fmt.Fprintf(bufrw, "HTTP/1.1 302 Found\r\nLocation: %s%sContent-Length: 0\r\n\r\n", next, terminator)
		bufrw.Flush()
	})
}

// TestLuaCRLFInjectionParity locks in identical finding count + dedupe
// key + severity between the Go original and the Lua port against a
// hand-crafted hijacking handler that mimics the bug. Two scenarios:
// CRLF-split (server splices verbatim), and LF-only (server strips
// \r but lets \n through).
func TestLuaCRLFInjectionParity(t *testing.T) {
	luaC := findCRLFInjection(t)
	client := newTestClient(t)
	var sc *scope.Scope

	t.Run("crlf_split_detected", func(t *testing.T) {
		srv := httptest.NewServer(vulnCRLFHijack(t, "\r\n"))
		defer srv.Close()
		target := srv.URL + "/redirect?next=home"

		goFs, err := (checks.CRLFInjection{}).Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("go: %v", err)
		}
		luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("lua: %v", err)
		}
		if len(goFs) != len(luaFs) {
			t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
		}
		for i := range goFs {
			if goFs[i].DedupeKey != luaFs[i].DedupeKey {
				t.Errorf("dedupe drift: go=%q lua=%q", goFs[i].DedupeKey, luaFs[i].DedupeKey)
			}
			if goFs[i].Severity != luaFs[i].Severity {
				t.Errorf("severity drift: go=%q lua=%q", goFs[i].Severity, luaFs[i].Severity)
			}
		}
	})

	t.Run("safe_server_no_finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		target := srv.URL + "/x?next=home"

		goFs, err := (checks.CRLFInjection{}).Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("go: %v", err)
		}
		luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(target))
		if err != nil {
			t.Fatalf("lua: %v", err)
		}
		if len(goFs) != 0 || len(luaFs) != 0 {
			t.Fatalf("expected no findings: go=%d lua=%d", len(goFs), len(luaFs))
		}
	})
}
