package lua_engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// fetchProbe is the inline check the client:fetch tests reuse. It runs
// fetch() once against ctx.config.url with the headers / body_cap the
// test supplies, then emits one finding whose Detail encodes the
// (status, body, err) tuple as "status=...|body=...|err=...". Running
// through Run gives us the same context plumbing real checks see,
// including the auto check-name-prefix the helper applies on error.
const fetchProbe = `
local check = {
  name  = "fetch-probe",
  level = levels.passive,
  scope = scopes.host,
}

function check.run(ctx)
  local opts = {
    method   = methods.get,
    url      = ctx.config.url or "",
    body_cap = ctx.config.body_cap or 0,
  }
  if ctx.config.body then opts.body = ctx.config.body end
  if ctx.config.headers then opts.headers = ctx.config.headers end
  local resp, body, err = ctx.client:fetch(opts)
  if err then
    return {{
      severity = severity.info,
      title    = "fetch-probe",
      detail   = "err=" .. err,
    }}
  end
  return {{
    severity = severity.info,
    title    = "fetch-probe",
    detail   = string.format("status=%d|body_len=%d|truncated=%s",
      resp:status(), #body, tostring(resp:truncated())),
  }}
end

return check
`

func loadFetchProbe(t *testing.T) *LuaCheck {
	t.Helper()
	c, err := Load("fetch-probe.lua", []byte(fetchProbe))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func newTestClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
}

// TestClientFetch_SuccessReadsBody covers the happy path: a 200 with
// a body shorter than the cap. fetch returns the full body and the
// response wrapper reports status=200, truncated=false.
func TestClientFetch_SuccessReadsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	c := loadFetchProbe(t)
	c.SetSettings(map[string]any{
		"url":      srv.URL + "/",
		"body_cap": 1024,
	})
	findings, err := c.Run(context.Background(), newTestClient(), nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := findings[0].Detail, "status=200|body_len=5|truncated=false"; got != want {
		t.Errorf("Detail = %q, want %q", got, want)
	}
}

// TestClientFetch_BodyCapZeroSkipsRead covers the headers-only path:
// body_cap=0 means "don't read body". The response status is still
// available; body length comes back zero.
func TestClientFetch_BodyCapZeroSkipsRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("this body should be ignored"))
	}))
	defer srv.Close()

	c := loadFetchProbe(t)
	c.SetSettings(map[string]any{
		"url":      srv.URL + "/",
		"body_cap": 0,
	})
	findings, err := c.Run(context.Background(), newTestClient(), nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := findings[0].Detail, "status=418|body_len=0|truncated=false"; got != want {
		t.Errorf("Detail = %q, want %q", got, want)
	}
}

// TestClientFetch_ErrorIsCheckNamePrefixed asserts the contract every
// Lua caller now relies on: fetch's err return already carries the
// check name as a prefix, so the per-error `return nil, "<name>: " .. err`
// boilerplate the catalog used to write is no longer needed. A bad
// URL is the cheapest trigger.
func TestClientFetch_ErrorIsCheckNamePrefixed(t *testing.T) {
	c := loadFetchProbe(t)
	c.SetSettings(map[string]any{
		"url":      "", // empty URL trips fetch's missing-url fail path
		"body_cap": 0,
	})
	findings, err := c.Run(context.Background(), newTestClient(), nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.HasPrefix(findings[0].Detail, "err=fetch-probe: ") {
		t.Errorf("err did not carry the check-name prefix; Detail = %q", findings[0].Detail)
	}
	if !strings.Contains(findings[0].Detail, "missing url") {
		t.Errorf("err should carry the underlying missing-url message; Detail = %q", findings[0].Detail)
	}
}
