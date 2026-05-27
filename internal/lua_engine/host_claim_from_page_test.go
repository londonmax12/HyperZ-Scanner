package lua_engine

import (
	"context"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// claimFromPageProbe is the inline Lua module the host-claim tests
// reuse. It calls ctx.host:claim_from_page exactly once and emits the
// host_root as the finding's detail (or "FAIL" with the ok bit set).
// Going through the full Run path exercises the same wiring real
// checks see - the helper is not poked via a Go-side bypass.
const claimFromPageProbe = `
local check = {
  name  = "claim-probe",
  level = levels.passive,
  scope = scopes.host,
}

function check.run(ctx)
  local host_root, ok = ctx.host:claim_from_page()
  return {{
    severity = severity.info,
    title    = "claim-probe",
    detail   = (ok and host_root or "FAIL"),
  }}
end

return check
`

func TestClaimFromPage_Success(t *testing.T) {
	c, err := Load("claim-probe.lua", []byte(claimFromPageProbe))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/some/path?q=1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findings[0].Detail != "https://example.com" {
		t.Errorf("first claim Detail = %q, want %q", findings[0].Detail, "https://example.com")
	}

	// Second Run on a sibling page on the same host should reject -
	// claim_once already burned the slot for this LuaCheck instance.
	findings, err = c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/other"})
	if err != nil {
		t.Fatalf("Run (second): %v", err)
	}
	if findings[0].Detail != "FAIL" {
		t.Errorf("second claim Detail = %q, want FAIL (claim_once should reject the repeat)", findings[0].Detail)
	}
}

func TestClaimFromPage_MalformedURL(t *testing.T) {
	c, err := Load("claim-probe.lua", []byte(claimFromPageProbe))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// A bare path with no scheme / host is what crawler-emitted pages
	// look like when the upstream URL was unparseable. The helper
	// should reject without claiming so subsequent valid pages still
	// get a chance.
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: "/oops-no-scheme"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findings[0].Detail != "FAIL" {
		t.Errorf("malformed-URL Detail = %q, want FAIL", findings[0].Detail)
	}
	// Confirm the slot wasn't burned: a valid URL afterwards should
	// still claim successfully.
	findings, err = c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run (recovery): %v", err)
	}
	if findings[0].Detail != "https://example.com" {
		t.Errorf("recovery Detail = %q, want host_root", findings[0].Detail)
	}
}

func TestClaimFromPage_ScopeDeny(t *testing.T) {
	c, err := Load("claim-probe.lua", []byte(claimFromPageProbe))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Build a scope pinned to example.org so the probe's example.com
	// page is outside the allowlist.
	sc, err := scope.New(scope.Config{Hosts: []string{"example.org"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := c.Run(context.Background(), nil, sc, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findings[0].Detail != "FAIL" {
		t.Errorf("scope-deny Detail = %q, want FAIL", findings[0].Detail)
	}
}
