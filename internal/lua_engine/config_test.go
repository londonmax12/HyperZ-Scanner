package lua_engine

import (
	"context"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// TestPerCheckSettingsReachLua verifies the full path from a Go-side
// settings bag (the YAML-loaded map[string]any) through SetSettings,
// through the per-Run ctx, into a Lua check that reads ctx.config.
//
// The test loads a tiny inline module that copies three settings
// fields into a finding's Detail. A nil bag is exercised first to
// confirm ctx.config is always present (an empty table) so Lua
// authors don't have to nil-guard before indexing.
func TestPerCheckSettingsReachLua(t *testing.T) {
	src := []byte(`
local check = {
  name  = "settings-probe",
  level = "passive",
  scope = "host",
}

function check.run(ctx)
  local out = {
    string.format("body_cap_bytes=%s", tostring(ctx.config.body_cap_bytes)),
    string.format("flag=%s", tostring(ctx.config.flag)),
    string.format("list=%s", tostring(ctx.config.list and ctx.config.list[2] or "")),
  }
  return {
    {
      severity = "info",
      title    = "settings-probe ran",
      detail   = table.concat(out, ";"),
    },
  }
end

return check
`)
	c, err := Load("settings-probe.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// First Run with no settings: ctx.config must be an empty table
	// so the nil-indexing pattern in the probe yields the string "nil".
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run (no settings): %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	want := "body_cap_bytes=nil;flag=nil;list="
	if findings[0].Detail != want {
		t.Errorf("no-settings Detail = %q, want %q", findings[0].Detail, want)
	}

	// Attach a bag and re-run. yaml.v3 normally decodes integers as
	// int and lists as []any; mirror that shape here so the test
	// matches the production data path.
	c.SetSettings(map[string]any{
		"body_cap_bytes": 32768,
		"flag":           true,
		"list":           []any{"a", "b", "c"},
	})
	findings, err = c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run (with settings): %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	want = "body_cap_bytes=32768;flag=true;list=b"
	if findings[0].Detail != want {
		t.Errorf("with-settings Detail = %q, want %q", findings[0].Detail, want)
	}
}

func TestCatalogAllSurfacesUnknownSettings(t *testing.T) {
	settings := map[string]map[string]any{
		"reflected-xss":           {"body_cap_bytes": 16384},
		"this-check-does-not-exist": {"foo": 1},
	}
	_, unknown := All(false, settings)
	found := false
	for _, name := range unknown {
		if name == "this-check-does-not-exist" {
			found = true
		}
	}
	if !found {
		t.Errorf("unknown = %v, want it to include 'this-check-does-not-exist'", unknown)
	}
	for _, name := range unknown {
		if name == "reflected-xss" {
			t.Errorf("reflected-xss should NOT be in unknown, but is")
		}
	}
}
