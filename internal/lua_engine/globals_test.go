package lua_engine

import (
	"context"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// TestConstGlobalsReachLua walks every entry buildConstGlobals returns
// and asserts the Lua side sees exactly the same (key, value) on the
// matching global table. Catches:
//
//   - A new constTable added in buildConstGlobals that the installer
//     forgot to wire onto the globals (installConstGlobals iterates
//     the same slice, so this is mostly a regression guard).
//   - A typo in the Lua-side identifier (`cms.wrdpress`) that would
//     surface as `nil` at the use site - the test asserts the value
//     is the expected non-nil string/number.
//   - Future drift between the canonical wire form and what the
//     Lua-side global table holds (the values come straight from
//     SeverityCritical / target.KindPage / etc., so a renamed Go-side
//     constant would surface here as a value mismatch).
//
// One per-table assertion runs as a sub-test so a failure points at
// the exact (table, key) pair rather than burying every mismatch in
// one error line.
func TestConstGlobalsReachLua(t *testing.T) {
	tables := buildConstGlobals()
	if len(tables) == 0 {
		t.Fatalf("buildConstGlobals returned no tables")
	}

	// Lua chunk: for each (table, key) the test passes in, return the
	// string-or-number value the global table holds at that key. We
	// fold every check into one Run by encoding (table, key) pairs as
	// `tbl|key` tokens on the input string and emitting `value` tokens
	// on the output, joined with newlines.
	src := []byte(`
local check = {
  name  = "globals-probe",
  level = levels.passive,
  scope = scopes.host,
}

function check.run(ctx)
  local lookups = ctx.config.lookups or {}
  local rows = {}
  for _, lookup in ipairs(lookups) do
    local sep = string.find(lookup, "|", 1, true)
    local tbl_name = string.sub(lookup, 1, sep - 1)
    local key = string.sub(lookup, sep + 1)
    local tbl = _G[tbl_name]
    if tbl == nil then
      rows[#rows + 1] = "NIL-TABLE:" .. tbl_name
    else
      local v = tbl[key]
      if v == nil then
        rows[#rows + 1] = "NIL-VAL:" .. lookup
      else
        rows[#rows + 1] = tostring(v)
      end
    end
  end
  return {{
    severity = severity.info,
    title    = "globals-probe",
    detail   = table.concat(rows, "\n"),
  }}
end

return check
`)
	c, err := Load("globals-probe.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	type lookup struct {
		table string
		key   string
		want  string
	}
	var lookups []lookup
	for _, tbl := range tables {
		for _, e := range tbl.entries {
			lookups = append(lookups, lookup{
				table: tbl.name,
				key:   e.key,
				// gopher-lua's LValue.String() returns the same form
				// Lua's tostring() does: bare string for LString,
				// integer-or-float decimal for LNumber. Both match the
				// `tostring(v)` the Lua probe emits.
				want: e.val.String(),
			})
		}
	}

	// Encode lookups as `tbl|key` tokens for the Lua chunk to iterate.
	tokens := make([]any, 0, len(lookups))
	for _, lk := range lookups {
		tokens = append(tokens, lk.table+"|"+lk.key)
	}
	c.SetSettings(map[string]any{"lookups": tokens})

	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	rows := strings.Split(findings[0].Detail, "\n")
	if len(rows) != len(lookups) {
		t.Fatalf("rows = %d, want %d", len(rows), len(lookups))
	}
	for i, lk := range lookups {
		t.Run(lk.table+"/"+lk.key, func(t *testing.T) {
			if rows[i] != lk.want {
				t.Errorf("%s.%s = %q, want %q", lk.table, lk.key, rows[i], lk.want)
			}
		})
	}
}

// TestNoLeakageOfRemovedCtxConstantTables guards against accidentally
// re-attaching severity / scopes / levels / locs back to the ctx
// table. These vocabularies live as Lua globals now (see
// installConstGlobals); having them ALSO on ctx would re-open the two-
// conventions footgun the refactor was meant to close.
func TestNoLeakageOfRemovedCtxConstantTables(t *testing.T) {
	src := []byte(`
local check = {
  name  = "ctx-leak-probe",
  level = levels.passive,
  scope = scopes.host,
}

function check.run(ctx)
  local bad = {}
  for _, name in ipairs({"severity", "scopes", "levels", "locs", "tiers", "cms", "framework",
                         "server", "language", "cdn", "waf", "methods", "content_types",
                         "kinds", "body_caps"}) do
    if ctx[name] ~= nil then bad[#bad + 1] = name end
  end
  return {{
    severity = severity.info,
    title    = "ctx-leak-probe",
    detail   = table.concat(bad, ","),
  }}
end

return check
`)
	c, err := Load("ctx-leak-probe.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findings[0].Detail != "" {
		t.Fatalf("ctx leaks constant tables: %s (should be on _G only)", findings[0].Detail)
	}
}
