package lua_engine

import (
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/target"
)

// TestLuaCheckTierParses confirms every declared tier label maps onto
// the matching core.Tier and that omitting the field leaves Tier()
// at zero so the scanner's checkTier clamp can hand back TierActive.
func TestLuaCheckTierParses(t *testing.T) {
	cases := []struct {
		label string
		want  core.Tier
	}{
		{"fingerprint", core.TierFingerprint},
		{"passive", core.TierPassive},
		{"discovery", core.TierDiscovery},
		{"active", core.TierActive},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			src := []byte(`
local check = {
  name  = "tier-` + tc.label + `",
  level = "passive",
  scope = "host",
  tier  = "` + tc.label + `",
}

function check.run(ctx)
  return {}
end

return check
`)
			c, err := Load("tier.lua", src)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := c.Tier(); got != tc.want {
				t.Errorf("Tier() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLuaCheckTierOmittedDefaultsToZero pins the back-compat path:
// a check that does NOT declare `tier` leaves c.Tier() at the zero
// core.Tier, and the scanner's checkTier clamps that to TierActive.
// Tests that rely on legacy dispatch-as-active behavior keep working
// without the catalog being touched.
func TestLuaCheckTierOmittedDefaultsToZero(t *testing.T) {
	src := []byte(`
local check = {
  name  = "no-tier",
  level = "passive",
  scope = "host",
}

function check.run(ctx)
  return {}
end

return check
`)
	c, err := Load("no-tier.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Tier(); got != 0 {
		t.Errorf("omitted tier: Tier() = %v, want 0 (zero Tier; scanner clamps to TierActive)", got)
	}
}

// TestLuaCheckTierTypoIsLoadError pins the strict-typo contract: a
// misspelled tier label (e.g. "passsive") must fail Load rather than
// silently dispatch as TierActive. The same rule that catches typos
// in applies_to keys applies here.
func TestLuaCheckTierTypoIsLoadError(t *testing.T) {
	src := []byte(`
local check = {
  name  = "tier-typo",
  level = "passive",
  scope = "host",
  tier  = "passsive",
}

function check.run(ctx)
  return {}
end

return check
`)
	_, err := Load("typo.lua", src)
	if err == nil {
		t.Fatalf("Load must reject misspelled tier")
	}
	if !strings.Contains(err.Error(), "invalid tier") {
		t.Errorf("error %q should mention invalid tier", err.Error())
	}
}

// TestLuaCheckConsumesParsesArray pins the array form of `consumes`,
// which is the common shape for param-tampering checks that want
// dispatch on multiple kinds.
func TestLuaCheckConsumesParsesArray(t *testing.T) {
	src := []byte(`
local check = {
  name     = "consume-array",
  level    = "passive",
  scope    = "host",
  consumes = {"param", "endpoint"},
}

function check.run(ctx)
  return {}
end

return check
`)
	c, err := Load("consume-array.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	kinds := c.Consumes()
	if len(kinds) != 2 {
		t.Fatalf("Consumes len = %d, want 2", len(kinds))
	}
	if kinds[0] != target.KindParam || kinds[1] != target.KindEndpoint {
		t.Errorf("Consumes = %v, want [KindParam, KindEndpoint]", kinds)
	}
}

// TestLuaCheckConsumesParsesSingleString pins the single-string sugar
// (`consumes = "param"`), which keeps the metadata block readable
// for the common one-kind case.
func TestLuaCheckConsumesParsesSingleString(t *testing.T) {
	src := []byte(`
local check = {
  name     = "consume-sugar",
  level    = "passive",
  scope    = "host",
  consumes = "param",
}

function check.run(ctx)
  return {}
end

return check
`)
	c, err := Load("consume-sugar.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	kinds := c.Consumes()
	if len(kinds) != 1 || kinds[0] != target.KindParam {
		t.Errorf("Consumes = %v, want [KindParam]", kinds)
	}
}

// TestLuaCheckConsumesUnknownKindIsLoadError pins the strict-typo
// contract for consumes: an unknown kind label (e.g. "pages" instead
// of "page") fails Load rather than silently dropping the check from
// every dispatch.
func TestLuaCheckConsumesUnknownKindIsLoadError(t *testing.T) {
	src := []byte(`
local check = {
  name     = "consume-typo",
  level    = "passive",
  scope    = "host",
  consumes = {"pages"},
}

function check.run(ctx)
  return {}
end

return check
`)
	_, err := Load("consume-typo.lua", src)
	if err == nil {
		t.Fatalf("Load must reject unknown consumes kind")
	}
	if !strings.Contains(err.Error(), "invalid discover kind") {
		t.Errorf("error %q should mention invalid kind", err.Error())
	}
}

// TestLuaCheckConsumesOmittedDefaultsToNil pins back-compat: a check
// that omits `consumes` leaves Consumes() at nil, and the scanner's
// consumesKind treats nil as the KindPage-only allow-list.
func TestLuaCheckConsumesOmittedDefaultsToNil(t *testing.T) {
	src := []byte(`
local check = {
  name  = "no-consumes",
  level = "passive",
  scope = "host",
}

function check.run(ctx)
  return {}
end

return check
`)
	c, err := Load("no-consumes.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Consumes(); got != nil {
		t.Errorf("Consumes() = %v, want nil (scanner clamps nil to KindPage-only)", got)
	}
}
