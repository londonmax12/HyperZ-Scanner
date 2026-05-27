package lua_engine

import (
	"context"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/page"
)

func TestLuaCheckAppliesToParsesCMS(t *testing.T) {
	src := []byte(`
local check = {
  name       = "wp-only",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = {"wordpress"} },
}

function check.run(ctx)
  return {{ severity = "info", title = "ran" }}
end

return check
`)
	c, err := Load("wp-only.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !c.AppliesTo(&fingerprint.Stack{CMS: "wordpress"}) {
		t.Errorf("WordPress host should match")
	}
	if c.AppliesTo(&fingerprint.Stack{CMS: "drupal"}) {
		t.Errorf("Drupal host should not match")
	}
	if !c.AppliesTo(&fingerprint.Stack{}) {
		t.Errorf("unknown stack value must pass (permissive on absence)")
	}
	if !c.AppliesTo(nil) {
		t.Errorf("nil stack must pass (permissive on no fingerprint)")
	}
}

func TestLuaCheckAppliesToSingleStringSugar(t *testing.T) {
	src := []byte(`
local check = {
  name       = "wp-sugar",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = "wordpress" },
}

function check.run(ctx)
  return {}
end

return check
`)
	c, err := Load("wp-sugar.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.AppliesTo(&fingerprint.Stack{CMS: "wordpress"}) {
		t.Errorf("single-string sugar form must match wordpress")
	}
}

func TestLuaCheckAppliesToMultipleFieldsAND(t *testing.T) {
	src := []byte(`
local check = {
  name       = "wp-on-nginx",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = {"wordpress"}, server = {"nginx"} },
}

function check.run(ctx)
  return {}
end

return check
`)
	c, err := Load("wp-on-nginx.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.AppliesTo(&fingerprint.Stack{CMS: "wordpress", Server: "nginx"}) {
		t.Errorf("WordPress on nginx should match")
	}
	if c.AppliesTo(&fingerprint.Stack{CMS: "wordpress", Server: "apache"}) {
		t.Errorf("WordPress on apache should not match (server is constrained)")
	}
}

func TestLuaCheckAppliesToUnknownFieldErrors(t *testing.T) {
	src := []byte(`
local check = {
  name       = "bad-field",
  level      = "passive",
  scope      = "host",
  applies_to = { stack = {"wordpress"} },
}

function check.run(ctx)
  return {}
end

return check
`)
	_, err := Load("bad-field.lua", src)
	if err == nil {
		t.Fatalf("expected Load to reject unknown applies_to field, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error message should mention the unknown field; got %q", err.Error())
	}
}

func TestLuaCheckPatchedInEmitsInferredObservation(t *testing.T) {
	src := []byte(`
local check = {
  name       = "wp-xmlrpc-fake",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = {"wordpress"} },
  patched_in = { cms = "6.2" },
}

function check.run(ctx)
  return {
    {
      severity = "high",
      title    = "wp xmlrpc pingback abuse confirmed",
      detail   = "the check found the bug",
    },
  }
end

return check
`)
	c, err := Load("wp-xmlrpc.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Banner unknown - expect one source finding + one inferred observation.
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})
	findings, err := c.Run(ctx, nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (source + inference); got %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("source severity = %q, want high", findings[0].Severity)
	}
	if findings[1].Severity != SeverityInfo {
		t.Errorf("inference severity = %q, want info", findings[1].Severity)
	}
	if !strings.Contains(strings.ToLower(findings[1].Title), "inferred") {
		t.Errorf("inference title should mention 'inferred'; got %q", findings[1].Title)
	}
	if !strings.Contains(findings[1].Title, "wordpress") {
		t.Errorf("inference title should name the detected vendor; got %q", findings[1].Title)
	}
}

func TestLuaCheckPatchedInPatchedButFired(t *testing.T) {
	src := []byte(`
local check = {
  name       = "wp-fired-on-patched",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = {"wordpress"} },
  patched_in = { cms = "6.2" },
}

function check.run(ctx)
  return {{ severity = "high", title = "vuln tripped" }}
end

return check
`)
	c, err := Load("wp-fired.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Banner reports a patched version - expect the "patched_but_fired"
	// observation alongside the source finding.
	stack := &fingerprint.Stack{
		CMS:      "wordpress",
		Versions: map[string]string{"cms": "6.4"},
	}
	ctx := WithStack(context.Background(), stack)
	findings, err := c.Run(ctx, nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (source + patched_but_fired)", len(findings))
	}
	if !strings.Contains(findings[1].Title, "6.4") {
		t.Errorf("patched_but_fired title should include the banner version 6.4; got %q", findings[1].Title)
	}
}

func TestLuaCheckPatchedInBelowPatchedNoExtraObservation(t *testing.T) {
	src := []byte(`
local check = {
  name       = "wp-below-patched",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = {"wordpress"} },
  patched_in = { cms = "6.2" },
}

function check.run(ctx)
  return {{ severity = "high", title = "vuln tripped" }}
end

return check
`)
	c, err := Load("wp-below.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	stack := &fingerprint.Stack{
		CMS:      "wordpress",
		Versions: map[string]string{"cms": "6.0"},
	}
	ctx := WithStack(context.Background(), stack)
	findings, err := c.Run(ctx, nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only the source; banner below patched)", len(findings))
	}
}

func TestLuaCheckPatchedInSkipsIfNoFindingsFired(t *testing.T) {
	src := []byte(`
local check = {
  name       = "wp-quiet",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = {"wordpress"} },
  patched_in = { cms = "6.2" },
}

function check.run(ctx)
  return nil
end

return check
`)
	c, err := Load("wp-quiet.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})
	findings, err := c.Run(ctx, nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 (no source findings -> no inference)", len(findings))
	}
}

func TestLuaCheckPatchedInUnknownFieldErrors(t *testing.T) {
	src := []byte(`
local check = {
  name       = "bad-patched",
  level      = "passive",
  scope      = "host",
  applies_to = { cms = {"wordpress"} },
  patched_in = { stack = "6.2" },
}

function check.run(ctx)
  return {}
end

return check
`)
	_, err := Load("bad-patched.lua", src)
	if err == nil {
		t.Fatalf("expected Load to reject unknown patched_in field")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error should mention the unknown field; got %q", err.Error())
	}
}

func TestLuaCheckAppliesToOmittedIsPermissive(t *testing.T) {
	src := []byte(`
local check = {
  name  = "no-gate",
  level = "passive",
  scope = "host",
}

function check.run(ctx)
  return {}
end

return check
`)
	c, err := Load("no-gate.lua", src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, stack := range []*fingerprint.Stack{
		nil,
		{},
		{CMS: "drupal"},
		{Server: "iis"},
	} {
		if !c.AppliesTo(stack) {
			t.Errorf("check without applies_to should match every stack; failed on %+v", stack)
		}
	}
}
