package lua_engine

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/target"
)

// recordingDiscoverer captures every target.Target the Lua bridge
// hands through core.Discover so tests can assert what was emitted.
// Captures the per-emission tier alongside the Target since the
// post-fold Discoverer signature carries scheduling info too.
type recordingDiscoverer struct {
	mu        sync.Mutex
	captured  []target.Target
	capturedT []core.Tier
}

func (r *recordingDiscoverer) sink(t target.Target, tier core.Tier) {
	r.mu.Lock()
	r.captured = append(r.captured, t)
	r.capturedT = append(r.capturedT, tier)
	r.mu.Unlock()
}

func (r *recordingDiscoverer) all() []target.Target {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]target.Target, len(r.captured))
	copy(out, r.captured)
	return out
}

// runWithDiscoverer compiles src as a Lua check, runs it with a
// recording discoverer attached to the ctx, and returns the captured
// emissions. Used by the test cases below to avoid each one
// duplicating the Load + WithDiscoverer + Run boilerplate.
func runWithDiscoverer(t *testing.T, name string, src []byte) []target.Target {
	t.Helper()
	c, err := Load(name, src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rec := &recordingDiscoverer{}
	ctx := core.WithDiscoverer(context.Background(), rec.sink)
	if _, err := c.Run(ctx, nil, nil, page.Page{URL: "https://example.com/"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rec.all()
}

func TestCtxDiscoverEmitsKindPage(t *testing.T) {
	got := runWithDiscoverer(t, "emit-page.lua", []byte(`
local check = { name = "emit-page", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{ kind = "page", url = "https://example.com/found" }
  return nil
end
return check
`))
	if len(got) != 1 {
		t.Fatalf("emissions = %d, want 1; got %+v", len(got), got)
	}
	if got[0].Kind != target.KindPage {
		t.Errorf("Kind = %v, want KindPage", got[0].Kind)
	}
	if got[0].URL != "https://example.com/found" {
		t.Errorf("URL = %q, want https://example.com/found", got[0].URL)
	}
}

func TestCtxDiscoverEmitsKindEndpointWithMethodAndContentType(t *testing.T) {
	got := runWithDiscoverer(t, "emit-endpoint.lua", []byte(`
local check = { name = "emit-endpoint", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{
    kind = "endpoint",
    url = "https://example.com/api/login",
    method = "post",
    content_type = "application/json",
  }
  return nil
end
return check
`))
	if len(got) != 1 {
		t.Fatalf("emissions = %d, want 1", len(got))
	}
	if got[0].Kind != target.KindEndpoint {
		t.Errorf("Kind = %v, want KindEndpoint", got[0].Kind)
	}
	if got[0].Method != "POST" {
		t.Errorf("Method = %q, want POST (uppercased)", got[0].Method)
	}
	if got[0].ContentType != "application/json" {
		t.Errorf("ContentType = %q, want application/json", got[0].ContentType)
	}
}

func TestCtxDiscoverEmitsKindParam(t *testing.T) {
	got := runWithDiscoverer(t, "emit-param.lua", []byte(`
local check = { name = "emit-param", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{
    kind = "param",
    url = "https://example.com/redirect",
    param = "next",
    location = "Query",
  }
  return nil
end
return check
`))
	if len(got) != 1 {
		t.Fatalf("emissions = %d, want 1", len(got))
	}
	if got[0].Kind != target.KindParam {
		t.Errorf("Kind = %v, want KindParam", got[0].Kind)
	}
	if got[0].Param != "next" {
		t.Errorf("Param = %q, want next", got[0].Param)
	}
	if got[0].ParamLocation != "query" {
		t.Errorf("ParamLocation = %q, want query (lowercased)", got[0].ParamLocation)
	}
}

func TestCtxDiscoverCarriesNoteOpaquely(t *testing.T) {
	got := runWithDiscoverer(t, "emit-note.lua", []byte(`
local check = { name = "emit-note", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{
    kind = "page",
    url = "https://example.com/readback",
    note = "stored-xss-readback:tok123",
  }
  return nil
end
return check
`))
	if len(got) != 1 {
		t.Fatalf("emissions = %d, want 1", len(got))
	}
	if got[0].Note != "stored-xss-readback:tok123" {
		t.Errorf("Note = %q, want stored-xss-readback:tok123", got[0].Note)
	}
}

func TestCtxDiscoverEmitsMultipleInOneRun(t *testing.T) {
	got := runWithDiscoverer(t, "emit-many.lua", []byte(`
local check = { name = "emit-many", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{ kind = "page", url = "https://example.com/a" }
  ctx:discover{ kind = "page", url = "https://example.com/b" }
  ctx:discover{ kind = "page", url = "https://example.com/c" }
  return nil
end
return check
`))
	if len(got) != 3 {
		t.Fatalf("emissions = %d, want 3", len(got))
	}
}

func TestCtxDiscoverWithoutSinkIsNoOp(t *testing.T) {
	// No core.WithDiscoverer attached - the call should be a silent
	// no-op rather than raising a Lua error. Matches ctx:report's
	// permissive contract when no reporter is wired.
	c, err := Load("emit-no-sink.lua", []byte(`
local check = { name = "emit-no-sink", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{ kind = "page", url = "https://example.com/x" }
  return {{ severity = "info", title = "ran" }}
end
return check
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	findings, err := c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (Run must still complete despite missing discoverer)", len(findings))
	}
}

func TestCtxDiscoverInvalidKindRaisesError(t *testing.T) {
	c, err := Load("emit-bad-kind.lua", []byte(`
local check = { name = "emit-bad-kind", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{ kind = "stack", url = "https://example.com/x" }
  return nil
end
return check
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rec := &recordingDiscoverer{}
	ctx := core.WithDiscoverer(context.Background(), rec.sink)
	_, err = c.Run(ctx, nil, nil, page.Page{URL: "https://example.com/"})
	if err == nil {
		t.Fatalf("expected error for invalid kind, got nil")
	}
	if !strings.Contains(err.Error(), "invalid discover kind") {
		t.Errorf("error should mention invalid discover kind; got %q", err.Error())
	}
	if len(rec.all()) != 0 {
		t.Errorf("nothing should have been emitted on error; got %d", len(rec.all()))
	}
}

func TestCtxDiscoverMissingURLRaisesError(t *testing.T) {
	c, err := Load("emit-no-url.lua", []byte(`
local check = { name = "emit-no-url", level = "passive", scope = "host" }
function check.run(ctx)
  ctx:discover{ kind = "page" }
  return nil
end
return check
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = c.Run(context.Background(), nil, nil, page.Page{URL: "https://example.com/"})
	if err == nil {
		t.Fatalf("expected error for missing url, got nil")
	}
	if !strings.Contains(err.Error(), "url") {
		t.Errorf("error should mention missing url; got %q", err.Error())
	}
}
