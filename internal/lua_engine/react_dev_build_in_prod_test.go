package lua_engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// TestReactDevBuildFiresOnScriptSrcFilename drives the check against
// the exact seed-HTML shape the vuln-react integration container
// serves: a tiny HTML page referencing the React + ReactDOM dev UMD
// bundles via <script src=...>. The integration suite saw the check
// stay silent against this fixture, so this test pins down whether
// the failure is in the check's pattern logic (would also fail here)
// or in the harness wiring (would pass here while the docker run
// stays red).
func TestReactDevBuildFiresOnScriptSrcFilename(t *testing.T) {
	body := `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vuln-react</title>
</head>
<body>
<div id="root">vuln-react demo</div>
<script crossorigin src="/static/react/react.development.js"></script>
<script crossorigin src="/static/react-dom/react-dom.development.js"></script>
</body>
</html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "react_dev_build_in_prod.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{Framework: "react"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1; got %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("severity = %q, want low", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "React development build") {
		t.Errorf("title should name the React dev build; got %q", findings[0].Title)
	}
}

// TestReactDevBuildFiresOnInBundleMarker drives the check against the
// in-body DEV_MARKER fallback path - what vuln-react-inline relies on
// once the script-src filenames have been scrubbed.
func TestReactDevBuildFiresOnInBundleMarker(t *testing.T) {
	body := `<!doctype html>
<html><body><div id="root"></div>
<script>
var __REACT_DEVTOOLS_GLOBAL_HOOK__ = {};
var ReactDebugCurrentFrame = { setExtraStackFrame: function () {} };
</script>
</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "react_dev_build_in_prod.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{Framework: "react"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1; got %+v", len(findings), findings)
	}
}

// TestReactDevBuildGateRejectsExpressFramework pins down the exact
// failure mode the vuln-react integration suite hit: Express sets
// X-Powered-By: Express by default, the fingerprinter's header rule
// pins Framework=express before any body-level rule (react-dom-bundle
// etc.) gets a turn, setReactIfUnknown defers to the already-pinned
// value, and the check's applies_to = { framework = { react, nextjs }
// } rejects the express host. The fix lives in the fixture
// (app.disable("x-powered-by")), not in the check or the gate: a real
// production React deployment also strips the framework version
// header for the same reason.
func TestReactDevBuildGateRejectsExpressFramework(t *testing.T) {
	c := loadCatalogCheck(t, "react_dev_build_in_prod.lua")

	if c.AppliesTo(&fingerprint.Stack{Framework: "express"}) {
		t.Errorf("express framework must NOT match the react/nextjs gate - " +
			"vuln-react / vuln-react-inline must disable Express's X-Powered-By " +
			"so the body-level react fingerprint rule wins")
	}
}

// TestReactDevBuildAppliesToNextJSToo confirms the framework gate
// passes for both react and nextjs hosts; vuln-react relies on the
// react case, vuln-nextjs would inherit dev-build detection through
// the nextjs case if a future fixture exercised it.
func TestReactDevBuildAppliesToNextJSToo(t *testing.T) {
	c := loadCatalogCheck(t, "react_dev_build_in_prod.lua")

	if !c.AppliesTo(&fingerprint.Stack{Framework: "react"}) {
		t.Errorf("react framework must match the gate")
	}
	if !c.AppliesTo(&fingerprint.Stack{Framework: "nextjs"}) {
		t.Errorf("nextjs framework must match the gate")
	}
	if c.AppliesTo(&fingerprint.Stack{Framework: "django"}) {
		t.Errorf("django host must NOT match the React-family gate")
	}
	if !c.AppliesTo(nil) {
		t.Errorf("nil stack (no fingerprint) must be permissive")
	}
}
