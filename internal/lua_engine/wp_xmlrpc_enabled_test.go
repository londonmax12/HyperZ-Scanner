package lua_engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// listMethodsResponse is a realistic system.listMethods response from
// a default WordPress install. The check looks for <methodResponse>
// plus at least one <string> entry inside; the presence of
// "pingback.ping" promotes the finding detail.
const listMethodsResponse = `<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>system.multicall</string></value>
            <value><string>system.listMethods</string></value>
            <value><string>system.getCapabilities</string></value>
            <value><string>demo.addTwoNumbers</string></value>
            <value><string>demo.sayHello</string></value>
            <value><string>pingback.ping</string></value>
            <value><string>pingback.extensions.getPingbacks</string></value>
            <value><string>wp.getUsersBlogs</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>`

// TestWPXMLRPCFiresOnEnabledEndpoint exercises the check against a
// server that mimics a real WordPress XML-RPC handler: it accepts
// POST /xmlrpc.php with text/xml content, parses the request,
// recognizes system.listMethods, and returns the canonical
// methodResponse envelope. The check should produce one medium-
// severity finding and the detail should call out pingback.ping
// since the response advertises it.
func TestWPXMLRPCFiresOnEnabledEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/xmlrpc.php" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		reqBody, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(reqBody), "system.listMethods") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(listMethodsResponse))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_xmlrpc_enabled.lua")

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1; got %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if !strings.Contains(f.Title, "XML-RPC") {
		t.Errorf("title should mention XML-RPC; got %q", f.Title)
	}
	if !strings.Contains(f.Detail, "pingback.ping") {
		t.Errorf("detail should call out pingback.ping when the response advertises it; got %q", f.Detail)
	}
}

// TestWPXMLRPCIgnoresNonXMLRPCResponse covers a host whose
// /xmlrpc.php returns 200 with an unrelated body (e.g. a catch-all
// HTML 200 from a misconfigured front controller). The shape check
// requires both <methodResponse> and <string> tags so an HTML
// response is rejected.
func TestWPXMLRPCIgnoresNonXMLRPCResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_xmlrpc_enabled.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 (HTML response is not XML-RPC); got %+v", len(findings), findings)
	}
}

// TestWPXMLRPCIgnoresDisabledEndpoint covers a host whose
// /xmlrpc.php returns 405 / 403 / 404 - the server software is
// present but the route is blocked. No finding.
func TestWPXMLRPCIgnoresDisabledEndpoint(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotFound} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()

			c := loadCatalogCheck(t, "wp_xmlrpc_enabled.lua")
			client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
			ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

			findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("status %d: findings = %d, want 0", code, len(findings))
			}
		})
	}
}

// TestWPXMLRPCOmitsPingbackDetailWhenAbsent covers a hardened
// WordPress install where pingback.ping has been removed from
// xmlrpc_methods. The check still fires (system.listMethods returns
// something, so xmlrpc is reachable), but the detail should NOT
// mention pingback.ping.
func TestWPXMLRPCOmitsPingbackDetailWhenAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>system.multicall</string></value>
            <value><string>system.listMethods</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>`))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_xmlrpc_enabled.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if strings.Contains(findings[0].Detail, "pingback.ping") {
		t.Errorf("detail must not mention pingback.ping when absent from the response; got %q", findings[0].Detail)
	}
}

// TestWPXMLRPCGateOnNonWordPressHost confirms the AppliesTo hook
// rejects non-WordPress stacks. The scanner's StackGated filter
// would skip dispatch in that case; this test asserts the gate
// directly.
func TestWPXMLRPCGateOnNonWordPressHost(t *testing.T) {
	c := loadCatalogCheck(t, "wp_xmlrpc_enabled.lua")
	if !c.AppliesTo(&fingerprint.Stack{CMS: "wordpress"}) {
		t.Errorf("WordPress host must match")
	}
	if c.AppliesTo(&fingerprint.Stack{CMS: "drupal"}) {
		t.Errorf("Drupal host must NOT match")
	}
}

// TestWPXMLRPCOncePerHost confirms claim_once short-circuits later
// pages on the same host so a multi-page crawl issues exactly one
// POST to /xmlrpc.php.
func TestWPXMLRPCOncePerHost(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/xmlrpc.php" {
			http.NotFound(w, r)
			return
		}
		hits++
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(listMethodsResponse))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_xmlrpc_enabled.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

	for i := 0; i < 3; i++ {
		p := page.Page{URL: srv.URL + "/page" + string(rune('0'+i))}
		if _, err := c.Run(ctx, client, nil, p); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
	}
	if hits != 1 {
		t.Errorf("upstream hits = %d, want 1 (claim_once must short-circuit later pages)", hits)
	}
}
