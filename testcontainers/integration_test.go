//go:build integration

// Integration tests that exercise every check the scanner ships
// against a purpose-built vulnerable container. Each Test* function
// owns one container and a contract: the set of check names it MUST
// see in the JSON output. Adding a new check to the catalog means
// either (a) extending one of the existing test contracts to assert
// it fires here too, or (b) adding a new container + test.
//
// Gated behind `-tags integration` so a plain `go test ./...` stays
// fast and Docker-free. Run via:
//
//	go test -tags integration -timeout 15m ./testcontainers/...
//
// Requires a reachable Docker daemon. Each test builds its image
// lazily; subsequent runs hit the layer cache and complete quickly.
package testcontainers

import "testing"

// TestVulnStatic covers the passive headers / HTML / TLS / JS / CORS
// / discovery / OAuth surface plus the CORS reflection and CSP
// bypass active probes. Crawl + default level pull the linked URLs
// into the scan automatically.
func TestVulnStatic(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-static",
		exposedPort: 80,
		httpsPort:   443,
	})

	httpsURL := tgt.HTTPSURL("/")
	if httpsURL == "" {
		t.Fatalf("vuln-static did not expose its HTTPS port")
	}

	// Pull the container's CA cert out so the hyperz subprocess can
	// verify the self-signed server cert without an --insecure flag
	// the scanner doesn't ship.
	caPath := extractCAFromContainer(t, tgt.container, "/export/ca.crt")

	got := runScanWith(t, scanOpts{SSLCertFile: caPath}, httpsURL,
		"--url", tgt.URL("/openapi.json"),
		"--url", tgt.URL("/.well-known/oauth-authorization-server"),
		"--url", tgt.URL("/api/profile"),
		"--url", tgt.URL("/api/reflect"),
		"--url", tgt.URL("/jsonp"),
		"--mode", "default",
		"--crawl",
	)

	assertChecksFired(t, got,
		// passive header surface
		"security-headers",
		"cookie-attributes",
		"cache-control-sensitive",
		"csp-weak",
		"hsts-weak",
		"cross-origin-isolation",
		"form-autocomplete",
		"form-action-insecure",
		"cors-config",
		"server-leak",
		"secrets-in-body",
		"oauth-discovery",
		"tls-audit",
		"mixed-content",
		"js-libs-known-vuln",
		"sri-missing",
		"source-map-exposure",
		"target-blank-noopener",
		// passive metadata
		"openapi-audit",
		// default-level active probes hitting the same image
		"cors-reflection",
		"csp-bypass",
		"content-discovery",
	)
}

// TestVulnTakeover isolates subdomain-takeover via the fingerprint-
// only path: the container's host root mimics an unclaimed S3 bucket
// (status + body + AmazonS3 server / x-amz headers). No DNS needed.
func TestVulnTakeover(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-takeover",
		exposedPort: 80,
	})
	got := runScan(t, tgt.URL("/"))
	assertChecksFired(t, got, "subdomain-takeover")
}

// TestVulnApp covers every active web-app probe in one container.
// Crawl + default mode + --pollute lights up stored-xss; --mode
// aggressive lifts the idor sweep.
func TestVulnApp(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-app",
		exposedPort: 8080,
	})
	got := runScan(t, tgt.URL("/"),
		"--crawl",
		"--mode", "aggressive",
		"--pollute",
	)

	assertChecksFired(t, got,
		"open-redirect",
		"host-header-injection",
		"cache-poisoning",
		"crlf-injection",
		"ssrf",
		"reflected-xss",
		"sqli-error",
		"sqli-boolean",
		"sqli-time",
		"nosqli",
		"ldapi",
		"path-traversal",
		"cmd-injection",
		"cmd-injection-blind",
		"insecure-deserialization",
		"xxe",
		"ssti",
		"idor",
		"stored-xss",
		"jwt-vulns",
		"graphql-audit",
		"sse-audit",
	)
}

// TestVulnWS exercises ws-audit against a Node ws server that
// accepts any Origin on /echo.
func TestVulnWS(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-ws",
		exposedPort: 8081,
		waitLog:     "vuln-ws listening on :8081",
	})
	got := runScan(t, tgt.URL("/"),
		"--mode", "default",
	)
	assertChecksFired(t, got, "ws-audit")
}

// TestVulnNode covers proto-pollution: a recursive merge that
// follows __proto__ keys, observable via Express's res.json
// honoring the polluted "json spaces" setting.
func TestVulnNode(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-node",
		exposedPort: 8082,
		waitLog:     "vuln-node listening on :8082",
	})
	got := runScan(t, tgt.URL("/"),
		"--crawl",
		"--mode", "aggressive",
		"--pollute",
	)
	assertChecksFired(t, got, "proto-pollution")
}

// TestVulnSmuggling exercises request-smuggling against a CL/TE
// desync rig: front-end parses Content-Length only, back-end
// parses Transfer-Encoding only.
func TestVulnSmuggling(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-smuggling",
		exposedPort: 80,
	})
	got := runScan(t, tgt.URL("/"),
		"--mode", "aggressive",
		"--pollute",
	)
	assertChecksFired(t, got, "request-smuggling")
}

// TestVulnRace exercises race-condition against a TOCTOU balance
// deduction. Single-packet attack on /spend triggers multiple 2xx
// responses where only one should succeed.
func TestVulnRace(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-race",
		exposedPort: 8084,
		waitLog:     "vuln-race on :8084",
	})
	got := runScan(t, tgt.URL("/spend?amount=60"),
		"--mode", "aggressive",
		"--pollute",
	)
	assertChecksFired(t, got, "race-condition")
}
