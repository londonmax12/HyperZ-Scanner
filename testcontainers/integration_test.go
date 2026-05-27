//go:build integration

// Integration tests that exercise every check the scanner ships
// against a purpose-built vulnerable container. Each Test* function
// owns one container and delegates the run profile (mode, crawl,
// pollute, seed URLs, the exact checks to run) to a sibling
// testcontainers/<dir>/hyperz.yaml. The same YAML's checks.enable
// list is the assertion contract: every check named there must fire
// against this container.
//
// Adding a new check to the catalog means either (a) extending an
// existing container's hyperz.yaml so the check appears in both the
// enable list AND the assertion, or (b) adding a new container plus
// its own YAML + test stub.
//
// Gated behind `-tags integration` so a plain `go test ./...` stays
// fast and Docker-free. Run via:
//
//	go test -tags integration -timeout 15m ./testcontainers/...
//
// The harness lives inside the main module and invokes the scanner
// in-process through internal/cli.Run rather than fork/exec'ing a
// freshly-built hyperz.exe. See testcontainers/harness.go for the
// rationale: Windows Smart App Control blocks the unsigned scanner
// binary by content hash regardless of where it's built, so any
// subprocess-based harness is dead on arrival on SAC-enabled hosts.
//
// Requires a reachable Docker daemon. Each test builds its image
// lazily; subsequent runs hit the layer cache and complete quickly.
package testcontainers

import "testing"

// TestVulnStatic covers the passive headers / HTML / TLS / JS / CORS
// / discovery / OAuth surface plus the CORS reflection and CSP
// bypass active probes. The HTTPS seed lives in the YAML; the
// harness pulls the container's CA out so the hyperz subprocess can
// verify the self-signed server cert.
func TestVulnStatic(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-static",
		exposedPort: 80,
		httpsPort:   443,
	})
	if tgt.HTTPSURL("") == "" {
		t.Fatalf("vuln-static did not expose its HTTPS port")
	}
	caPath := extractCAFromContainer(t, tgt.container, "/export/ca.crt")
	cfgPath, checks := materializeContainerConfig(t, "vuln-static", tgt)
	got := runScanWith(t, scanOpts{CAFile: caPath}, "--config", cfgPath)
	assertChecksFired(t, got, checks...)
}

// TestVulnTakeover isolates subdomain-takeover via the fingerprint-
// only path: the container's host root mimics an unclaimed S3 bucket
// (status + body + AmazonS3 server / x-amz headers). No DNS needed.
func TestVulnTakeover(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-takeover",
		exposedPort: 80,
	})
	cfgPath, checks := materializeContainerConfig(t, "vuln-takeover", tgt)
	got := runScan(t, "--config", cfgPath)
	assertChecksFired(t, got, checks...)
}

// TestVulnApp covers every active web-app probe in one container.
// Mode / crawl / pollute / enable all come from vuln-app/hyperz.yaml.
func TestVulnApp(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-app",
		exposedPort: 8080,
	})
	cfgPath, checks := materializeContainerConfig(t, "vuln-app", tgt)
	got := runScan(t, "--config", cfgPath)
	assertChecksFired(t, got, checks...)
}

// TestVulnWS exercises ws-audit against a Node ws server that
// accepts any Origin on /echo.
func TestVulnWS(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-ws",
		exposedPort: 8081,
		waitLog:     "vuln-ws listening on :8081",
	})
	cfgPath, checks := materializeContainerConfig(t, "vuln-ws", tgt)
	got := runScan(t, "--config", cfgPath)
	assertChecksFired(t, got, checks...)
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
	cfgPath, checks := materializeContainerConfig(t, "vuln-node", tgt)
	got := runScan(t, "--config", cfgPath)
	assertChecksFired(t, got, checks...)
}

// TestVulnSmuggling exercises request-smuggling against a CL/TE
// desync rig: front-end parses Content-Length only, back-end
// parses Transfer-Encoding only.
func TestVulnSmuggling(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-smuggling",
		exposedPort: 80,
	})
	cfgPath, checks := materializeContainerConfig(t, "vuln-smuggling", tgt)
	got := runScan(t, "--config", cfgPath)
	assertChecksFired(t, got, checks...)
}

// TestVulnRace exercises race-condition against a TOCTOU balance
// deduction. The seed URL (with its ?amount=60 query) lives in the
// YAML so the test stub stays uniform with every other container.
func TestVulnRace(t *testing.T) {
	tgt := startTarget(t, targetSpec{
		dir:         "vuln-race",
		exposedPort: 8084,
		waitLog:     "vuln-race on :8084",
	})
	cfgPath, checks := materializeContainerConfig(t, "vuln-race", tgt)
	got := runScan(t, "--config", cfgPath)
	assertChecksFired(t, got, checks...)
}
