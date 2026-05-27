//go:build integration

// Integration tests that exercise every check the scanner ships
// against a purpose-built vulnerable container. Each entry in
// vulnSuites owns one container and delegates the run profile
// (mode, crawl, pollute, seed URLs, the exact checks to run) to a
// sibling testcontainers/<dir>/hyperz.yaml. The same YAML's
// checks.enable list is the assertion contract: every check named
// there must fire against this container.
//
// Adding a new check to the catalog means either (a) extending an
// existing container's hyperz.yaml so the check appears in both the
// enable list AND the assertion, or (b) adding a new container plus
// its own YAML + an entry in vulnSuites below.
//
// Gated behind `-tags integration` so a plain `go test ./...` stays
// fast and Docker-free. Run via:
//
//	go test -tags integration -timeout 15m ./testcontainers/...
//
// To run a single suite, filter the subtest by its directory name:
//
//	go test -tags integration -run TestVuln/vuln-app ./testcontainers/...
//	go test -tags integration -run 'TestVuln/vuln-(app|node)$' ./testcontainers/...
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

import (
	"testing"
	"time"
)

// vulnCase describes one container suite. spec is forwarded to
// startTarget; prepareScan is an optional hook that runs after the
// container is up and may return scanOpts overrides (e.g. --ca-file
// for HTTPS-only containers). A nil prepareScan means the default
// scanOpts{} is used.
type vulnCase struct {
	spec        targetSpec
	prepareScan func(t *testing.T, tgt *target) scanOpts
	notes       string // one-line description, surfaced in t.Logf for context
}

// vulnSuites is the single source of truth for which containers the
// integration suite drives. Filter via -run TestVuln/<dir>.
var vulnSuites = []vulnCase{
	{
		// Passive headers / HTML / TLS / JS / CORS / discovery /
		// OAuth surface plus the CORS reflection and CSP bypass
		// active probes. The HTTPS seed lives in the YAML; the
		// harness pulls the container's CA out so the in-process
		// scan can verify the self-signed server cert.
		spec: targetSpec{
			dir:         "vuln-static",
			exposedPort: 80,
			httpsPort:   443,
		},
		prepareScan: func(t *testing.T, tgt *target) scanOpts {
			if tgt.HTTPSURL("") == "" {
				t.Fatalf("vuln-static did not expose its HTTPS port")
			}
			return scanOpts{CAFile: extractCAFromContainer(t, tgt.container, "/export/ca.crt")}
		},
		notes: "passive surface + CORS / CSP active probes (HTTPS)",
	},
	{
		// Subdomain-takeover via the fingerprint-only path: the
		// container's host root mimics an unclaimed S3 bucket
		// (status + body + AmazonS3 server / x-amz headers). No
		// DNS needed.
		spec:  targetSpec{dir: "vuln-takeover", exposedPort: 80},
		notes: "subdomain-takeover fingerprint",
	},
	{
		// Every active web-app probe in one container. Mode /
		// crawl / pollute / enable all come from the YAML.
		spec:  targetSpec{dir: "vuln-app", exposedPort: 8080},
		notes: "active web-app probes",
	},
	{
		// ws-audit against a Node ws server that accepts any
		// Origin on /echo.
		spec: targetSpec{
			dir:         "vuln-ws",
			exposedPort: 8081,
			waitLog:     "vuln-ws listening on :8081",
		},
		notes: "ws-audit (Origin reflection)",
	},
	{
		// Proto-pollution: a recursive merge that follows
		// __proto__ keys, observable via Express's res.json
		// honoring the polluted "json spaces" setting.
		spec: targetSpec{
			dir:         "vuln-node",
			exposedPort: 8082,
			waitLog:     "vuln-node listening on :8082",
		},
		notes: "proto-pollution",
	},
	{
		// Request-smuggling against a CL/TE desync rig: front-end
		// parses Content-Length only, back-end parses
		// Transfer-Encoding only.
		spec:  targetSpec{dir: "vuln-smuggling", exposedPort: 80},
		notes: "request-smuggling CL/TE desync",
	},
	{
		// Race-condition against a TOCTOU balance deduction. The
		// seed URL lives in the YAML; the crawler discovers the
		// POST /withdraw form rendered on the index page.
		spec: targetSpec{
			dir:         "vuln-race",
			exposedPort: 8084,
			waitLog:     "vuln-race on :8084",
		},
		notes: "race-condition TOCTOU",
	},
	{
		// Real WordPress (Apache + MariaDB co-hosted, installed via
		// wp-cli on first boot) so wp-rest-user-enum exercises the
		// live /wp-json/wp/v2/users surface and wp-xmlrpc-enabled
		// exercises the live /xmlrpc.php surface (WordPress 6.4
		// ships it enabled by default). The startup wait keys off
		// the install-complete marker emitted by init.sh; the
		// default port-listen wait would race the wp core install
		// step. Bumped startupWait covers the apt-cached image's
		// MariaDB bootstrap + wp-cli install (~30s warm, ~3min cold).
		spec: targetSpec{
			dir:         "vuln-wordpress",
			exposedPort: 80,
			waitLog:     "[vuln-wordpress] ready",
			startupWait: 5 * time.Minute,
		},
		notes: "wp-rest-user-enum + wp-xmlrpc-enabled (real WordPress install)",
	},
	{
		// Real Drupal 7 (Apache + MariaDB co-hosted, installed via
		// drush 8.4.12 on first boot) so drupal-changelog-disclosure
		// exercises the live /CHANGELOG.txt surface a real D7 install
		// ships at docroot, the fingerprinter's Drupal detection
		// against real Drupal HTML, and the applies_to dispatch path
		// end-to-end. The startup wait keys off the install-complete
		// marker emitted by init.sh; the default port-listen wait
		// would race the drush site-install step. Bumped startupWait
		// covers the apt-cached image's MariaDB bootstrap + drush
		// install (~30s warm, ~3min cold) - same envelope as
		// vuln-wordpress.
		spec: targetSpec{
			dir:         "vuln-drupal",
			exposedPort: 80,
			waitLog:     "[vuln-drupal] ready",
			startupWait: 5 * time.Minute,
		},
		notes: "drupal-changelog-disclosure (real Drupal 7 install + /CHANGELOG.txt at docroot)",
	},
}

// TestVuln drives every container in vulnSuites as a t.Run subtest
// named after the vuln-* directory. The subtest name is what -run
// matches on, so the directory is the identifier the operator types.
func TestVuln(t *testing.T) {
	for _, tc := range vulnSuites {
		t.Run(tc.spec.dir, func(t *testing.T) {
			if tc.notes != "" {
				t.Logf("[%s] %s", tc.spec.dir, tc.notes)
			}
			tgt := startTarget(t, tc.spec)
			var opts scanOpts
			if tc.prepareScan != nil {
				opts = tc.prepareScan(t, tgt)
			}
			cfgPath, checks := materializeContainerConfig(t, tc.spec.dir, tgt)
			got := runScanWith(t, opts, "--config", cfgPath)
			assertChecksFired(t, got, checks...)
		})
	}
}
