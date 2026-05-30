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
//	go test -tags integration -timeout 30m ./testcontainers/...
//
// 30m is sized for a warm Docker layer cache: ~14 suites, four of
// which (vuln-sqli/nosqli/ldap/graphql) do a pip install on first
// build, and vuln-wordpress + vuln-drupal each carry a 5-minute
// startupWait for their DB + install steps. A cold run on a fresh
// machine can spill past 30m; rerun once images are cached.
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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// vulnCase describes one container suite. spec is forwarded to
// startTarget; prepareScan is an optional hook that runs after the
// container is up and may return scanOpts overrides (e.g. --ca-file
// for HTTPS-only containers). A nil prepareScan means the default
// scanOpts{} is used.
//
// requires is an optional preflight that runs before the (slow)
// container build/start; it may call t.Skip to bail when an external
// dependency the suite needs is missing (e.g. requireBrowser for
// suites whose YAML opts into js.enabled). Skipping here keeps the
// Docker image from being built only to throw away the scan.
type vulnCase struct {
	spec        targetSpec
	requires    func(t *testing.T)
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
		// Active web-app probes that don't need a dedicated
		// backend (open-redirect, host-header, cache-poison,
		// CRLF, SSRF, reflected-xss, traversal, cmd-inject,
		// SSTI, IDOR, JWT, stored-xss, XXE, deserialization,
		// SSE, dom-xss). Mode / crawl / pollute / enable all
		// come from the YAML. vuln-app's hyperz.yaml opts into
		// js.enabled so dom-xss fires against /dom-xss;
		// requireBrowser skips the whole subtest when no
		// Chrome/Chromium binary is reachable rather than
		// letting the scan fail mid-flight.
		//
		// Checks that previously lived here against hand-crafted
		// oracles (sqli-error/boolean/time, nosqli, ldapi,
		// graphql-audit) graduated to dedicated containers with
		// real backends - see vuln-sqli, vuln-nosqli, vuln-ldap,
		// vuln-graphql.
		spec:     targetSpec{dir: "vuln-app", exposedPort: 8080},
		requires: requireBrowser,
		notes:    "active web-app probes (+ dom-xss via headless browser)",
	},
	{
		// Real SQLite-backed search endpoint with `name` field
		// concatenated into a SELECT. SLEEP is registered as a
		// UDF so the scanner's `' AND SLEEP({{SLEEP}})-- -`
		// time-based payload resolves through SQLite's
		// expression evaluator. Anchor value `alice` matches a
		// row so the per-row AND short-circuit still lets
		// SLEEP fire on at least one row.
		spec: targetSpec{
			dir:         "vuln-sqli",
			exposedPort: 8093,
		},
		notes: "sqli-error / sqli-boolean / sqli-time (real SQLite + SLEEP UDF)",
	},
	{
		// mongomock-backed find endpoint that deserialises the
		// scanner's `q[$eq]=v` / `q[$in][0]=v` bracket-form
		// query string into a real Mongo-style operator dict
		// and hands it to coll.find unchanged. Boolean
		// divergence is produced by real $eq / $in semantics,
		// not a hand-rolled if/else.
		spec: targetSpec{
			dir:         "vuln-nosqli",
			exposedPort: 8091,
		},
		notes: "nosqli (real mongomock $op-dict evaluation)",
	},
	{
		// ldap3 MOCK_SYNC directory with cn concatenated into
		// an `(&(cn={cn})(objectClass=person))` filter. The
		// surrounding AND template lets the scanner's truthy
		// `)(|(objectClass=*` reshape the matched set to the
		// baseline entry while the falsy `)(&(objectClass=
		// <canary>` collapses it to nothing - real RFC 4515
		// filter parsing decides both, not a substring branch.
		spec: targetSpec{
			dir:         "vuln-ldap",
			exposedPort: 8092,
		},
		notes: "ldapi (real ldap3 MOCK_SYNC filter parser)",
	},
	{
		// graphene-backed GraphQL endpoint with introspection,
		// suggestions, batching, alias amplification, and a
		// login mutation that returns success without
		// consulting any credential store - so alias-based
		// auth-bypass and batched-mutations both observe N
		// resolves per HTTP request. Depth probe resolves
		// through the native introspection ofType chain.
		spec: targetSpec{
			dir:         "vuln-graphql",
			exposedPort: 8090,
		},
		notes: "graphql-audit (real graphene schema, batching, native suggestions)",
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
		// React development build shipped to production: a tiny
		// Express server that serves the real React + ReactDOM
		// development UMD bundles out of the npm-installed packages,
		// with the seed HTML referencing both via <script src=...>.
		// Exercises the react-dev-build-in-prod check's
		// filename-pattern detection path - the canonical real-world
		// shape: a developer who left the dev CDN URL or
		// NODE_ENV=development in production. The script-tag context
		// also pins framework=react via the fingerprinter's
		// react-dom-bundle rule, satisfying applies_to.
		//
		// prepareScan asserts a real React dev bundle is actually
		// served at the script-src URL - not a 404 or stub. The
		// scanner check itself only inspects the seed HTML body, but
		// the integrity assertion ensures the fixture is
		// observationally indistinguishable from a real misconfigured
		// production deployment, not just an HTML page that lies
		// about loading bundles.
		//
		// vuln-react-inline (below) covers the banner-fallback
		// detection path the check uses when the bundler renamed the
		// chunk and there's no .development. path component on the
		// wire.
		spec: targetSpec{
			dir:         "vuln-react",
			exposedPort: 8083,
			waitLog:     "vuln-react listening on :8083",
		},
		prepareScan: func(t *testing.T, tgt *target) scanOpts {
			// ReactDebugCurrentFrame is the dev-only stack-trace
			// symbol present in every shipping react-dom UMD dev
			// build (16/17/18) and stripped from the production
			// minified bundle. Asserting it on the served URL proves
			// the fixture is genuinely shipping the unminified dev
			// bundle - not a 404 or a production stub.
			assertServesBody(t,
				tgt.URL("/static/react-dom/react-dom.development.js"),
				"ReactDebugCurrentFrame")
			return scanOpts{}
		},
		notes: "react-dev-build-in-prod via script-src filename (real React 18 UMD, fixture-integrity asserted)",
	},
	{
		// React development build shipped to production via an
		// inlined bundle: server reads the real React + ReactDOM dev
		// UMD source out of the npm-installed packages, strips the
		// leading @license header and the trailing sourceMappingURL
		// pragma (the only places the .development.js filename
		// literally appears in the bundle), and inlines the
		// remaining source into the seed HTML between
		// <script>...</script> tags.
		//
		// Exercises the react-dev-build-in-prod check's
		// fallback-marker path: with the filename literals scrubbed
		// and no <script src> reference to react-dom present, the
		// check can only fire via the in-body ReactDebugCurrentFrame
		// dev-only symbol React's internal stack-trace machinery
		// emits unconditionally in any dev bundle (stripped from the
		// production minified output). The
		// __REACT_DEVTOOLS_GLOBAL_HOOK__ reference embedded in the
		// inlined source is what pins framework=react via the
		// fingerprinter's react-devtools-hook rule, since there's
		// no react-dom script-src for the bundle rule to match.
		//
		// prepareScan asserts the served HTML contains the dev
		// marker so a packaging regression (e.g. a future React
		// version removing the symbol) surfaces as a fixture failure
		// rather than a silently-skipped check.
		spec: targetSpec{
			dir:         "vuln-react-inline",
			exposedPort: 8086,
			waitLog:     "vuln-react-inline listening on :8086",
		},
		prepareScan: func(t *testing.T, tgt *target) scanOpts {
			assertServesBody(t,
				tgt.URL("/"),
				"ReactDebugCurrentFrame")
			return scanOpts{}
		},
		notes: "react-dev-build-in-prod via in-body dev marker (real React dev bundle inlined, filename pragmas stripped)",
	},
	{
		// Real Next.js 14.2.24 (one minor below the 14.2.25
		// CVE-2025-29927 patch) exercises two checks end-to-end:
		//
		//   * nextjs-middleware-bypass: middleware.js
		//     unconditionally redirects /dashboard, /admin,
		//     /account, /api/me to /login. The
		//     x-middleware-subrequest depth-saturation header
		//     causes the runtime to skip middleware entirely, so
		//     baseline 307 -> /login becomes 200 on /dashboard -
		//     the status-class change the check uses as its
		//     load-bearing oracle.
		//
		//   * nextjs-image-ssrf: next.config.js opens
		//     remotePatterns to "**" so /_next/image fetches any
		//     attacker-supplied URL. prepareScan picks a free port,
		//     wires the scanner's built-in OOB listener onto it,
		//     and advertises host.docker.internal:<port> as the
		//     canary host (the HostConfigModifier in startTarget
		//     adds the alias so Linux CI works too - Mac/Windows
		//     Docker Desktop already wires it). The in-container
		//     Next.js runtime fetches the canary, the listener
		//     records the hit, the check's Drain phase emits the
		//     finding.
		//
		// `next build` runs at image-build time so subsequent
		// container starts are sub-second.
		spec: targetSpec{
			dir:         "vuln-nextjs",
			exposedPort: 8085,
			waitLog:     "Ready in",
			startupWait: 3 * time.Minute,
		},
		prepareScan: func(t *testing.T, _ *target) scanOpts {
			port := pickFreePort(t)
			return scanOpts{
				OOBListenIP:   "0.0.0.0",
				OOBListenPort: port,
				OOBHost:       fmt.Sprintf("host.docker.internal:%d", port),
				// Next.js image-optimizer fetches are
				// synchronous and complete inside the same
				// request the check makes, so a tight drain
				// window is fine. Bumped above the default 10s
				// only to absorb a cold-cache JIT spike on the
				// optimizer's first invocation.
				OOBWait: 15 * time.Second,
			}
		},
		notes: "nextjs-middleware-bypass + nextjs-image-ssrf (real Next.js 14.2.24, CVE-2025-29927 unpatched, open remotePatterns; OOB listener via host.docker.internal)",
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

// TestCatalogCoverage names every check in the shipped catalog that
// no container in vulnSuites enables, so a new check added without a
// matching vuln-*/hyperz.yaml entry is visible in the suite output
// rather than silently uncovered. It does not fail the suite: not
// every check is meaningfully exercisable from a single container
// (some need the operator-mode-only OOB listener, some are gated by a
// fingerprint that no fixture mimics), and the operator decides what
// to do with the gap. Docker-free; safe to run via
//
//	go test -tags integration -run TestCatalogCoverage ./testcontainers/...
//
// pollute=true on the catalog load so disruptive checks count too:
// vuln-app opts into pollute, so pollute-gated checks are reachable
// and a missing entry there is the same kind of gap as elsewhere.
func TestCatalogCoverage(t *testing.T) {
	catalog, _ := lua_engine.All(true, nil)
	covered := map[string]bool{}
	root := repoRoot(t)
	for _, tc := range vulnSuites {
		path := filepath.Join(root, "testcontainers", tc.spec.dir, "hyperz.yaml")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var view containerConfigView
		if err := yaml.Unmarshal(raw, &view); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, name := range view.Checks.Enable {
			covered[name] = true
		}
	}
	var untested []string
	for _, c := range catalog {
		if !covered[c.Name()] {
			untested = append(untested, c.Name())
		}
	}
	sort.Strings(untested)
	progress(fmt.Sprintf("catalog coverage: %d/%d checks exercised, %d untested",
		len(catalog)-len(untested), len(catalog), len(untested)))
	for _, name := range untested {
		progress(fmt.Sprintf("untested: %s", name))
	}
	t.Logf("untested checks (%d): %v", len(untested), untested)
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
			// requires runs before the slow image build / container
			// start so a missing dependency surfaces as a clean
			// t.Skip instead of an opaque mid-scan error.
			if tc.requires != nil {
				tc.requires(t)
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
