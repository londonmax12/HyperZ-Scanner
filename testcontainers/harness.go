//go:build integration

// Package testcontainers builds vulnerable Docker images on demand,
// runs the hyperz scan in-process against them, and asserts which
// checks fired. Each target image lives in its own subdirectory
// (vuln-app/, vuln-static/, ...) with a Dockerfile + sources; the
// harness rebuilds them lazily so a source change forces a rebuild
// on the next test run.
//
// The harness used to be its own Go module that fork/exec'd a
// freshly-built hyperz binary - the boundary kept testcontainers-go's
// dep tree out of the scanner's go.mod. That stopped working on
// Windows once Smart App Control / Application Control started
// blocking the unsigned scanner binary at process-creation time
// ("Malicious binary reputation"), so we fold the harness into the
// main module and call internal/cli.Run directly. Same code path
// the operator gets via `hyperz scan ...`, just without the
// fork/exec a hostile App Control policy can veto. The integration
// build tag still keeps `go test ./...` Docker-free.
package testcontainers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gopkg.in/yaml.v3"

	"github.com/londonmax12/hyperz/internal/cli"
)

// repoRoot resolves to the scanner project root regardless of where
// the test was invoked from. We pin off this file's path so callers
// don't have to set HYPERZ_ROOT.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("cannot resolve caller for repo root")
	}
	return filepath.Dir(filepath.Dir(here))
}

// target describes one running vulnerable container the harness owns
// for the duration of a single test. The container is torn down with
// the test context.
type target struct {
	ctx        context.Context
	container  testcontainers.Container
	host       string
	port       int
	scheme     string
	exposed    nat.Port
	httpsExtra nat.Port // populated when the image exposes TLS too
}

// URL returns the seed URL to scan. Path is appended to the host
// origin without trailing-slash collapsing so tests can target
// specific entrypoints (the crawler walks links from there).
func (t *target) URL(path string) string {
	u := fmt.Sprintf("%s://%s:%d", t.scheme, t.host, t.port)
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			u += "/"
		}
		u += path
	}
	return u
}

// HTTPSURL returns the TLS seed URL when the image exposes one. Used
// by checks that only meaningfully fire over HTTPS (tls-audit,
// mixed-content, form-action-insecure, hsts-weak).
func (t *target) HTTPSURL(path string) string {
	if t.httpsExtra == "" {
		return ""
	}
	port, err := t.container.MappedPort(t.ctx, t.httpsExtra)
	if err != nil {
		return ""
	}
	out := fmt.Sprintf("https://%s:%d", t.host, port.Int())
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			out += "/"
		}
		out += path
	}
	return out
}

// startTarget builds the image at dir and starts it. waitLog is a
// substring the container must emit on stdout/stderr before the
// container is considered ready; an empty waitLog falls back to a
// TCP listen check on exposedPort.
type targetSpec struct {
	dir         string
	exposedPort int    // primary port; mapped and tracked
	httpsPort   int    // optional second port for TLS
	waitLog     string // optional readiness log substring
	scheme      string // http or https
	startupWait time.Duration
}

// ensureDockerReachable preflights the Docker daemon before testcontainers
// gets a chance to fall through its rootless-socket probe and panic on
// Windows. We also default DOCKER_HOST to the standard Windows named pipe
// when it isn't set: testcontainers' env walk wants it explicitly even
// when the OS itself has a working `docker` CLI configured against the
// pipe. The probe is `docker info`; if it fails we skip with a clear
// message instead of letting the test panic deep inside testcontainers.
func ensureDockerReachable(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" && os.Getenv("DOCKER_HOST") == "" {
		_ = os.Setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
		if os.Getenv("TESTCONTAINERS_HOST_OVERRIDE") == "" {
			_ = os.Setenv("TESTCONTAINERS_HOST_OVERRIDE", "localhost")
		}
	}
	probe := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
	probe.Env = os.Environ()
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("docker not reachable - skipping container test. "+
			"Start Docker Desktop (or set DOCKER_HOST to a working daemon) "+
			"and rerun. probe: %v\n%s", err, string(out))
	}
}

func startTarget(t *testing.T, spec targetSpec) *target {
	t.Helper()
	// progress() bypasses `go test` output capture so the operator
	// running the suite sees which container is being exercised even
	// without -v. Anchored here because every test goes through
	// startTarget; placing it in the per-test stubs would duplicate
	// the line and let it drift away from the dir name.
	progress(fmt.Sprintf("testing: %s", spec.dir))
	ensureDockerReachable(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	root := repoRoot(t)
	buildContext := filepath.Join(root, "testcontainers", spec.dir)

	exposed := nat.Port(fmt.Sprintf("%d/tcp", spec.exposedPort))
	exposedSpec := []string{string(exposed)}
	if spec.httpsPort != 0 {
		exposedSpec = append(exposedSpec, fmt.Sprintf("%d/tcp", spec.httpsPort))
	}

	var strategy wait.Strategy
	if spec.waitLog != "" {
		strategy = wait.ForLog(spec.waitLog).WithStartupTimeout(spec.timeoutOrDefault())
	} else {
		strategy = wait.ForListeningPort(exposed).WithStartupTimeout(spec.timeoutOrDefault())
	}

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       buildContext,
			KeepImage:     true,
			PrintBuildLog: true,
		},
		ExposedPorts: exposedSpec,
		WaitingFor:   strategy,
	}

	t.Logf("[%s] building image + starting container (context=%s)", spec.dir, buildContext)
	buildStart := time.Now()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start %s: %v", spec.dir, err)
	}
	t.Cleanup(func() {
		_ = c.Terminate(context.Background())
	})

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("host for %s: %v", spec.dir, err)
	}
	port, err := c.MappedPort(ctx, exposed)
	if err != nil {
		t.Fatalf("port for %s: %v", spec.dir, err)
	}
	scheme := spec.scheme
	if scheme == "" {
		scheme = "http"
	}
	tg := &target{
		ctx:       ctx,
		container: c,
		host:      host,
		port:      port.Int(),
		scheme:    scheme,
		exposed:   exposed,
	}
	if spec.httpsPort != 0 {
		tg.httpsExtra = nat.Port(fmt.Sprintf("%d/tcp", spec.httpsPort))
	}
	t.Logf("[%s] container up after %s -> %s://%s:%d",
		spec.dir, time.Since(buildStart).Round(time.Millisecond),
		scheme, host, port.Int())
	return tg
}

func (s targetSpec) timeoutOrDefault() time.Duration {
	if s.startupWait > 0 {
		return s.startupWait
	}
	return 90 * time.Second
}

// scanResult is the subset of the JSON report we assert against.
type scanResult struct {
	Findings []finding `json:"findings"`
}

type finding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Target   string `json:"target"`
}

// scanOpts overrides the per-call scan invocation. Set CAFile to make
// the in-process scan trust a custom CA bundle when scanning HTTPS
// targets with self-signed certs - threaded into the scanner as
// --ca-file so the trust is wired into the actual http.Transport.
type scanOpts struct {
	CAFile string
}

// extractCAFromContainer reads a CA cert out of a running container
// at the given path and writes it to a fresh temp file. Returns the
// path, suitable for the --ca-file flag.
func extractCAFromContainer(t *testing.T, c testcontainers.Container, srcPath string) string {
	t.Helper()
	rc, err := c.CopyFileFromContainer(context.Background(), srcPath)
	if err != nil {
		t.Fatalf("copy %s from container: %v", srcPath, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read CA from container: %v", err)
	}
	out := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(out, data, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return out
}

// runScanWith is the env-aware variant of runScan. runScan delegates
// to it with an empty scanOpts so the simple call site stays terse.
//
// Callers supply every target-specific arg (--url, --config, --mode,
// ...) via extra. The harness only injects the scan-machinery flags
// (format/output/log-level/timeout/rate/burst) that should be uniform
// across the suite; everything that varies per container lives in
// the test or in the container's hyperz.yaml.
func runScanWith(t *testing.T, opts scanOpts, extra ...string) []finding {
	return runScanImpl(t, opts, extra...)
}

// runScan invokes the in-process hyperz scan with the given extra
// args (e.g. --config or --url, plus --mode aggressive --pollute)
// and returns parsed findings. JSON output goes through a temp file
// because cli.Run takes ownership of its stdout - the file path
// matches what an operator would see using -o on the CLI.
func runScan(t *testing.T, extra ...string) []finding {
	return runScanImpl(t, scanOpts{}, extra...)
}

func runScanImpl(t *testing.T, opts scanOpts, extra ...string) []finding {
	t.Helper()
	out := filepath.Join(t.TempDir(), "scan.json")
	args := []string{
		"scan",
		"--format", "json",
		"-o", out,
		"--log-level", "warn",
		// Fail-on none: we want every finding, not the operator gate.
		"--fail-on", "none",
		// Bound the wall-clock; defaults are conservative for real targets.
		"--timeout", "15s",
		"--rate", "20",
		"--burst", "20",
	}
	if opts.CAFile != "" {
		args = append(args, "--ca-file", opts.CAFile)
	}
	args = append(args, extra...)

	t.Logf("running hyperz scan (in-process): %s", strings.Join(args, " "))
	scanStart := time.Now()
	// cli.Run is the same entry point cmd/hyperz/main.go drives, so
	// the test exercises the same orchestration an operator gets.
	// --fail-on=none above keeps exit 1 (findings-at-threshold) out
	// of the picture; any non-zero is a tool failure we want to
	// surface as a test failure.
	if code := cli.Run(args); code != 0 {
		t.Fatalf("hyperz scan exited %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r scanResult
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parse report: %v\nraw:\n%s", err, string(raw))
	}
	t.Logf("scan finished in %s: %d findings", time.Since(scanStart).Round(time.Millisecond), len(r.Findings))
	return r.Findings
}

// containerConfigPlaceholderHTTP / HTTPS are the textual markers each
// vuln-*/hyperz.yaml uses in place of the runtime origin. They are
// substituted by materializeContainerConfig before the file reaches
// the in-process scan.
const (
	containerConfigPlaceholderHTTP  = "${ORIGIN_HTTP}"
	containerConfigPlaceholderHTTPS = "${ORIGIN_HTTPS}"
)

// containerConfigView is the slice of hyperz config the harness reads
// for itself. The check-list is the test's assertion contract; the
// URL list is parsed only so a test can sanity-log what it is about
// to scan. Everything else in the file is opaque to the harness and
// flows through to hyperz unchanged via --config.
type containerConfigView struct {
	URL    []string `yaml:"url"`
	Checks struct {
		Enable []string `yaml:"enable"`
	} `yaml:"checks"`
}

// materializeContainerConfig reads testcontainers/<dir>/hyperz.yaml,
// substitutes the dynamic-origin placeholders with tgt's running URL,
// writes the result to t.TempDir(), and returns:
//
//   - configPath: the absolute path of the materialized file, ready
//     to hand to `hyperz scan --config`.
//   - checks: the parsed checks.enable list, used as the assertion
//     contract by assertChecksFired so the YAML is the one source of
//     truth for "what this container exercises".
//
// The substitution is plain text replacement (not YAML-aware): every
// occurrence of ${ORIGIN_HTTP} becomes tgt.URL("") and every
// ${ORIGIN_HTTPS} becomes tgt.HTTPSURL(""). Tests that do not need
// the HTTPS placeholder simply omit it; an absent HTTPSURL on a
// target with no httpsExtra port leaves the placeholder unsubstituted
// and the strict YAML decoder will reject it, which is the failure
// shape we want (silently scanning the wrong scheme would be worse).
func materializeContainerConfig(t *testing.T, dir string, tgt *target) (configPath string, checks []string) {
	t.Helper()
	root := repoRoot(t)
	src := filepath.Join(root, "testcontainers", dir, "hyperz.yaml")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}

	originHTTP := tgt.URL("")
	originHTTPS := tgt.HTTPSURL("")
	substituted := strings.ReplaceAll(string(raw), containerConfigPlaceholderHTTP, originHTTP)
	if originHTTPS != "" {
		substituted = strings.ReplaceAll(substituted, containerConfigPlaceholderHTTPS, originHTTPS)
	}

	var view containerConfigView
	if err := yaml.Unmarshal([]byte(substituted), &view); err != nil {
		t.Fatalf("parse materialized config (%s): %v\n---\n%s", src, err, substituted)
	}

	out := filepath.Join(t.TempDir(), "hyperz.yaml")
	if err := os.WriteFile(out, []byte(substituted), 0o600); err != nil {
		t.Fatalf("write materialized config: %v", err)
	}
	t.Logf("[%s] materialized config -> %s (seeds=%v, enable=%d)",
		dir, out, view.URL, len(view.Checks.Enable))
	return out, view.Checks.Enable
}

// assertChecksFired fails the test when any name in want is missing
// from the findings set. Every enabled check is announced via
// progress() as "<name>: triggered" or "<name>: not triggered" so the
// operator can watch each check's outcome without -v, and any bonus
// checks that fired outside the enable list are announced too.
func assertChecksFired(t *testing.T, got []finding, want ...string) {
	t.Helper()
	fired := map[string]bool{}
	for _, f := range got {
		fired[f.Check] = true
	}
	firedSorted := make([]string, 0, len(fired))
	for k := range fired {
		firedSorted = append(firedSorted, k)
	}
	sort.Strings(firedSorted)

	// Report status in the order the test declared its expectations
	// (which is the same as the YAML's checks.enable order) so the
	// terminal output reads top-down without surprises.
	var missing []string
	for _, w := range want {
		if fired[w] {
			progress(fmt.Sprintf("%s: triggered", w))
		} else {
			progress(fmt.Sprintf("%s: not triggered", w))
			missing = append(missing, w)
		}
	}
	for _, extra := range diff(firedSorted, want) {
		progress(fmt.Sprintf("%s: triggered (bonus, not in enable list)", extra))
	}

	if len(missing) == 0 {
		return
	}
	t.Fatalf("missing checks: %v\nfired: %v", missing, firedSorted)
}

// diff returns elements present in a but not in b.
func diff(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, v := range b {
		in[v] = true
	}
	var out []string
	for _, v := range a {
		if !in[v] {
			out = append(out, v)
		}
	}
	return out
}
