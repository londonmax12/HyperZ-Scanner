//go:build integration

// Package testcontainers builds vulnerable Docker images on demand,
// runs the hyperz binary against them, and asserts which checks
// fired. Each target image lives in its own subdirectory (vuln-app/,
// vuln-static/, ...) with a Dockerfile + sources; the harness
// rebuilds them lazily so a sourcechange forces a rebuild on the
// next test run.
//
// The harness is intentionally separate from the main scanner module:
// testcontainers-go pulls in a sprawling dep tree that has no place
// in the scanner's binary. We invoke hyperz via os/exec to keep that
// boundary clean and to exercise the same code path operators use.
package testcontainers

import (
	"bytes"
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
	"sync"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
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

// hyperzBinary returns the path to a freshly-built hyperz binary,
// building it lazily and caching across tests in the same package
// run. The build output deliberately lives in a package-scoped
// os.MkdirTemp directory (not t.TempDir, which is reaped after the
// first test that asked for it) so every later test can reuse the
// same binary. TestMain removes the dir at the end of the run.
var (
	hyperzBinaryOnce sync.Once
	hyperzBinaryPath string
	hyperzBinaryDir  string
	hyperzBinaryErr  error
)

func hyperzBinary(t *testing.T) string {
	t.Helper()
	hyperzBinaryOnce.Do(func() {
		root := repoRootDir()
		dir, err := os.MkdirTemp("", "hyperz-build-")
		if err != nil {
			hyperzBinaryErr = err
			return
		}
		out := filepath.Join(dir, "hyperz")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, "./cmd/hyperz")
		cmd.Dir = root
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			hyperzBinaryErr = err
			return
		}
		hyperzBinaryDir = dir
		hyperzBinaryPath = out
	})
	if hyperzBinaryErr != nil {
		t.Fatalf("build hyperz: %v", hyperzBinaryErr)
	}
	return hyperzBinaryPath
}

// repoRootDir resolves the scanner project root without needing a
// *testing.T - used by code paths that run inside sync.Once or
// TestMain where no test context is in scope.
func repoRootDir() string {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(filepath.Dir(here))
}

// TestMain owns the lifecycle of the cached hyperz binary so the
// build dir survives across tests but doesn't leak past the run.
func TestMain(m *testing.M) {
	code := m.Run()
	if hyperzBinaryDir != "" {
		_ = os.RemoveAll(hyperzBinaryDir)
	}
	os.Exit(code)
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
	exposedPort int     // primary port; mapped and tracked
	httpsPort   int     // optional second port for TLS
	waitLog     string  // optional readiness log substring
	scheme      string  // http or https
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
			Context:    buildContext,
			KeepImage:  true,
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

// scanOpts overrides the subprocess environment runScan uses. Set
// SSLCertFile to make the hyperz process trust a custom CA bundle
// when scanning HTTPS targets with self-signed certs (the standard
// SSL_CERT_FILE Go env var; see crypto/x509/root_unix.go).
type scanOpts struct {
	SSLCertFile string
}

// extractCAFromContainer reads a CA cert out of a running container
// at the given path and writes it to a fresh temp file. Returns the
// path, suitable for SSL_CERT_FILE on the hyperz subprocess.
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
func runScanWith(t *testing.T, opts scanOpts, url string, extra ...string) []finding {
	return runScanImpl(t, opts, url, extra...)
}

// runScan invokes the hyperz binary against url with the given extra
// args (e.g. --mode aggressive --pollute) and returns parsed
// findings. JSON output goes through a temp file so any human-style
// progress lines hyperz writes to stdout don't break the parser.
func runScan(t *testing.T, url string, extra ...string) []finding {
	return runScanImpl(t, scanOpts{}, url, extra...)
}

func runScanImpl(t *testing.T, opts scanOpts, url string, extra ...string) []finding {
	t.Helper()
	bin := hyperzBinary(t)
	out := filepath.Join(t.TempDir(), "scan.json")
	args := []string{
		"scan",
		"--url", url,
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
	args = append(args, extra...)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if opts.SSLCertFile != "" {
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+opts.SSLCertFile)
	}
	t.Logf("running hyperz scan: %s", strings.Join(args, " "))
	scanStart := time.Now()
	err := cmd.Run()
	if err != nil {
		t.Logf("hyperz stdout: %s", stdout.String())
		t.Logf("hyperz stderr: %s", stderr.String())
		// Exit code 1 means findings >= --fail-on, which we set to
		// none so it shouldn't happen; treat any non-zero as fatal.
		t.Fatalf("hyperz scan: %v", err)
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

// assertChecksFired fails the test when any name in want is missing
// from the findings set. Reports the missing set + the full set of
// checks that did fire so debugging is one log line away.
func assertChecksFired(t *testing.T, got []finding, want ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.Check] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var missing, present []string
	for _, w := range want {
		if seen[w] {
			present = append(present, w)
		} else {
			missing = append(missing, w)
		}
	}
	sort.Strings(missing)
	sort.Strings(present)

	t.Logf("required checks fired (%d/%d): %v", len(present), len(want), present)
	if extra := diff(keys, want); len(extra) > 0 {
		t.Logf("bonus checks also fired (not required): %v", extra)
	}
	if len(missing) == 0 {
		return
	}
	t.Fatalf("missing checks: %v\nfired: %v", missing, keys)
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
