# testcontainers/

Vulnerable Docker targets + a testcontainers-go harness that exercises
every check in the scanner catalog. Each target image is deliberately
broken in a different way; the harness builds the image, spawns the
container, runs the `hyperz` binary against it, and asserts the
expected set of check names appears in the JSON report.

## Run

Requires Docker and Go 1.22+. From the repo root:

```bash
go test -tags integration -v -timeout 20m ./testcontainers/...
```

`-v` is recommended so you see per-phase progress: image build, container
start, scan invocation, finding count, and which required checks fired.
Without `-v`, `go test` buffers all `t.Logf` output until a test fails -
the suite looks idle even when it's working. The `progress()` helper
in `progress.go` also writes "testing: <dir>" and "<check>:
triggered/not triggered" lines straight to the terminal so the run is
observable without `-v` too.

The `integration` build tag keeps `go test ./...` (no tag) Docker-free.

The harness calls the scanner in-process via `internal/cli.Run` rather
than fork/exec'ing a freshly-built `hyperz` binary. The subprocess
approach used to live in its own Go module to keep testcontainers-go's
transitive deps out of the scanner's `go.mod`, but Windows Smart App
Control routinely flags the unsigned scanner binary with "Malicious
binary reputation" and blocks every fork/exec on hosts where SAC is
enabled - making the suite unrunnable. Calling `cli.Run` in-process
exercises the same orchestration an operator gets via
`hyperz scan ...` without creating a new process for SAC to veto.
The build tag still keeps testcontainers-go out of the compiled
scanner binary; only the integration suite sees it.

## Coverage map

| Container         | Image base           | Checks exercised |
| ----------------- | -------------------- | --- |
| `vuln-static`     | nginx + self-signed CA | security-headers, cookie-attributes, cache-control-sensitive, csp-weak, hsts-weak, cross-origin-isolation, form-autocomplete, form-action-insecure, cors-config, server-leak, secrets-in-body, oauth-discovery, tls-audit, mixed-content, js-libs-known-vuln, sri-missing, source-map-exposure, target-blank-noopener, openapi-audit, cors-reflection, csp-bypass, content-discovery |
| `vuln-takeover`   | nginx                | subdomain-takeover (fingerprint path: NoSuchBucket + AmazonS3 + x-amz-* at host root) |
| `vuln-app`        | python:3.12 + flask  | open-redirect, host-header-injection, cache-poisoning, crlf-injection, ssrf, reflected-xss, sqli-error, sqli-boolean, sqli-time, nosqli, ldapi, path-traversal, cmd-injection, cmd-injection-blind, insecure-deserialization, xxe, ssti, idor, stored-xss, jwt-vulns, graphql-audit, sse-audit |
| `vuln-ws`         | node:20 + ws         | ws-audit |
| `vuln-node`       | node:20 + express    | proto-pollution |
| `vuln-smuggling`  | python:3.12 sockets  | request-smuggling (CL.TE: front-end CL-only proxy + back-end TE-only) |
| `vuln-race`       | golang:1.22          | race-condition (TOCTOU balance deduct) |
| `vuln-wordpress`  | wordpress:apache + mariadb | wp-rest-user-enum (real WP install; `/wp-json/wp/v2/users` open to anon) |
| `vuln-drupal`     | drupal:7-apache + mariadb | drupal-changelog-disclosure (real D7 install; `/CHANGELOG.txt` at docroot) |

`dom-xss` is not exercised here because it requires `--js` (Chrome /
chromedp); add a Chromium-enabled runner if you need it in CI.

## How a new check gets covered

1. Find the closest existing container by category (passive HTTP =>
   `vuln-static`, active webapp probe => `vuln-app`, etc.).
2. Add the minimum vulnerable shape (route / header / page) that
   makes the check fire. Document the trigger inline; the .lua check
   under `internal/checks/<family>/<name>.lua` (or
   `internal/checks/platform/<middleware>/<name>.lua` for a
   protocol/CMS-specific rule) is the canonical spec.
3. Append the check name to the relevant `assertChecksFired` call in
   `integration_test.go`.

If the new check needs a runtime no existing container provides (a
distinct framework, a real DNS resolver, a TLS edge case), add a new
subdirectory + `Test*` case rather than overloading an existing image.

## TLS for vuln-static

`vuln-static` ships HTTPS so `tls-audit`, `mixed-content`, `hsts-weak`,
and `form-action-insecure` have something to bite on. Self-signed
certs would fail the scanner's default trust-store check, so the
image generates a build-time CA and exposes it at `/export/ca.crt`.
The harness copies it out via `CopyFileFromContainer` and threads it
into the in-process scan as `--ca-file`. Server cert SANs cover
`localhost` + `127.0.0.1`, which are the only addresses
testcontainers-go ever maps `:443` to.
