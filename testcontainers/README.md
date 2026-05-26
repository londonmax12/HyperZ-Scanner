# testcontainers/

Vulnerable Docker targets + a testcontainers-go harness that exercises
every check in the scanner catalog. Each target image is deliberately
broken in a different way; the harness builds the image, spawns the
container, runs the `hyperz` binary against it, and asserts the
expected set of check names appears in the JSON report.

## Run

Requires Docker and Go 1.22+. The harness is its own Go module, so
run it from inside this directory (not via `./testcontainers/...`
from the repo root, which `go test` won't follow across modules):

```bash
cd testcontainers
go test -tags integration -v -timeout 20m ./...
```

`-v` is recommended so you see per-phase progress: image build, container
start, hyperz invocation, finding count, and which required checks
fired. Without `-v`, `go test` buffers all `t.Logf` output until a test
fails - the suite looks idle even when it's working.

The separate module keeps testcontainers-go's transitive deps out of
the scanner's `go.mod`. The `integration` build tag keeps
`go test ./...` in the parent module Docker-free.

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

`dom-xss` is not exercised here because it requires `--js` (Chrome /
chromedp); add a Chromium-enabled runner if you need it in CI.

## How a new check gets covered

1. Find the closest existing container by category (passive HTTP =>
   `vuln-static`, active webapp probe => `vuln-app`, etc.).
2. Add the minimum vulnerable shape (route / header / page) that
   makes the check fire. Document the trigger inline; the .lua check
   under `internal/checks/<name>.lua` is the canonical spec.
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
The harness copies it out via `CopyFileFromContainer` and points the
hyperz subprocess at it with `SSL_CERT_FILE` (the standard Go env
var). Server cert SANs cover `localhost` + `127.0.0.1`, which are
the only addresses testcontainers-go ever maps `:443` to.
