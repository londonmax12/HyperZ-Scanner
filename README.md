# HyperZ Vulnerability Scanner 🚀

A web vulnerability scanner, written in Go.

> Only scan systems you have explicit authorization to test.

## Features

- Tiered scan modes (`passive` / `default` / `aggressive`) so you choose how
  invasive the run is - each level is a superset of the cheaper ones.
- Plugin-shaped check engine - drop in a new `checks.Check` implementation
  and register it without touching the orchestrator.
- Optional crawler with per-host scope controls (allowed hosts, ports, path
  regex include/exclude, max depth) and OpenAPI/Swagger discovery so
  documented endpoints get enqueued automatically.
- Stack fingerprinting (CMS / framework / server) caches per host and feeds
  the report; disable with `--no-fingerprint`.
- Cookie jar, HTTP Basic / Bearer auth, arbitrary custom headers, an
  optional session sentinel that halts the scan on session loss, and auto
  CSRF-token attachment for state-changing requests.
- Per-host rate limiting plus a scan-wide request budget and global RPS
  ceiling so fan-out across many hosts can't blow past a noise budget.
- Proxy pool with epsilon-greedy selection on per-proxy success rate, plus
  optional auto-scraping of public proxy lists.
- Baseline diff: re-run against a previous report and label every finding
  `new` / `persisting` / `resolved`, with `--fail-on` only gating on new
  issues.
- Text, JSON, JSONL, CSV, SARIF, Markdown, and PDF report formats
  (`--format`, `-o`).

Built-in checks:

| Check | Level | What it looks at |
| --- | --- | --- |
| `security-headers` | passive | missing or weak security response headers (HSTS, CSP, etc.) |
| `cookie-attributes` | passive | cookies missing `Secure`, `HttpOnly`, or `SameSite` |
| `cors-config` | passive | wildcard / null / credentialed CORS misconfiguration on the seed response |
| `server-leak` | passive | banner disclosure via `Server` / `X-Powered-By` |
| `tls-audit` | passive | TLS version, certificate expiry, hostname mismatch |
| `mixed-content` | passive | passive mixed content referenced from HTTPS pages |
| `cors-reflection` | default | `Access-Control-Allow-Origin` reflection probe with a crafted `Origin` |
| `open-redirect` | default | redirect parameter probing on links and forms |
| `reflected-xss` | default | reflected XSS probes across query, form, and header inputs |
| `sqli-error` | default | error-based SQL injection probes |
| `sqli-boolean` | default | boolean-based SQL injection probes |

`hyperz checks list` prints the current registry at runtime.

## Build

```
go build ./cmd/hyperz
```

## Usage

```
hyperz scan --url https://example.com
hyperz scan --url https://example.com --format json -o report.json
hyperz scan --url https://example.com --timeout 5s --user-agent "myscanner/1.0"
hyperz scan --url https://example.com --mode aggressive
hyperz scan --url https://example.com --proxy http://127.0.0.1:8080
hyperz scan --urls-file targets.txt --proxies-file proxies.txt
hyperz scan --urls-file targets.txt --scrape-proxies
hyperz scan --url https://example.com --crawl --scope-max-depth 3
hyperz scan --url https://example.com --cookie "sid=abc; theme=dark"
hyperz scan --url https://example.com --cookies-file cookies.txt
hyperz scan --url https://example.com --auth-basic user:pass
hyperz scan --url https://example.com --auth-bearer eyJhbGciOi...
hyperz scan --url https://example.com --header "X-API-Key: secret"
hyperz scan --url https://example.com --baseline last.json --fail-on high
```

Run `hyperz --help` to see every subcommand, and `hyperz scan --help` for the
full flag reference. Other useful subcommands:

```
hyperz version       # build info
hyperz formats       # list output formats
hyperz checks list   # list built-in checks and their level
```

### Scan levels

`--mode` selects how invasive the scan is. Each level includes every check
at or below it - an aggressive scan is a superset of a passive one, so you
never silently drop the cheap observations.

`--mode passive` (default) runs only observation-only checks - it inspects
responses to normal-looking requests and never sends payloads designed to
trigger vulnerabilities. Safe to point at anything you're allowed to look at.

`--mode default` adds low-risk crafted probes (XSS, SQLi, open redirect,
CORS reflection, ...) on top of the passive set. These can be logged as
attacks; only run them against systems you have explicit authorization to
test.

`--mode aggressive` adds noisy or heavy fuzzing (long wordlists, many
requests) on top of default. Likely to trip rate limits or WAFs - reserve
for explicit deep scans.

### Authentication & cookies

Use `--auth-basic user:pass` for HTTP Basic, `--auth-bearer <token>` for an
`Authorization: Bearer ...` header, or `--header "Name: Value"` (repeatable)
for any custom header (e.g. `X-API-Key`). A request that already carries the
relevant header on its own wins, so individual checks can still override.

`--cookie "name=value"` (repeatable; semicolon-separated pairs allowed) seeds
a cookie jar shared by every request, so server-issued `Set-Cookie` headers
also stick for the rest of the scan. `--cookies-file <path>` accepts either
the Netscape format that curl and browsers export, or a plain `name=value`
per line (prefix a line with `<domain> ` to scope it; otherwise the cookie is
attached to every seed host).

### Session sentinel & CSRF

`--session-check-url <url>` makes the client periodically GET that URL to
verify the session is still authenticated. The scan halts with
`session-lost` the first time the probe fails. By default any non-200 trips
the sentinel; set `--session-check-pattern <regex>` to also require the
response body to match a regex (e.g. a logged-in marker). The probe fires
every `--session-check-every` requests (default 50).

`--csrf-token-source <url>` makes hyperz fetch that URL once at startup,
parse a CSRF token out of it, and auto-attach it to every POST/PUT/PATCH/
DELETE the scanner sends. `--csrf-inject` controls placement: `auto` (form
field when the source page had a hidden input, header when it had a
`<meta name="csrf-token">`), `form`, or `header`. Override the header name
with `--csrf-header-name` and the form-field name with `--csrf-param`.

### Proxies

`--proxy` (repeatable) and `--proxies-file` accept `http://`, `https://`,
`socks5://`, and `socks5h://` URLs; bare `host:port` entries default to
`http://`. Pass `--scrape-proxies` to pull additional proxies from built-in
public lists at startup, or `--proxy-source <url>` (repeatable) to add
custom sources.

When more than one proxy is in play, requests go through a smart pool that
picks proxies via epsilon-greedy on per-proxy success rate. Bad proxies fade
out automatically; promising ones get used more. The pool distinguishes
target blocks (HTTP 403/429) from proxy errors (5xx, network) - at scan
end, hyperz prints per-proxy stats and an overall block rate so you can
tell whether the scan itself is being rejected. Tune visible rows with
`--proxy-stats-top` (default 10, 0 to hide).

### Scope

The scanner refuses to follow links outside of scope, and active checks
refuse to probe sub-resources outside of scope. By default the scope is
"any of the seed hosts, depth 2." Tune it with:

- `--scope-host <host>` (repeatable) - hostname allowed in scope. Defaults
  to the seed hosts when empty.
- `--scope-any-host` - disable host filtering entirely.
- `--scope-ports 443` or `--scope-ports 8000-8999` - restrict to a port or
  port range.
- `--scope-path-include <regex>` / `--scope-path-exclude <regex>`
  (repeatable) - URL path must match ANY include and must NOT match any
  exclude.
- `--scope-max-depth N` - max crawl depth from any seed; `0` = seeds only,
  `-1` = unlimited.

### Crawling & API discovery

`--crawl` walks each seed URL, enqueuing every same-scope page it finds.
`--max-pages` caps the total queue (`0` = unlimited) and `--crawl-workers`
sets the number of parallel fetchers.

`--api-discovery` (on by default when `--crawl` is set) probes well-known
OpenAPI / Swagger paths on each seed origin and enqueues every documented
endpoint as an additional crawl target.

### Rate limiting & request budget

- `--rate` / `--burst` set the per-host RPS and burst (default 5 RPS,
  burst 5).
- `--rate-global` / `--burst-global` layer a scan-wide RPS ceiling on top
  so fan-out across many hosts can't slip past a noise budget.
- `--max-requests N` caps the total number of HTTP requests across the
  whole scan; once hit, in-flight findings are flushed and further requests
  fail fast with `scan-request-budget-exhausted`.
- `--max-retries` / `--max-retry-wait` control retry behavior on 429/503;
  the client honors `Retry-After` up to the cap.

### Baseline diff & fail-on

Pass `--baseline <path>` to diff against a previous report. Every emitted
finding gets a `diff_status`: `new` (absent from baseline), `persisting`
(also in baseline), or `resolved` (in baseline but not in this run). Only
formats that round-trip dedupe keys cleanly work as baselines (`json`,
`jsonl`, `csv`, `sarif`); override autodetection with `--baseline-format`.

`--fail-on <severity>` (default `medium`) makes hyperz exit `1` when any
finding's severity is at or above that level. With `--baseline`, only `new`
findings count toward the gate. Set `--fail-on none` to disable the gate
entirely.

Exit codes:

- `0` - scan completed cleanly and nothing tripped `--fail-on`.
- `1` - scan completed but at least one finding (or `new` finding with a
  baseline) is at or above `--fail-on`.
- `2` - scan or tool error (bad input, proxy load failure, report write
  error, check error).
- `130` - SIGINT / SIGTERM.

## Layout

```
cmd/hyperz/          CLI entrypoint
internal/scanner/    orchestrator that runs checks against a target
internal/crawler/    crawler, HTML link extractor, robots.txt, sitemap,
                     OpenAPI/Swagger discovery
internal/httpclient/ shared HTTP client, host limiter, budget, session
                     sentinel, CSRF middleware
internal/checks/     Check interface + Finding type, one check per file
internal/fingerprint/ stack detection rules and per-host cache
internal/scope/      host/port/path/depth scope rules
internal/page/       crawler -> check page artifact
internal/report/     text / JSON / JSONL / CSV / SARIF / Markdown / PDF
                     reporters, dedupe, baseline diff
```

## Adding a check

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. The short version:
implement the `checks.Check` interface and register it in the catalog at
[cmd/hyperz/checks.go](cmd/hyperz/checks.go):

```go
type MyCheck struct{}

func (MyCheck) Name() string        { return "my-check" }
func (MyCheck) Level() checks.Level { return checks.LevelPassive } // or LevelDefault / LevelAggressive

func (MyCheck) Run(ctx context.Context, client *httpclient.Client, scope *scope.Scope, p page.Page) ([]checks.Finding, error) {
    // ...
}
```
