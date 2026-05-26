<div align="center">

# 🚀 HyperZ

**A modern web vulnerability scanner, written in Go.**

[![Go Version](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Checks](https://img.shields.io/badge/checks-50-success)](#-checks)
[![Modes](https://img.shields.io/badge/modes-passive%20%7C%20default%20%7C%20aggressive-orange)](#scan-modes)

`security-headers` · `tls-audit` · `sqli` · `xss` · `ssrf` · `xxe` · `graphql-audit` · `jwt-vulns` · `request-smuggling` · `race-condition` · …

</div>

---

> ⚠️  **Authorization required.** Only point this at systems you own or have
> explicit written permission to test. Default mode is observation-only, but
> `--mode default` and above send crafted payloads that intermediate WAFs,
> SIEMs, and on-call humans will see as attacks.

---

## ✨ Why HyperZ?

- **Tiered, predictable surface.** Three scan levels (`passive` / `default` /
  `aggressive`) form a strict superset, so an aggressive scan never silently
  drops a cheap observation. Pick the level, get every check at or below it.
- **Out-of-band first-class.** Built-in `--oob` HTTP listener threads canary
  URLs into blind SSRF / XXE / SSTI / command-injection probes - findings
  fire when a target *actually* calls back, not on flaky timing heuristics.
- **Real browser when you need one.** `--js` spins up a headless
  Chrome/Chromium pool for DOM-based checks (`dom-xss`). Off by default;
  costs nothing when you don't need it.
- **CI-friendly diffs.** `--baseline` annotates every finding `new` /
  `persisting` / `resolved`, and `--fail-on` gates only on *new* issues -
  drop it into a pipeline without re-flagging known debt.
- **Doesn't blow up your target.** Per-host rate limits, a scan-wide RPS
  ceiling, request budget, retry-with-`Retry-After`, and a session sentinel
  that halts on session loss. Proxy pool with epsilon-greedy ranking on
  per-proxy success rate, plus optional auto-scraping.
- **Lua-defined checks.** Detection logic lives in `internal/checks/*.lua`,
  one file per check, executed by an embedded Lua VM against typed Go
  bridges for HTTP, cookies, OOB, browser, scope, and the rest. Editing a
  finding's prose, severity, or dedupe shape doesn't require rebuilding Go.
- **Seven report formats.** Text, JSON, JSONL, CSV, SARIF, Markdown, PDF.

---

## 🚀 Quick start

```bash
# build
go build ./cmd/hyperz

# fastest path - passive observations against a single target
./hyperz scan --url https://example.com

# active probes + crawler, structured output
./hyperz scan \
  --url https://example.com \
  --crawl --scope-max-depth 3 \
  --mode default \
  --format sarif -o report.sarif

# blind-vuln callbacks via the built-in OOB listener
./hyperz scan \
  --url https://example.com \
  --mode default \
  --oob --oob-host scanner.example.com:7777

# CI: diff against last run, fail only on NEW high-or-above findings
./hyperz scan \
  --url https://example.com \
  --mode default \
  --baseline last-scan.json \
  --fail-on high \
  --format json -o this-scan.json
```

Inspect the catalog any time:

```bash
hyperz checks list   # name + level for every built-in check
hyperz formats       # supported output formats
hyperz version       # build info
```

---

## 📚 Table of contents

- [Checks](#-checks)
- [Scan modes](#scan-modes)
- [Authentication & cookies](#authentication--cookies)
- [Session sentinel & CSRF](#session-sentinel--csrf)
- [Proxies](#proxies)
- [Scope](#scope)
- [Crawling & API discovery](#crawling--api-discovery)
- [Out-of-band callbacks (`--oob`)](#out-of-band-callbacks---oob)
- [Headless browser (`--js`)](#headless-browser---js)
- [State-mutating checks (`--pollute`)](#state-mutating--disruptive-checks---pollute)
- [Concurrency & rate limiting](#concurrency-rate-limiting--request-budget)
- [Logging](#logging)
- [Baseline diff & fail-on](#baseline-diff--fail-on)
- [Project layout](#project-layout)
- [Adding a check](#adding-a-check)

---

## 🔍 Checks

`hyperz checks list` prints the live registry at runtime. The grouping below
mirrors `--mode`: each level is a superset of the cheaper ones.

<details open>
<summary><b>🟢 Passive</b> &nbsp;<i>observation-only, safe to point at anything you're allowed to look at</i></summary>

| Check | What it looks at |
| --- | --- |
| `security-headers` | missing or weak security response headers (HSTS, CSP, etc.) |
| `cookie-attributes` | cookies missing `Secure`, `HttpOnly`, or `SameSite` |
| `cache-control-sensitive` | sensitive responses served without `Cache-Control: no-store` |
| `csp-weak` | Content-Security-Policy weakness (`unsafe-inline`/`unsafe-eval`, wildcard sources, missing directives) |
| `hsts-weak` | HSTS missing, short `max-age`, no `includeSubDomains`, no `preload` |
| `cross-origin-isolation` | missing / weak COOP, COEP, CORP headers |
| `form-autocomplete` | sensitive form inputs missing `autocomplete=off` / `new-password` |
| `form-action-insecure` | form posts over plain HTTP from an HTTPS page |
| `cors-config` | wildcard / null / credentialed CORS misconfiguration on the seed response |
| `server-leak` | banner disclosure via `Server` / `X-Powered-By` |
| `secrets-in-body` | API keys, tokens, private keys, and other secrets leaking in response bodies |
| `oauth-discovery` | OAuth/OIDC metadata exposure and misconfiguration on well-known discovery endpoints |
| `openapi-audit` | OpenAPI / Swagger documents at well-known paths audited for embedded credentials, example auth headers, and auth-less operations |
| `tls-audit` | TLS version, cipher, OCSP stapling, SCT, cert chain expiry, hostname mismatch |
| `mixed-content` | passive mixed content referenced from HTTPS pages |
| `js-libs-known-vuln` | bundled JS libraries detected at known-vulnerable versions |
| `sri-missing` | external `<script>` / `<link>` tags missing Subresource Integrity hashes |
| `source-map-exposure` | `.map` files served alongside JS / CSS that expose original source |
| `target-blank-noopener` | `target="_blank"` anchors missing `rel="noopener"` |
| `subdomain-takeover` | dangling CNAMEs pointing at unclaimed SaaS providers |

</details>

<details>
<summary><b>🟡 Default</b> &nbsp;<i>low-risk crafted probes; intermediate WAFs/SIEMs will see these</i></summary>

| Check | What it looks at |
| --- | --- |
| `cors-reflection` | `Access-Control-Allow-Origin` reflection probe with a crafted `Origin` |
| `csp-bypass` | active probes for known CSP bypass techniques (JSONP endpoints, allowed-host script gadgets) |
| `open-redirect` | redirect parameter probing on links and forms |
| `host-header-injection` | `Host` / `X-Forwarded-Host` rewrite probes |
| `cache-poisoning` | unkeyed-input poisoning probes via header / query reflection that survives in cached responses |
| `crlf-injection` | CR/LF header-splitting probes on URL and header inputs |
| `ssrf` | server-side request forgery probes against URL-bearing parameters (OOB-aware) |
| `reflected-xss` | reflected XSS probes across query, form, and header inputs |
| `dom-xss` | DOM-based XSS probes executed in a headless browser (requires `--js`) |
| `sqli-error` | error-based SQL injection probes |
| `sqli-boolean` | boolean-based SQL injection probes |
| `sqli-time` | time-based blind SQL injection probes |
| `nosqli` | NoSQL operator injection probes (Mongo-style operators, JS payloads) |
| `ldapi` | LDAP injection probes against search/auth parameters |
| `path-traversal` | `../` traversal probes against path-bearing parameters |
| `cmd-injection` | in-band OS command injection probes |
| `cmd-injection-blind` | out-of-band / time-based command injection probes (OOB-aware) |
| `ssti` | server-side template injection probes (expression-eval, error-based, and OOB) across major template engines |
| `insecure-deserialization` | language-specific gadget probes for unsafe deserialization sinks |
| `xxe` | XML external entity probes, including OOB DTD exfil and `php://filter` base64 paths |
| `graphql-audit` | introspection exposure, suggestion leakage, alg-confusion / batched-query abuse on GraphQL endpoints |
| `ws-audit` | WebSocket handshake misconfiguration (origin enforcement, subprotocol, auth carryover) |
| `sse-audit` | Server-Sent Events misconfiguration (CORS, auth carryover, leaking event channels) |
| `content-discovery` | directory and file brute-forcing against allowed roots |

</details>

<details>
<summary><b>🔴 Aggressive</b> &nbsp;<i>heavy fuzzing, long wordlists, likely to trip rate limits or WAFs</i></summary>

| Check | What it looks at |
| --- | --- |
| `idor` | insecure direct object reference probing on numeric / UUID identifiers |

</details>

<details>
<summary><b>☢️  Pollute-gated</b> &nbsp;<i>state-mutating or disruptive; require <code>--pollute</code></i></summary>

| Check | Level | What it does |
| --- | --- | --- |
| `proto-pollution` | aggressive | pollutes `Object.prototype` on a vulnerable Node target with best-effort cleanup afterward |
| `stored-xss` | default | plants XSS canaries that **persist past the storage boundary** (no cleanup) |
| `request-smuggling` | aggressive | CL/TE/H2 desync probes over a raw socket - timing-only, but loud |
| `jwt-vulns` | aggressive | alg=none, alg-confusion, kid-as-URL, offline HMAC brute force, crit-abuse forgery |
| `race-condition` | aggressive | parallel-request races on state-changing endpoints (double-spend, coupon reuse, …) |

</details>

---

## Scan modes

`--mode` selects how invasive the scan is. Each level includes every check
at or below it - an aggressive scan is a superset of a passive one, so you
never silently drop the cheap observations.

| Mode | Sends payloads? | What gets added |
| --- | --- | --- |
| `passive` (default) | no | response inspection only - HSTS, CSP, cookie flags, TLS audit, secret-pattern scanning, ... |
| `default` | yes (low-risk) | XSS, SQLi, open redirect, CORS reflection, CRLF, SSRF, XXE, GraphQL/WS/SSE audit, ... |
| `aggressive` | yes (noisy) | long-wordlist content discovery, IDOR sweep, ... |

`--pollute` is orthogonal: it gates state-mutating and disruptive checks
that can leave a footprint on the target even at the level they normally
run at. See [State-mutating checks](#state-mutating--disruptive-checks---pollute).

---

## Authentication & cookies

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

## Session sentinel & CSRF

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

## Proxies

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

## Scope

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

## Crawling & API discovery

`--crawl` walks each seed URL, enqueuing every same-scope page it finds.
`--max-pages` caps the total queue (`0` = unlimited) and `--crawl-workers`
sets the number of parallel fetchers.

`--api-discovery` (on by default when `--crawl` is set) probes well-known
OpenAPI / Swagger paths on each seed origin and enqueues every documented
endpoint as an additional crawl target.

## Out-of-band callbacks (`--oob`)

`--oob` enables the out-of-band callback backbone. The scanner starts a
built-in HTTP listener and threads canary URLs into blind SSRF, XXE, SSTI,
and command-injection probes - findings fire when a target's request
actually reaches the listener, instead of relying on in-band oracles alone.

| Flag | Purpose |
| --- | --- |
| `--oob-listen` | bind address for the built-in listener (`host:port` or `:port`; default `:7777`). Only used when `--oob` is set. |
| `--oob-host` | **required** when `--oob` is set. The `host:port` targets see in canary URLs (e.g. `scanner.example.com:7777`). Usually matches `--oob-listen` unless a reverse proxy or port-forward sits in front. |
| `--oob-wait` | how long the scanner waits after the active phase before draining OOB hits (default `10s`). Async fetch queues and slow webhooks routinely take seconds to fire. |

## Headless browser (`--js`)

`--js` enables the headless-browser pool used by DOM-based checks
(`dom-xss`). The scanner launches one Chrome/Chromium process at scan start
and opens up to `--js-concurrent` tabs at a time (default 4). Requires a
Chrome/Chromium binary on `PATH`. Off by default; DOM checks need a real
engine and the dependency is heavier than the rest of the scanner.

## State-mutating & disruptive checks (`--pollute`)

`--pollute` opts the scan into actions that can leave a footprint on - or
deliberately misbehave against - the target. Off by default; only turn it
on against systems you have explicit authorization to mutate or disrupt.

When set, the following changes apply:

- The crawler walks select-driven navigation forms: any
  `<form method="POST">` whose only meaningful input is a single `<select>`
  (plus hidden / submit controls) gets POSTed once per `<option>`, and the
  redirect target each submission lands on gets enqueued. This is what
  bWAPP-style portals, lots of CMS admin panels, and legacy PHP control
  panels use for navigation. Forms with visible text / file inputs are
  never walked - those are almost certainly real submissions, not nav.
- `proto-pollution` is loaded. It pollutes `Object.prototype` on a
  vulnerable Node target with a best-effort cleanup payload afterward;
  even with cleanup, a successful finding implies a (now-neutralized)
  modification to the target's shared state.
- `stored-xss` is loaded. It plants XSS canaries on storage-backed
  surfaces and verifies they survive across requests. The canaries
  **persist until the operator removes them** - the whole point of the
  check is the payload surviving the storage boundary, so there is no
  cleanup pass.
- `request-smuggling` is loaded. It sends deliberately malformed CL/TE/H2
  requests over a raw socket. Timing-only, so no smuggled suffix lands on
  the next user's connection, but the traffic is loud and some front-ends
  will log or block the source IP.
- `jwt-vulns` is loaded. It forges alg=none, alg-confusion, kid-as-URL,
  and crit-abuse tokens against the application, and brute-forces HMAC
  secrets offline against intercepted tokens.
- `race-condition` is loaded. It fires parallel-request races against
  state-changing endpoints looking for non-idempotent windows (double
  spend, coupon reuse, etc.).

## Concurrency, rate limiting & request budget

- `--concurrency` sets the number of targets scanned in parallel (default
  8); `--check-concurrency` caps how many checks fan out per target
  (default 16, `0` = unlimited).
- `--rate` / `--burst` set the per-host RPS and burst (default 5 RPS,
  burst 5).
- `--rate-global` / `--burst-global` layer a scan-wide RPS ceiling on top
  so fan-out across many hosts can't slip past a noise budget.
- `--max-requests N` caps the total number of HTTP requests across the
  whole scan; once hit, in-flight findings are flushed and further requests
  fail fast with `scan-request-budget-exhausted`.
- `--max-retries` / `--max-retry-wait` control retry behavior on 429/503;
  the client honors `Retry-After` up to the cap.

## Logging

`--log-level` controls verbosity (`debug` | `info` | `warn` | `error`);
`debug` surfaces per-target check skip events. `--log-format text` (the
default) prints `key=value` records; `--log-format json` emits one JSON
record per line, ready to pipe into `jq`.

## Baseline diff & fail-on

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

| Code | Meaning |
| --- | --- |
| `0` | scan completed cleanly and nothing tripped `--fail-on` |
| `1` | scan completed; at least one finding (or `new` finding with a baseline) is at or above `--fail-on` |
| `2` | scan or tool error (bad input, proxy load failure, report write error, check error) |
| `130` | SIGINT / SIGTERM |

---

## 🗂️ Project layout

```
cmd/hyperz/           CLI entrypoint, flag wiring, check catalog, auth wiring
internal/scanner/     orchestrator that runs checks against a target
internal/core/        Check interface, Finding / Evidence / Exchange types,
                      severity / level / scope, context plumbing for OOB,
                      browser pool, fingerprint, per-check budget
internal/checks/      one .lua file per check, embedded into the binary at
                      build time; detection logic lives here
internal/lua_engine/  embedded Lua VM, Go-side helper bridges (HTTP, cookies,
                      OOB, browser, scope, payloads, ...) and per-check Go
                      shims for operations Lua can't do directly
internal/crawler/     crawler, HTML link extractor, robots.txt, sitemap,
                      OpenAPI/Swagger discovery
internal/httpclient/  shared HTTP client, host limiter, budget, session
                      sentinel, CSRF middleware
internal/proxy/       proxy loader, scraper, epsilon-greedy pool, transport
internal/oob/         out-of-band HTTP listener, canary URL minting,
                      registered-asset serving
internal/browser/     headless Chrome/Chromium pool for DOM-driven checks
internal/fingerprint/ stack detection rules and per-host cache
internal/scope/       host/port/path/depth scope rules
internal/page/        crawler -> check page artifact
internal/report/      text / JSON / JSONL / CSV / SARIF / Markdown / PDF
                      reporters, dedupe, baseline diff
```

## 🛠️ Adding a check

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. The short version:
drop a new `internal/checks/<name>.lua` file. The Lua VM picks it up via
[internal/checks/embed.go](internal/checks/embed.go) on the next build and
the catalog command (`hyperz checks list`) reflects it automatically.

```lua
local check = {
  name  = "my-check",
  level = "passive",     -- or "default" / "aggressive"
  scope = "host",        -- or "page" / "param"
  owasp = "A05:2021 Security Misconfiguration",
}

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err or not snap then return end

  if snap.headers["X-Sloppy"] then
    ctx:emit({
      severity    = ctx.severity.medium,
      title       = "X-Sloppy header exposed",
      detail      = "Response carried X-Sloppy at " .. ctx.page.url,
      cwe         = "CWE-200",
      remediation = "Drop the X-Sloppy header at the edge.",
    })
  end
end

return check
```

If a check needs an operation Lua can't reach directly (raw sockets, the
headless browser, the OOB listener, parsing nuance you'd rather keep in
Go), add a typed bridge under [internal/lua_engine/](internal/lua_engine/)
and call it from the Lua side. The bridge is the seam: detection logic
stays in `.lua`, Go-only primitives live in `internal/lua_engine/api_*.go`.

---

## 📄 License

[MIT](LICENSE) © London Ball
