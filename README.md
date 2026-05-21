# hyperz

A web vulnerability scanner, written in Go.

> Only scan systems you have explicit authorization to test.

## Status

Minimal skeleton: CLI + HTTP client + one example check (missing security
response headers). The check engine is plugin-shaped so more checks can be added
without touching the orchestrator.

## Build

```
go build ./cmd/hyperz
```

## Usage

```
hyperz -url https://example.com
hyperz -url https://example.com -format json
hyperz -url https://example.com -timeout 5s -user-agent "myscanner/1.0"
hyperz -url https://example.com -mode active
hyperz -url https://example.com -proxy http://127.0.0.1:8080
hyperz -urls-file targets.txt -proxies-file proxies.txt
hyperz -urls-file targets.txt -scrape-proxies
```

### Modes

`-mode passive` (default) runs only observation-only checks — it inspects
responses to normal-looking requests and never sends payloads designed to
trigger vulnerabilities. Safe to point at anything you're allowed to look at.

`-mode active` adds intrusive probes (XSS, SQLi, traversal, etc.) on top of
the passive set. Active scans can be logged as attacks; only run them
against systems you have explicit authorization to test.

### Proxies

`-proxy` (repeatable) and `-proxies-file` accept `http://`, `https://`,
`socks5://`, and `socks5h://` URLs; bare `host:port` entries default to
`http://`. Pass `-scrape-proxies` to pull additional proxies from built-in
public lists at startup, or `-proxy-source <url>` (repeatable) to add custom
sources.

When more than one proxy is in play, requests go through a smart pool that
picks proxies via epsilon-greedy on per-proxy success rate. Bad proxies fade
out automatically; promising ones get used more. The pool distinguishes
target blocks (HTTP 403/429) from proxy errors (5xx, network) — at scan end,
hyperz prints per-proxy stats and an overall block rate so you can tell
whether the scan itself is being rejected. Tune visible rows with
`-proxy-stats-top` (default 10, 0 to hide).

## Layout

```
cmd/hyperz/          CLI entrypoint
internal/scanner/    orchestrator that runs checks against a target
internal/httpclient/ shared HTTP client
internal/checks/     Check interface + Finding type, one check per file
internal/report/     text / JSON output
```

## Adding a check

Implement the `checks.Check` interface and register it in
[cmd/hyperz/main.go](cmd/hyperz/main.go):

```go
type MyCheck struct{}

func (MyCheck) Name() string      { return "my-check" }
func (MyCheck) Mode() checks.Mode { return checks.ModePassive } // or ModeActive

func (MyCheck) Run(ctx context.Context, client *httpclient.Client, target string) ([]checks.Finding, error) {
    // ...
}
```
