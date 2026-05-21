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
hyperz -url https://example.com -proxy http://127.0.0.1:8080
hyperz -urls-file targets.txt -proxies-file proxies.txt
```

### Proxies

`-proxy` (repeatable) and `-proxies-file` accept `http://`, `https://`,
`socks5://`, and `socks5h://` URLs; bare `host:port` entries default to
`http://`. Multiple proxies are used round-robin across requests. A follow-up
will add auto-scraping and block-rate-aware cycling.

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

func (MyCheck) Name() string { return "my-check" }

func (MyCheck) Run(ctx context.Context, client *httpclient.Client, target string) ([]checks.Finding, error) {
    // ...
}
```
