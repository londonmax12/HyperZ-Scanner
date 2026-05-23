# Contributing to hyperz

Thanks for your interest in helping out. hyperz is a Go-based web vulnerability
scanner and contributions of new checks, bug fixes, and documentation are all
welcome.

> Only scan systems you have explicit authorization to test. This applies to
> the examples you put in tests, issues, and PR descriptions too - prefer
> `httptest` servers or `example.com`.

## Getting started

1. Fork the repo and clone your fork.
2. Make sure you can build and test:
   ```
   go build ./cmd/hyperz
   go test ./...
   ```
3. Create a branch off `main` for your change.
4. Open a pull request against `main` when ready.

## How to contribute

- **Bugs**: open an issue with a minimal reproduction. If the bug is in a
  check, include the target's relevant response headers (sanitized) and the
  command you ran.
- **New checks**: see [Adding a check](#adding-a-check) below. Small,
  single-purpose checks are easier to review than sprawling ones.
- **Refactors**: keep them separate from feature commits so the diff stays
  reviewable.
- **Docs**: README and inline comments are fair game. Don't paraphrase the
  code - explain the *why*.

## Code style

The repo follows standard Go conventions. A few project-specific rules on top:

- **Format with `gofmt`** (or `goimports`). CI-equivalent: `gofmt -l . ` must
  print nothing.
- **One check per file** under [internal/checks/](internal/checks/), with a
  matching `_test.go` next to it.
- **Package layout**: shared types live in [internal/checks/check.go](internal/checks/check.go);
  HTTP plumbing in [internal/httpclient/](internal/httpclient/); the
  orchestrator in [internal/scanner/](internal/scanner/). Don't add new
  top-level packages without discussion.
- **Comments explain *why*, not *what***. Well-named identifiers cover the
  what. Reserve comments for hidden constraints, subtle invariants, or
  surprising trade-offs. See the doc comments in
  [internal/checks/check.go](internal/checks/check.go) for the tone.
- **No dead code, no speculative abstractions.** Three similar lines beats a
  premature helper. Delete unused code rather than commenting it out.
- **Errors**: return them; don't `log.Fatal` outside `main`. Wrap with
  `fmt.Errorf("...: %w", err)` when adding context.
- **Logging**: use the structured `slog` logger plumbed through the scanner
  rather than `fmt.Print*` from inside checks.
- **Dependencies**: keep them minimal. If a new dependency is unavoidable,
  call it out in the PR description.

## Findings

Every check returns `[]checks.Finding`. To keep reports useful:

- Set `Severity`, `CWE`, `OWASP`, and `Remediation` whenever they apply.
- Populate `Evidence` via `BuildEvidence` so reporters can show what was
  observed.
- Set `DedupeKey` via `MakeKey(check, scope, target, parts...)` with the
  narrowest scope that still represents one logical issue: `ScopeHost` for
  site-wide misconfiguration (headers, TLS, banner leaks), `ScopePage` for
  URL-specific bugs, `ScopeParam` for input-surface findings where one page
  can have multiple vulnerable inputs. The same problem shouldn't flood the
  report. Reach for the raw `MakeDedupeKey` only if `MakeKey` can't express
  the scope you need.

## Adding a check

Implement [`checks.Check`](internal/checks/check.go) and register the type in
[cmd/hyperz/checks.go](cmd/hyperz/checks.go):

```go
type MyCheck struct{}

func (MyCheck) Name() string         { return "my-check" }
func (MyCheck) Level() checks.Level  { return checks.LevelPassive }

func (MyCheck) Run(ctx context.Context, client *httpclient.Client, scope *scope.Scope, target string) ([]checks.Finding, error) {
    // ...
}
```

Pick the right `Level`:

- `LevelPassive` - only inspects responses to normal requests. No payloads.
- `LevelDefault` - crafted probes (XSS, SQLi, traversal). Auth required.
- `LevelAggressive` - noisy / heavy fuzzing. Reserve for deep scans.

Non-passive checks **must** consult `scope` before probing sub-resources
discovered on the page.

## Tests

- Every check needs a `_test.go` exercising at least: the happy path (issue
  detected), a negative case (clean response, no findings), and stable dedupe
  keys across runs. Look at [internal/checks/server_leak_test.go](internal/checks/server_leak_test.go)
  for the shape.
- Use `httptest.NewServer` to drive checks; don't hit real hosts.
- Run the full suite before opening a PR:
  ```
  go test ./...
  go vet ./...
  ```

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) for the
subject line. Examples from the existing history:

```
feat(checks): add mixed-content passive check for HTTPS pages
fix(scanner): flush in-flight findings on cancel and drain reporters
refactor(httpclient): add ReadBody helper and use it across callers
style: normalize em-dashes to hyphens in comments and docs
test: add unit tests across cmd, checks, ...
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `style`, `chore`.
The scope (in parentheses) is usually the package or subsystem touched.

Keep the subject under ~72 characters, imperative mood, no trailing period.
If you need to say more, leave a blank line and write a body explaining the
*why* of the change.

## Pull requests

- One logical change per PR. If you find yourself writing "and also..." in
  the description, split it.
- Link any related issue.
- Note anything reviewers should pay attention to: new dependencies, behavior
  changes, anything that affects the report format.
- CI must be green before merge.

## License

By contributing you agree that your contributions are licensed under the same
terms as the rest of the project (see [LICENSE](LICENSE)).
