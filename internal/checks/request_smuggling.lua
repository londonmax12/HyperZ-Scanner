-- request-smuggling: Lua port of internal/checks/request_smuggling.go.
--
-- Probes the target's front-end / back-end parser pair for HTTP
-- request-framing desynchronization (CL.TE, TE.CL, H2.CL). All
-- probes are timing-only: the connection-level hang IS the signal,
-- so no smuggled suffix lands on another user's connection and the
-- only state disturbed is the single connection the probe rode in on.
--
-- Architecture mirrors jwt-vulns / race-condition: the SCAN
-- ALGORITHM (raw-socket HTTP/1.1 framing, hand-rolled HPACK + h2
-- frames, baseline measurement, timing oracle) lives in Go and is
-- exposed through ctx.smuggling.scan as a raw FACTS shape. The Lua
-- port reads per-variant timings + the timing-oracle's confirmed
-- bool, picks the first confirmed variant to surface (or returns
-- nothing on a clean host), and composes severity / title / detail /
-- remediation / dedupe-key here. Per-host caching keeps multi-page
-- scans cheap; the Lua port consults ctx.smuggling.scan().from_cache
-- to decide whether to re-emit on subsequent pages.
--
-- Level: Aggressive. The probes are deliberately malformed and many
-- production WAFs will log or block the source IP; loads only when
-- the operator opts in via --pollute, alongside the other state-
-- mutating / disruptive checks.

local check = {
  name        = "request-smuggling",
  level       = "aggressive",
  scope       = "host",
  cwe         = "CWE-444",
  owasp       = "A03:2021 Injection",
  remediation = "Normalize request framing at the front-end: reject any HTTP/1.1 request that "
    .. "carries both Content-Length and Transfer-Encoding, and reject any Transfer-Encoding "
    .. "value other than \"chunked\". For HTTP/2 front-ends, validate that content-length matches "
    .. "the actual DATA frame size before downgrading to an HTTP/1.1 back-end, or use HTTP/2 end-to-end. "
    .. "Configure both front-end and back-end to use identical HTTP parsers where possible, and "
    .. "disable HTTP keep-alive on the front-to-back connection if the framing risk cannot be "
    .. "eliminated at the parser level.",
  budget_seconds = 300,
  pollute = true,
}

-- first_confirmed_variant returns the first variant entry with
-- confirmed=true, or nil when the scan produced no confirmed
-- variants. Mirrors the Go check's per-host emit policy: one
-- finding per host, attributed to the first variant that crossed
-- the timing oracle's threshold on both probes.
local function first_confirmed_variant(variants)
  for _, v in ipairs(variants) do
    if v.confirmed then return v end
  end
  return nil
end

-- format_ms renders a millisecond integer as the "1.234s"-style
-- string the Go check stamps via time.Duration.Round(time.Millisecond).
-- Sub-second values stay in ms; second-scale and beyond render as
-- seconds with three decimal places. Centralised so the Lua composer
-- and the Go-side text agree on the units we surface.
local function format_ms(ms)
  if ms < 1000 then
    return string.format("%dms", ms)
  end
  local secs = ms / 1000.0
  -- Strip trailing zeros to match the Go duration formatter ("1s",
  -- "1.5s", "1.234s") without writing a parser. Format with 3 dp,
  -- then trim "0+$" and the dangling dot.
  local s = string.format("%.3fs", secs)
  s = s:gsub("0+s$", "s")
  s = s:gsub("%.s$", "s")
  return s
end

-- compose_finding lifts a confirmed variant into the finding shape.
-- Every operator-visible field is composed here: severity (High,
-- since confirmed front/back parser disagreement is reliably
-- exploitable for cache poisoning + auth bypass), title, detail,
-- evidence, dedupe parts. The remediation, CWE / OWASP come from
-- the module's catalog metadata.
local function compose_finding(ctx, host_key, page_url, v)
  local baseline_label = format_ms(v.baseline_ms)
  local probe1_label   = format_ms(v.probe1_ms)
  local probe2_label   = format_ms(v.probe2_ms)
  local threshold_label = format_ms(v.threshold_ms)

  local detail = string.format(
    "The front-end and back-end disagree on request framing (%s variant: %s). "
    .. "A timing-only probe induced a back-end hang on two independent attempts "
    .. "(baseline %s, probe-1 %s, probe-2 %s); the threshold for confirmation "
    .. "was %s above baseline. An attacker can exploit this disagreement to "
    .. "smuggle a request prefix onto another user's connection, enabling "
    .. "cache poisoning, header injection, session fixation, and bypass of "
    .. "front-end security controls (WAF, auth proxies, ACLs).",
    v.label, v.description,
    baseline_label, probe1_label, probe2_label, threshold_label)

  local snippet = string.format(
    "Variant: %s (front=%s, back=%s)\nBaseline: %s\nProbe 1:  %s\nProbe 2:  %s\nThreshold: %s above baseline (or absolute floor)\n",
    v.label, v.front_end, v.back_end,
    baseline_label, probe1_label, probe2_label, threshold_label)

  return {
    severity = ctx.severity.high,
    target   = page_url,
    url      = page_url,
    title    = string.format("HTTP request smuggling (%s desynchronization)", v.label),
    detail   = detail,
    evidence = ctx.evidence.build {
      method  = "POST",
      url     = host_key,
      snippet = snippet,
    },
    -- Match the Go check's dedupe shape: scope=host, parts carry the
    -- variant label so a single host with two confirmed variants
    -- (rare but possible) collapses to one finding per variant.
    -- We honour the per-host emit policy by picking just one variant
    -- in first_confirmed_variant, but the key shape stays variant-
    -- specific in case a future tweak surfaces every confirmed
    -- variant per host.
    dedupe_parts = { v.label },
  }
end

function check.run(ctx)
  local host_fact, err = ctx.smuggling.scan("framing")
  if err then return nil, err end
  if host_fact == nil then return nil end

  local v = first_confirmed_variant(host_fact.variants)
  if v == nil then return nil end

  return { compose_finding(ctx, host_fact.host_key, ctx.page.url, v) }
end

return check
