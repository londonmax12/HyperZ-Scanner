-- request-smuggling: probes the target's front-end / back-end parser
-- pair for HTTP request-framing desynchronization (CL.TE, TE.CL,
-- H2.CL). All probes are timing-only: the connection-level hang IS
-- the signal, so no smuggled suffix lands on another user's
-- connection and the only state disturbed is the single connection
-- the probe rode in on.
--
-- The scan algorithm (raw-socket HTTP/1.1 framing, hand-rolled HPACK
-- + h2 frames, baseline measurement, timing oracle) sits behind
-- ctx.smuggling.scan, which returns raw per-variant facts. This file
-- picks the first confirmed variant and composes the finding. Per-
-- host caching keeps multi-page scans cheap; ctx.smuggling.scan().from_cache
-- tells us whether to re-emit on later pages.
--
-- Level: Aggressive. The probes are deliberately malformed and many
-- production WAFs will log or block the source IP; loads only when
-- the operator opts in via --pollute.

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

-- One finding per host, attributed to the first variant that crossed
-- the timing oracle's threshold on both probes. Returns nil when no
-- variant confirmed.
local function first_confirmed_variant(variants)
  for _, v in ipairs(variants) do
    if v.confirmed then return v end
  end
  return nil
end

-- format_ms renders a millisecond integer as a human-readable
-- duration. Sub-second stays in ms; second-scale and beyond render as
-- seconds with up to three decimals, trailing zeros stripped.
local function format_ms(ms)
  if ms < 1000 then
    return string.format("%dms", ms)
  end
  local secs = ms / 1000.0
  local s = string.format("%.3fs", secs)
  s = s:gsub("0+s$", "s")
  s = s:gsub("%.s$", "s")
  return s
end

-- compose_finding lifts a confirmed variant into the finding shape.
-- Severity is High: confirmed front/back parser disagreement is
-- reliably exploitable for cache poisoning + auth bypass.
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
    -- Variant label in the dedupe key keeps the shape future-proof if
    -- we ever surface every confirmed variant per host; today
    -- first_confirmed_variant only picks one.
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
