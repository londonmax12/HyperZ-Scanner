-- open-redirect: probes whether a target reflects an attacker-
-- controlled URL parameter into its redirect Location (header), into
-- a JavaScript navigation API (location.assign / .href / .replace,
-- window.location), or into a meta-refresh tag. A canary on the
-- reserved .example domain serves as the probe target; any 3xx
-- Location pointing at the canary host - or any body sink pointing
-- at it - means the input is unvalidated.

local check = {
  name        = "open-redirect",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-601",
  owasp       = "A01:2021 Broken Access Control",
  remediation = "Validate the redirect target against an allowlist of trusted hosts "
                .. "(or restrict to same-origin paths). Never use unvalidated user input "
                .. "as a Location value; map opaque tokens to known destinations instead.",
  consumes    = {"page", "param"},
}

-- RFC 2606 .example so the host is guaranteed unregistered. The
-- path marker makes the probe easy to spot in target access logs.
local CANARY      = "https://evil.example/hyperz-probe"
local CANARY_HOST = "evil.example"

-- Bound the response body we read for evidence and body-sink scan.
-- 32 KiB is large enough to cover the <head> + early <body> where
-- soft-redirect scripts typically live, without exposing the check
-- to a runaway response on a page that doesn't have one.
local BODY_CAP = 32 * 1024

-- Curated, not exhaustive: every additional name is one more probe
-- per scanned URL. The open-set of existing query params on the
-- target URL already catches app-specific cases.
local CANONICAL_PARAMS = {
  "continue", "dest", "destination", "goto",
  "next", "redir", "redirect", "redirect_uri",
  "redirect_url", "return", "returnTo", "returnUrl",
  "return_url", "target", "url",
}

-- Forward declaration: probe is defined below check.run so the run
-- function reads top-down, but Lua needs the local in scope at the
-- call site - this captures the upvalue the `function probe(...)`
-- assignment below fills in.
local probe

function check.run(ctx)
  local u, err = ctx.url.parse(ctx.page.url)
  if err or not u or u.scheme == "" or u.host == "" then
    -- Unparseable target is not a finding, and returning an error
    -- would pollute the scan summary with noise that has nothing
    -- to do with the check.
    return nil
  end
  -- Non-passive checks must consult scope before probing. The
  -- scanner only dispatches in-scope targets, but the contract
  -- says checks re-affirm before sending crafted traffic.
  if not ctx.scope:allows(ctx.page.url) then
    return nil
  end

  local sweep = ctx:level_at_least("aggressive") or ctx.url.looks_redirectish(u.path)
  local candidates = ctx.sinks.for_page {
    sweep_params = sweep and CANONICAL_PARAMS or nil,
  }

  local findings = {}
  local first_err = nil
  for _, sink in ipairs(candidates) do
    -- Sub-scope check: a sink discovered on a form whose action is
    -- off-host (or off-scope) must not be probed even though the
    -- page-level scope check above passed. Skip silently rather
    -- than erroring - off-scope sinks aren't probe failures.
    if ctx.scope:allows(sink.url) then
      local finding, probe_err = probe(ctx, sink)
      if probe_err then
        ctx:report("probe param " .. sink.name .. ": " .. probe_err)
        if first_err == nil then first_err = probe_err end
      elseif finding then
        findings[#findings + 1] = finding
      end
    end
  end
  -- Only surface an error when we have nothing to show - the
  -- scanner discards findings on error, so a single transient
  -- probe failure shouldn't erase hits the other probes turned
  -- up. Wholesale failure (e.g. unreachable host) still propagates
  -- because every probe errored.
  if first_err and #findings == 0 then
    return nil, first_err
  end
  return findings
end

-- probe issues one no-follow request with the canary overlaid onto
-- sink.name. The request shape (GET-with-query, POST form, header,
-- cookie) is decided by sink:mutate_request, so this function stays
-- loc-agnostic.
function probe(ctx, sink)
  local req, mut_err = sink:mutate_request(CANARY)
  if mut_err then return nil, mut_err end

  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, do_err end

  -- Header sink dispatched first so the answer is a single header
  -- read; the body is then loaded once for both evidence and the
  -- body-sink scan, avoiding a double read when a page bounces
  -- through both channels.
  local sink_kind, sink_payload = "", ""
  if ctx.url.is_redirect_status(resp:status()) then
    local loc = resp:headers():get("Location")
    if ctx.url.location_targets_host(loc, CANARY_HOST) then
      sink_kind, sink_payload = "the Location header", loc
    end
  end

  local body, truncated, read_err = resp:read_body_capped(BODY_CAP)
  if read_err then return nil, read_err end

  if sink_kind == "" then
    local hit, kind = ctx.body.find_redirect_sink(body, CANARY_HOST)
    if hit ~= "" then
      sink_kind, sink_payload = kind, hit
    end
  end
  if sink_kind == "" then
    return nil
  end

  local probe_url = req:url()
  local detail = string.format(
    "Parameter %q (%s) is reflected unvalidated into %s. "
      .. "Probe %s=%s produced: %s - an attacker can craft a link to %s that "
      .. "bounces victims to any external host.",
    sink.name, sink.loc, sink_kind, sink.name, CANARY, sink_payload, probe_url)

  return {
    severity = ctx.severity.high,
    url      = probe_url,
    title    = string.format("Open redirect via %s ?%s=", sink.loc, sink.name),
    detail   = detail,
    evidence = ctx.evidence.from_exchange {
      request   = req,
      response  = resp,
      body      = body,
      truncated = truncated,
    },
    -- Dedupe per (page, loc, param): the same vulnerable page hit
    -- by the crawler from many entry points is one issue per param.
    -- Header and body sinks for the same param collapse on purpose.
    dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
  }
end

return check
