-- ssrf: for each candidate sink the probe overlays an attacker-
-- controlled URL on a reserved .example host and looks for HTTP-
-- library error signatures in the response body. A match means the
-- target's fetch primitive attempted the canary URL.
--
-- Two arms ride together when an OOB listener is attached:
--   1. In-band: plant the canary URL, scan body for error markers.
--      Catches targets that leak errors but cannot reach the OOB
--      listener (firewalled outbound, air-gapped network).
--   2. OOB: plant the listener's canary URL, drain on callback. Fires
--      a separate Critical-severity finding because an observed
--      callback proves both fetch + egress.
--
-- Sink selection: the always-probed "specific" names (url, fetch,
-- webhook, ...) cover well-known URL-handling parameters; the
-- "generic" sweep names (q, link, page, ...) are folded in when the
-- URL path looks proxy-ish OR the operator opted into aggressive
-- scanning.

local check = {
  name        = "ssrf",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-918",
  owasp       = "A10:2021 Server-Side Request Forgery (SSRF)",
  remediation = "Validate and restrict the URL parameter to a strict allowlist of domains/hosts. "
                .. "Disable access to private/internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1). "
                .. "Use a URL parsing library that properly validates scheme and host. Never fetch arbitrary user-supplied URLs.",
}

local function probe_inband(ctx, target, sink)
  local canary = ctx.payloads.ssrf_canary()
  local req, mut_err = sink:mutate_request(canary)
  if mut_err then return nil, mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, do_err end
  local body, truncated, rerr = resp:read_body_capped(ctx.payloads.ssrf_body_cap())
  if rerr then return nil, rerr end
  local pattern = ctx.body.ssrf_matches_error(body)
  if pattern == "" then return nil end

  local probe_url = req:url()
  return {
    severity = ctx.severity.high,
    target   = target,
    url      = probe_url,
    title    = string.format("Server-Side Request Forgery via %s ?%s=", sink.loc, sink.name),
    detail   = string.format(
      'Parameter %q (%s) accepts a URL that the server fetches. '
        .. 'Probe with %s triggered server-side request attempt; '
        .. 'response contains error signature %q indicating connection failure. '
        .. 'An attacker can craft URLs to probe internal network, bypass authentication, or attack internal services.',
      sink.name, sink.loc, canary, pattern),
    evidence = ctx.evidence.from_exchange {
      request   = req,
      response  = resp,
      body      = body,
      truncated = truncated,
    },
    dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
  }
end

local function probe_oob(ctx, target, sink)
  if not ctx.oob:attached() then return end
  local canary = ctx.oob:register {
    target = target,
    sink   = sink.name,
    loc    = sink.loc,
    method = sink.method,
  }
  if canary == nil then return end
  local req, mut_err = sink:mutate_request(canary.http_url)
  if mut_err then
    ctx:report(string.format("oob probe param %q: %s", sink.name, mut_err))
    return
  end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then
    ctx:report(string.format("oob probe param %q: %s", sink.name, do_err))
    return
  end
  -- Drain a small chunk so the connection returns to the pool cleanly.
  -- The listener-side hit is the signal, not the response body.
  resp:read_body_capped(1024)
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local sweep = ctx:level_at_least("aggressive") or ctx.payloads.ssrf_looks_proxyish(u.path)

  local sweep_params = {}
  for _, name in ipairs(ctx.payloads.ssrf_specific_params()) do
    sweep_params[#sweep_params + 1] = name
  end
  if sweep then
    for _, name in ipairs(ctx.payloads.ssrf_generic_params()) do
      sweep_params[#sweep_params + 1] = name
    end
  end

  local sinks = ctx.sinks.for_page { sweep_params = sweep_params }
  if #sinks == 0 then return nil end

  local findings = {}
  local first_err
  for _, sink in ipairs(sinks) do
    if ctx.scope:allows(sink.url) then
      local f, err = probe_inband(ctx, ctx.page.url, sink)
      if err then
        ctx:report(string.format("probe param %q: %s", sink.name, err))
        if not first_err then first_err = err end
      elseif f then
        findings[#findings + 1] = f
      end
      probe_oob(ctx, ctx.page.url, sink)
    end
  end

  if first_err and #findings == 0 then return nil, first_err end
  return findings
end

-- Drain emits one Critical-severity finding per OOB registration that
-- observed at least one callback. Callback evidence beats reflected-
-- error evidence, so OOB-confirmed sits at Critical while in-band
-- tops out at High.
function check.drain(ctx)
  if not ctx.oob:attached() then return nil end
  local findings = {}
  for _, reg in ipairs(ctx.oob:registrations()) do
    local hits = ctx.oob:hits(reg.token)
    if #hits > 0 then
      local extra = reg.extra or {}
      local target = extra.target or ""
      local sink_name = extra.sink or ""
      local loc = extra.loc or ""
      local method = extra.method or ""
      local hit = hits[1]
      findings[#findings + 1] = {
        severity = ctx.severity.critical,
        target   = target,
        url      = target,
        title    = string.format("Server-Side Request Forgery (OOB-confirmed) via %s %s", loc, sink_name),
        detail   = string.format(
          'Parameter %q (%s) accepts a URL that the server fetches. '
            .. 'Probe with canary %s caused the target to issue a request that landed on the OOB '
            .. 'listener (method=%s, source=%s, user-agent=%q, %d hit(s)). '
            .. 'An attacker can craft URLs to probe internal network, bypass authentication, '
            .. 'or attack internal services.',
          sink_name, loc, reg.http_url,
          hit.method, hit.source_addr, hit.user_agent or "", #hits),
        evidence = ctx.evidence.build {
          method  = method,
          url     = target,
          snippet = string.format(
            "Canary URL: %s\nFirst hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
            reg.http_url, hit.method, hit.path, hit.source_addr,
            os.date("!%Y-%m-%dT%H:%M:%SZ", hit.timestamp_unix),
            hit.user_agent or "", #hits),
        },
        dedupe_parts = { "loc:" .. loc, "param:" .. sink_name, "oob" },
      }
    end
  end
  return findings
end

return check
