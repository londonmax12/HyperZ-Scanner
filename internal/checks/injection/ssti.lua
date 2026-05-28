-- ssti: three arms per probable sink.
--   1. Expression evaluation: canary-flanked math expressions per
--      template engine family. A match on canary+expected+canary
--      proves engine evaluation. A confirmation probe (different
--      operands) is sent; severity downgrades from Critical to High
--      on confirm-miss.
--   2. Error-based: deliberately malformed template syntax. New
--      engine-specific error patterns (subtracted against baseline)
--      fire a High-severity finding.
--   3. OOB (drained later): per-engine canary-fetching templates
--      registered with the OOB listener; check.drain emits a
--      Critical finding per registration that observed a callback.
--
-- LevelAggressive folds in header sinks (User-Agent, Referer, ...)
-- so the same body sweep covers header-templated emails / banners.

local check = {
  name        = "ssti",
  level       = levels.default,
  scope       = scopes.param,
  cwe         = "CWE-1336",
  owasp       = "A03:2021 Injection",
  remediation = "Never concatenate user input into template source code. Render user input as template "
                .. "variables or data objects instead. Use template engines with sandboxing when user-controlled templates "
                .. "are a product requirement.",
  consumes    = { kinds.page, kinds.param },
}

local BODY_CAP = body_caps.passive

local function new_canary()
  local hex = "0123456789abcdef"
  local out = { "hpzc" }
  for _ = 1, 12 do
    local r = math.random(1, 16)
    out[#out + 1] = string.sub(hex, r, r)
  end
  return table.concat(out)
end

-- do_no_follow: SSTI probes ride into query / form / header params,
-- and some of those reflect into the Location header on a 3xx (open-
-- redirect / crlf-style endpoints). Following a redirect whose
-- Location is our raw `<%= 7*7 %>` payload would not only fail to
-- parse but also send a second request to a meaningless URL. The
-- immediate response is the only thing the evaluation oracle cares
-- about.
local function send(ctx, sink, wire_value)
  local req, mut_err = sink:mutate_request(wire_value)
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

local function probe(ctx, sink)
  local canary = new_canary()
  local _, _, baseline_body, baseline_truncated, base_err = send(ctx, sink, canary)
  if base_err then return nil, base_err end
  local any_truncated = baseline_truncated

  for _, exp_probe in ipairs(ctx.injection.ssti_expr_probes()) do
    local tok = new_canary()
    local wire = string.gsub(exp_probe.template, "{{TOKEN}}", tok)
    local req, resp, body, truncated, err = send(ctx, sink, wire)
    if err then return nil, err end
    if truncated then any_truncated = true end

    local needle = tok .. exp_probe.expected .. tok
    if string.find(body, needle, 1, true) then
      local confirm = ctx.injection.ssti_confirm_probe(exp_probe.template)
      local confirm_tok = new_canary()
      local confirm_wire = string.gsub(confirm.template, "{{TOKEN}}", confirm_tok)
      local _, _, confirm_body, confirm_truncated, conf_err = send(ctx, sink, confirm_wire)
      local confirmed = false
      local confirm_phrase = "did not confirm"
      if conf_err then
        ctx:report(string.format("ssti confirm %s %s=%s: %s", sink.loc, sink.name, sink.url, conf_err))
        confirm_phrase = "transport error: " .. conf_err
      else
        if confirm_truncated then any_truncated = true end
        local confirm_needle = confirm_tok .. confirm.expected .. confirm_tok
        if string.find(confirm_body, confirm_needle, 1, true) then
          confirmed = true
          confirm_phrase = "confirmed"
        end
      end

      local sev = confirmed and severity.critical or severity.high
      local title_suffix = confirmed and "expression evaluation" or "expression evaluation, unconfirmed"
      local probe_url = req:url()
      local loc_descriptor = ctx.injection.loc_descriptor(sink.loc)
      local math_source = string.gsub(exp_probe.template, "{{TOKEN}}", "")
      local confirm_source = string.gsub(confirm.template, "{{TOKEN}}", "")
      return {
        severity = sev,
        url      = probe_url,
        title    = string.format('Server-Side Template Injection (%s) in %s %s "%s"',
          title_suffix, loc_descriptor, sink.loc, sink.name),
        detail   = string.format(
          'Parameter %q (%s) appears to be rendered in a %s-family template engine: payload ssti/%s '
            .. 'probed %s and evaluated to %s with context marker %q (confirmation probe %s -> %s %s). '
            .. 'Server-side template injection can range from sensitive data disclosure to remote code '
            .. 'execution depending on the engine and its sandboxing.',
          sink.name, sink.loc, exp_probe.name, exp_probe.name,
          math_source, exp_probe.expected, tok,
          confirm_source, confirm.expected, confirm_phrase),
        evidence = ctx.evidence.from_exchange {
          request   = req,
          response  = resp,
          body      = body,
          truncated = truncated,
        },
        dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
      }
    end
  end

  for _, error_payload in ipairs(ctx.injection.ssti_error_payloads()) do
    local req, resp, body, truncated, err = send(ctx, sink, error_payload)
    if err then return nil, err end
    if truncated then any_truncated = true end
    local new_hits = ctx.injection.ssti_error_new_matches(body, baseline_body)
    if #new_hits > 0 then
      local probe_url = req:url()
      local loc_descriptor = ctx.injection.loc_descriptor(sink.loc)
      return {
        severity = severity.high,
        url      = probe_url,
        title    = string.format('Server-Side Template Injection (error-based) in %s %s "%s"',
          loc_descriptor, sink.loc, sink.name),
        detail   = string.format(
          'Parameter %q (%s) appears to be rendered in a template engine: probe payload %q '
            .. 'provoked template engine error signature %q. '
            .. 'An attacker can likely extract sensitive information and may be able to execute code.',
          sink.name, sink.loc, error_payload, new_hits[1]),
        evidence = ctx.evidence.from_exchange {
          request   = req,
          response  = resp,
          body      = body,
          truncated = truncated,
        },
        dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
      }
    end
  end

  if any_truncated then
    ctx:report(string.format("probe %s %s=%s: response body truncated at %d bytes during sweep, template injection may have been missed",
      sink.loc, sink.name, sink.url, BODY_CAP))
  end
  return nil
end

local function probe_oob(ctx, sink)
  if not ctx.oob:attached() then return end
  for _, pld in ipairs(ctx.injection.ssti_oob_payloads()) do
    local canary = ctx.oob:register{
      target = ctx.page.url,
      sink   = sink.name,
      loc    = sink.loc,
      method = sink.method,
      engine = pld.engine,
    }
    if canary then
      local wire = string.gsub(pld.template, "{{URL}}", canary.http_url)
      local req, mut_err = sink:mutate_request(wire)
      if mut_err then
        ctx:report(string.format("ssti oob mutate %s %s=%s engine=%s: %s",
          sink.loc, sink.name, sink.url, pld.engine, mut_err))
      else
        local resp, do_err = ctx.client:do_no_follow(req)
        if do_err then
          ctx:report(string.format("oob probe %s %s=%s engine=%s: %s",
            sink.loc, sink.name, sink.url, pld.engine, do_err))
        else
          resp:read_body_capped(1024)
        end
      end
    end
  end
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local sinks = ctx.sinks.for_page{}
  if ctx:level_at_least("aggressive") then
    local hdrs = ctx.sinks.for_headers(ctx.page.url,
      { "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host" })
    for _, h in ipairs(hdrs) do
      sinks[#sinks + 1] = h
    end
  end
  if #sinks == 0 then return nil end

  local findings = {}
  local seen = {}
  local first_err
  for _, sink in ipairs(sinks) do
    if ctx.scope:allows(sink.url) then
      local f, err = probe(ctx, sink)
      if err then
        ctx:report(string.format("probe %s %s=%s: %s", sink.loc, sink.name, sink.url, err))
        if not first_err then first_err = err end
      elseif f then
        local key = "loc:" .. sink.loc .. "|param:" .. sink.name
        if not seen[key] then
          seen[key] = true
          findings[#findings + 1] = f
        end
      end
      probe_oob(ctx, sink)
    end
  end

  if first_err and #findings == 0 then return nil, first_err end
  return findings
end

-- Drain emits one Critical-severity finding per OOB registration that
-- observed a callback. Dedupe is on (target, loc, param, oob-engine):
-- one engine-confirmed sink is one row regardless of how many hits
-- the listener saw.
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
      local engine = extra.engine or ""
      local hit = hits[1]
      local detail = string.format(
        'Parameter %q (%s) is rendered by the %s template engine with HTTP-issuing primitives '
          .. 'enabled: canary %s received %d callback(s) (first hit: method=%s, source=%s, user-agent=%q). '
          .. 'The %s primitives that produced this callback typically expose adjacent RCE; '
          .. 'treat as remote code execution unless the engine sandbox is independently verified.',
        sink_name, loc, engine, reg.http_url, #hits,
        hit.method, hit.source_addr, hit.user_agent or "", engine)
      local loc_descriptor = ctx.injection.loc_descriptor(loc)
      findings[#findings + 1] = {
        severity = severity.critical,
        target   = target,
        url      = target,
        title    = string.format('Server-Side Template Injection (OOB-confirmed, %s engine) in %s %s "%s"',
          engine, loc_descriptor, loc, sink_name),
        detail   = detail,
        evidence = ctx.evidence.build {
          method = method,
          url    = target,
          snippet = string.format(
            "Engine: %s\nCanary URL: %s\nFirst hit: %s %s from %s\nUser-Agent: %s\nTotal hits: %d\n",
            engine, reg.http_url, hit.method, hit.path, hit.source_addr, hit.user_agent or "", #hits),
        },
        dedupe_parts = { "loc:" .. loc, "param:" .. sink_name, "oob:" .. engine },
      }
    end
  end
  return findings
end

return check
