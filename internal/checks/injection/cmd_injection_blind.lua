-- cmd-injection-blind: two arms, both per-sink:
--   1. In-band: send each blind cmd-inject payload (e.g. `;
--      <CANARY> nonexistent_cmd_xyzabc`); a finding fires when the
--      response carries BOTH the canary (proves the injection
--      reached the shell) AND a shell-error signature (proves the
--      shell tried to execute).
--   2. OOB: register a fresh canary URL, substitute it into each
--      OOB-payload's {{URL}} placeholder, send. Detection lives in
--      check.drain, which iterates registrations whose canary
--      observed a callback after the active phase.
--
-- The OOB arm is silently skipped when no listener is attached to
-- the scan (ctx.oob:attached() == false), so a passive --no-oob run
-- still benefits from the in-band detection.

local check = {
  name        = "cmd-injection-blind",
  level       = levels.default,
  scope       = scopes.param,
  cwe         = "CWE-78",
  owasp       = "A03:2021 Injection",
  remediation = "Never pass user input to a shell. Use the language's exec API that takes an argv slice "
                .. "(e.g. Go's exec.Command(name, args...), Python's subprocess with shell=False) so arguments are passed as "
                .. "separate elements rather than concatenated into a shell-parsed string. When a shell is unavoidable, "
                .. "strictly allowlist the permitted argument shape - blocklists of metacharacters are routinely bypassed.",
  consumes    = { kinds.page, kinds.param },
}

local BODY_CAP = body_caps.small

local function new_canary()
  local hex = "0123456789abcdef"
  local out = { "hpzc" }
  for _ = 1, 12 do
    local r = math.random(1, 16)
    out[#out + 1] = string.sub(hex, r, r)
  end
  return table.concat(out)
end

local function probe_inband(ctx, sink)
  local anchor = sink.value
  if anchor == "" then anchor = ctx.injection.cmd_injection_filler_value() end

  local canary = new_canary()
  for _, payload in ipairs(ctx.injection.cmd_inject_blind()) do
    local wire = anchor .. ctx.payloads.render(payload.template, canary, 0)
    local req, mut_err = sink:mutate_request(wire)
    if mut_err then
      ctx:report(string.format("cmd-injection-blind mutate %s %s=%s pl=%s: %s",
        sink.loc, sink.name, sink.url, payload.name, mut_err))
    else
      local resp, do_err = ctx.client["do"](ctx.client, req)
      if do_err then
        ctx:report(string.format("cmd-injection-blind send %s %s=%s pl=%s: %s",
          sink.loc, sink.name, sink.url, payload.name, do_err))
      else
        local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
        if rerr then
          ctx:report(string.format("cmd-injection-blind read %s %s=%s pl=%s: %s",
            sink.loc, sink.name, sink.url, payload.name, rerr))
        else
          local body_lower = string.lower(body)
          if string.find(body_lower, string.lower(canary), 1, true) then
            local matched_error = ctx.injection.cmd_error_first_match(body)
            if matched_error ~= "" then
              local probe_url = req:url()
              return {
                severity = severity.critical,
                url      = probe_url,
                title    = string.format('Blind OS command injection in %s parameter "%s"', sink.loc, sink.name),
                detail   = string.format(
                  'Parameter %q (%s) is concatenated into a shell command. '
                    .. 'Payload cmd-injection-blind/%s with canary %q triggered both the injected canary '
                    .. '(confirming injection reached execution context) and error signature %q (confirming command execution). '
                    .. 'The application is vulnerable to blind RCE: an attacker can execute arbitrary OS commands as the web server process, '
                    .. 'enabling filesystem read/write, network reconnaissance, or full system compromise.',
                  sink.name, sink.loc, payload.name, canary, matched_error),
                evidence = ctx.evidence.from_exchange {
                  request   = req,
                  response  = resp,
                  body      = body,
                  truncated = truncated,
                  snippet   = string.format("canary=%q error-signature=%q", canary, matched_error),
                },
                dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
              }
            end
          end
        end
      end
    end
  end
  return nil
end

local function probe_oob(ctx, sink)
  if not ctx.oob:attached() then return end
  local anchor = sink.value
  if anchor == "" then anchor = ctx.injection.cmd_injection_filler_value() end

  for _, payload in ipairs(ctx.injection.cmd_injection_blind_oob()) do
    local canary = ctx.oob:register{
      target  = ctx.page.url,
      sink    = sink.name,
      loc     = sink.loc,
      method  = sink.method,
      payload = payload.name,
    }
    if canary then
      local wire = anchor .. string.gsub(payload.template, "{{URL}}", canary.http_url)
      local req, mut_err = sink:mutate_request(wire)
      if mut_err then
        ctx:report(string.format("cmd-injection-blind oob mutate %s %s=%s pl=%s: %s",
          sink.loc, sink.name, sink.url, payload.name, mut_err))
      else
        local resp, do_err = ctx.client["do"](ctx.client, req)
        if do_err then
          ctx:report(string.format("cmd-injection-blind oob send %s %s=%s pl=%s: %s",
            sink.loc, sink.name, sink.url, payload.name, do_err))
        else
          -- Drain a small chunk so the connection returns to the pool
          -- cleanly. Detection signal is the listener-side callback.
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
  if #sinks == 0 then return nil end

  local findings = {}
  local seen = {}
  local first_err
  for _, sink in ipairs(sinks) do
    if ctx.scope:allows(sink.url) then
      local f, err = probe_inband(ctx, sink)
      if err then
        ctx:report(string.format("blind-probe %s %s=%s: %s", sink.loc, sink.name, sink.url, err))
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

-- Drain emits one finding per OOB registration that observed at least
-- one callback. Dedupe is on (target, loc, param): a vulnerable sink
-- typically fires several payload variants at once, but the reported
-- bug is the same parameter.
function check.drain(ctx)
  if not ctx.oob:attached() then return nil end
  local findings = {}
  local seen = {}
  for _, reg in ipairs(ctx.oob:registrations()) do
    local hits = ctx.oob:hits(reg.token)
    if #hits > 0 then
      local extra = reg.extra or {}
      local target = extra.target or ""
      local sink_name = extra.sink or ""
      local loc = extra.loc or ""
      local method = extra.method or ""
      local payload = extra.payload or ""
      local hit = hits[1]
      local key = "target:" .. target .. "|loc:" .. loc .. "|param:" .. sink_name .. "|oob"
      if not seen[key] then
        seen[key] = true
        local detail = string.format(
          'Parameter %q (%s) is concatenated into a shell command. '
            .. 'Payload cmd-injection-blind/%s with canary %s caused the target to issue an outbound '
            .. 'HTTP request that landed on the OOB listener (method=%s, source=%s, user-agent=%q, %d hit(s)). '
            .. 'This proves the parameter both reached the shell AND the resulting command executed - the target '
            .. 'is vulnerable to blind RCE, with confirmed egress to attacker-controlled hosts.',
          sink_name, loc, payload, reg.http_url, hit.method, hit.source_addr, hit.user_agent or "", #hits)
        findings[#findings + 1] = {
          severity = severity.critical,
          target   = target,
          url      = target,
          title    = string.format('Blind OS command injection (OOB-confirmed) in %s parameter "%s"', loc, sink_name),
          detail   = detail,
          evidence = ctx.evidence.build {
            method = method,
            url    = target,
            snippet = string.format(
              "Payload: cmd-injection-blind/%s\nCanary URL: %s\nFirst hit: %s %s from %s\nUser-Agent: %s\nTotal hits: %d\n",
              payload, reg.http_url, hit.method, hit.path, hit.source_addr, hit.user_agent or "", #hits),
          },
          dedupe_parts = { "loc:" .. loc, "param:" .. sink_name, "oob" },
        }
      end
    end
  end
  return findings
end

return check
