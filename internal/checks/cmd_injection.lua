-- cmd-injection: per sink, send baseline + per-payload candidate +
-- confirmation with a DIFFERENT sleep value. Shell payloads have no
-- universal comment shape, so we cache-bust by changing the requested
-- sleep (cand=5s, conf=6s by default) rather than appending a
-- comment-hidden canary. The differing wire value defeats URL-keyed
-- caches; the differing sleep value is harmless to detection because
-- ctx.oracle.timing_compare is parameterised on the requested sleep
-- each time.

local check = {
  name        = "cmd-injection",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-78",
  owasp       = "A03:2021 Injection",
  budget_seconds = 300,
  remediation = "Never pass user input to a shell. Use the language's exec API that takes an argv slice (e.g. "
                .. "Go's exec.Command(name, args...), Python's subprocess with shell=False) so arguments are passed as "
                .. "separate elements rather than concatenated into a shell-parsed string. When a shell is unavoidable, "
                .. "strictly allowlist the permitted argument shape - blocklists of metacharacters are routinely bypassed.",
  consumes    = {"page", "param"},
}

local BODY_CAP = 4 * 1024
local FILLER_VALUE = "1"

local function send(ctx, sink, wire_value)
  local req, mut_err = sink:mutate_request(wire_value)
  if mut_err then return nil, nil, nil, false, 0, mut_err end
  local resp, latency_seconds, do_err = ctx.client:do_timed(req)
  if do_err then return req, nil, nil, false, latency_seconds or 0, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, latency_seconds, rerr end
  return req, resp, body, truncated, latency_seconds, nil
end

local function send_for_timing(ctx, sink, wire_value)
  local _, _, _, _, latency, err = send(ctx, sink, wire_value)
  return latency, err
end

local function probe(ctx, sink)
  local anchor = sink.value
  if anchor == "" then anchor = FILLER_VALUE end

  local cand_sleep = ctx.body.cmd_injection_sleep_seconds()
  local conf_sleep = cand_sleep + 1
  local margin = ctx.body.cmd_injection_margin()

  -- Baseline with a benign canary tail; latency is what the rest of
  -- the oracle compares against.
  local canary = "hpzc" .. string.format("%012x", math.random(0, 0xffffff) * 0x1000000 + math.random(0, 0xffffff))
  local base_latency, base_err = send_for_timing(ctx, sink, anchor .. canary)
  if base_err then return nil, base_err end

  for _, payload in ipairs(ctx.payloads.cmd_inject()) do
    local cand_wire = anchor .. ctx.payloads.render(payload.template, "", cand_sleep)
    local cand_latency, cand_err = send_for_timing(ctx, sink, cand_wire)
    if cand_err then
      ctx:report(string.format("cmd-injection candidate %s %s=%s pl=%s: %s",
        sink.loc, sink.name, sink.url, payload.name, cand_err))
    else
      local cand_result = ctx.oracle.timing_compare(base_latency, cand_latency, cand_sleep, margin)
      if cand_result.vulnerable then
        local conf_wire = anchor .. ctx.payloads.render(payload.template, "", conf_sleep)
        local conf_req, conf_resp, conf_body, conf_truncated, conf_latency, conf_err = send(ctx, sink, conf_wire)
        if conf_err then
          ctx:report(string.format("cmd-injection confirm %s %s=%s pl=%s: %s",
            sink.loc, sink.name, sink.url, payload.name, conf_err))
        else
          local conf_result = ctx.oracle.timing_compare(base_latency, conf_latency, conf_sleep, margin)
          if conf_result.vulnerable then
            local probe_url = conf_req:url()
            return {
              severity = ctx.severity.critical,
              url      = probe_url,
              title    = string.format('OS command injection in %s parameter "%s"', sink.loc, sink.name),
              detail   = string.format(
                'Parameter %q (%s) is concatenated into a shell command: payload cmd-injection/%s '
                  .. '(confirmation wire value %q, candidate sleep %ds, confirmation sleep %ds) produced '
                  .. 'candidate latency %.3fs and confirmation latency %.3fs against baseline %.3fs. %s. '
                  .. 'An attacker can run arbitrary commands as the web server process and pivot to '
                  .. 'filesystem read/write, network reconnaissance, or full RCE.',
                sink.name, sink.loc, payload.name, conf_wire, cand_sleep, conf_sleep,
                cand_latency, conf_latency, base_latency, conf_result.detail),
              evidence = ctx.evidence.from_exchange {
                request   = conf_req,
                response  = conf_resp,
                body      = conf_body,
                truncated = conf_truncated,
                snippet   = string.format("baseline=%.3fs candidate=%.3fs confirmation=%.3fs threshold=%.3fs",
                  base_latency, cand_latency, conf_latency, conf_result.threshold_seconds),
              },
              dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
            }
          end
        end
      end
    end
  end
  return nil
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
  local probed_any = false
  for _, sink in ipairs(sinks) do
    if ctx.scope:allows(sink.url) then
      local f, err = probe(ctx, sink)
      if err then
        ctx:report(string.format("probe %s %s=%s: %s", sink.loc, sink.name, sink.url, err))
        if not first_err then first_err = err end
      else
        probed_any = true
        if f then
          local key = "loc:" .. sink.loc .. "|param:" .. sink.name
          if not seen[key] then
            seen[key] = true
            findings[#findings + 1] = f
          end
        end
      end
    end
  end

  if not probed_any and first_err then return nil, first_err end
  return findings
end

return check
