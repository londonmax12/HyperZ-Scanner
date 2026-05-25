-- sqli-time: Lua port of internal/checks/sqli_time.go.
--
-- Per sink: baseline timing + candidate + confirmation. Each {{SLEEP}}
-- placeholder resolves to the active tuning (5s by default; tests dial
-- it to 1s via SetSQLiTimeTuningForTest in the checks package). A
-- finding fires only when BOTH the candidate AND the confirmation
-- cross TimingCompare's threshold: one slow request is
-- indistinguishable from network jitter; two confirming requests on
-- the same payload collapse that false-positive surface dramatically.

local check = {
  name        = "sqli-time",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-89",
  owasp       = "A03:2021 Injection",
  budget_seconds = 300,
  remediation = "Use parameterized queries / prepared statements; time-based blind SQLi remains exploitable "
                .. "even when the response body never reflects database content. Disabling SLEEP / pg_sleep / WAITFOR via "
                .. "the DB user's privileges narrows the attack surface but is not a replacement for parameterized queries.",
}

local BODY_CAP = 4 * 1024
local FILLER_VALUE = "1"

local function new_canary()
  local hex = "0123456789abcdef"
  local out = { "hpzc" }
  for _ = 1, 12 do
    local r = math.random(1, 16)
    out[#out + 1] = string.sub(hex, r, r)
  end
  return table.concat(out)
end

local function send(ctx, sink, wire_value)
  local req, mut_err = sink:mutate_request(wire_value)
  if mut_err then return nil, nil, nil, false, 0, mut_err end
  local resp, latency_seconds, do_err = ctx.client:do_timed(req)
  if do_err then return req, nil, nil, false, latency_seconds or 0, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, latency_seconds, rerr end
  return req, resp, body, truncated, latency_seconds, nil
end

local function probe(ctx, sink)
  local anchor = sink.value
  if anchor == "" then anchor = FILLER_VALUE end

  local sleep_secs = ctx.body.sqli_time_sleep_seconds()
  local margin = ctx.body.sqli_time_margin()

  local canary = new_canary()
  local _, _, _, _, base_latency, base_err = send(ctx, sink, anchor .. canary)
  if base_err then return nil, base_err end

  for _, payload in ipairs(ctx.payloads.sqli_time()) do
    local rendered = ctx.payloads.render(payload.template, "", sleep_secs)

    -- Cache-bust suffix per probe. Every PayloadSQLiTime template ends
    -- with `-- -`, so an appended canary lands inside the SQL line
    -- comment and has zero effect on execution - but varies the wire
    -- value so a URL-keyed cache in front of the target can't collapse
    -- candidate and confirmation onto the same cached fast path.
    local cand_wire = anchor .. rendered .. new_canary()
    local _, _, _, _, cand_latency, cand_err = send(ctx, sink, cand_wire)
    if cand_err then
      ctx:report(string.format("sqli-time candidate %s %s=%s pl=%s: %s",
        sink.loc, sink.name, sink.url, payload.name, cand_err))
    else
      local cand_result = ctx.oracle.timing_compare(base_latency, cand_latency, sleep_secs, margin)
      if cand_result.vulnerable then
        local conf_wire = anchor .. rendered .. new_canary()
        local conf_req, conf_resp, conf_body, conf_truncated, conf_latency, conf_err = send(ctx, sink, conf_wire)
        if conf_err then
          ctx:report(string.format("sqli-time confirm %s %s=%s pl=%s: %s",
            sink.loc, sink.name, sink.url, payload.name, conf_err))
        else
          local conf_result = ctx.oracle.timing_compare(base_latency, conf_latency, sleep_secs, margin)
          if conf_result.vulnerable then
            local probe_url = conf_req:url()
            return {
              severity = ctx.severity.high,
              url      = probe_url,
              title    = string.format('SQL injection (time-based) in %s parameter "%s"', sink.loc, sink.name),
              detail   = string.format(
                'Parameter %q (%s) responds to time-based SQL inference: payload sqli-time/%s '
                  .. '(wire value %q, sleep %ds) produced candidate latency %.3fs and confirmation latency %.3fs '
                  .. 'against baseline %.3fs. %s. An attacker can extract database contents one bit at a time '
                  .. 'by chaining sleep-on-condition probes.',
                sink.name, sink.loc, payload.name, conf_wire, sleep_secs,
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
