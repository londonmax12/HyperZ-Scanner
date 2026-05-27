-- sqli-boolean: per sink, send a baseline plus a truthy/falsy pair
-- sweep. ctx.oracle.boolean_compare decides whether the differential
-- evidence (truthy ~ baseline AND falsy != baseline) is vulnerability-
-- shaped. Per-pair bodies are stripped of the literal pair suffix
-- before the oracle runs so an echo-heavy page doesn't artificially
-- diverge truthy from falsy.

local check = {
  name        = "sqli-boolean",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-89",
  owasp       = "A03:2021 Injection",
  remediation = "Use parameterized queries / prepared statements so user input is bound as a value, never "
                .. "concatenated into SQL text. Boolean-based SQLi remains exploitable even when verbose errors are disabled, "
                .. "so suppressing error output alone is not a fix.",
  consumes    = {"page", "param"},
}

local BODY_CAP = 64 * 1024

local function send(ctx, sink, wire_value)
  local req, mut_err = sink:mutate_request(wire_value)
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

-- strip_all removes every occurrence of needle from body. gopher-lua's
-- gsub treats the pattern as a Lua pattern by default; we want a
-- literal substring scrub so callers can pass arbitrary SQL fragments
-- without escaping each pattern metacharacter. plain-find + concat keeps
-- the scrub literal.
local function strip_all(body, needle)
  if body == "" or needle == "" then return body end
  local out, i = {}, 1
  while true do
    local s, e = string.find(body, needle, i, true)
    if not s then
      out[#out + 1] = string.sub(body, i)
      break
    end
    out[#out + 1] = string.sub(body, i, s - 1)
    i = e + 1
  end
  return table.concat(out)
end

local function probe(ctx, sink)
  local base_value = sink.value
  local _, base_resp, base_body, _, base_err = send(ctx, sink, base_value)
  if base_err then return nil, base_err end
  local base_status = base_resp and base_resp:status() or 0
  local baseline_snap = { status = base_status, body = base_body }

  for _, pair in ipairs(ctx.payloads.sqli_boolean_pairs()) do
    local truthy_wire = base_value .. pair.truthy
    local falsy_wire = base_value .. pair.falsy

    -- Pair-level send errors do not disqualify the sink: one flaky
    -- request only invalidates this pair's verdict, not the next
    -- pair's.
    local _, t_resp, t_body, _, t_err = send(ctx, sink, truthy_wire)
    if t_err then
      ctx:report(string.format("sqli-boolean truthy %s %s=%s pair=%s: %s",
        sink.loc, sink.name, sink.url, pair.name, t_err))
    else
      local f_req, f_resp, f_body, f_truncated, f_err = send(ctx, sink, falsy_wire)
      if f_err then
        ctx:report(string.format("sqli-boolean falsy %s %s=%s pair=%s: %s",
          sink.loc, sink.name, sink.url, pair.name, f_err))
      else
        local t_stripped = strip_all(t_body, pair.truthy)
        local f_stripped = strip_all(f_body, pair.falsy)
        local t_status = t_resp and t_resp:status() or 0
        local f_status = f_resp and f_resp:status() or 0

        local result = ctx.oracle.boolean_compare(
          baseline_snap,
          { status = t_status, body = t_stripped },
          { status = f_status, body = f_stripped })

        if result.decision == "vulnerable" then
          local probe_url = f_req:url()
          return {
            severity = ctx.severity.high,
            url      = probe_url,
            title    = string.format('SQL injection (boolean-based) in %s parameter "%s"', sink.loc, sink.name),
            detail   = string.format(
              'Parameter %q (%s) responds to SQL boolean inference: pair sqli-boolean/%s produced '
                .. 'truthy~baseline (sim=%.3f, status=%d) and falsy!=baseline (sim=%.3f, status=%d). '
                .. '%s. An attacker can extract database contents by chaining boolean conditions.',
              sink.name, sink.loc, pair.name,
              result.truthy_sim, t_status, result.falsy_sim, f_status, result.detail),
            evidence = ctx.evidence.from_exchange {
              request   = f_req,
              response  = f_resp,
              body      = f_body,
              truncated = f_truncated,
            },
            dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
          }
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
