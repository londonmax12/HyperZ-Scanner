-- nosqli: two arms per probable sink.
--   1. Operator injection (boolean): rewrite the sink's name with a
--      Mongo operator suffix (`name[$eq]`, `name[$in][0]`) or
--      equivalent nested-JSON shape, oscillating the value between
--      sink.value (truthy) and a fresh canary (falsy). The wire-shape
--      rewrite is produced by ctx.body.nosqli_build_operator_request.
--   2. Error-based: append payloads engineered to break Mongo /
--      Mongoose driver parsing. A driver-error pattern not already
--      in baseline body fires the finding.
--
-- Probable sinks (nosqli_sink_probable): query / form / json body
-- values. Header / cookie / path values aren't auto-deserialised into
-- query operators by common frameworks and are skipped.

local check = {
  name        = "nosqli",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-943",
  owasp       = "A03:2021 Injection",
  remediation = "Treat client-supplied values as strings, not as structured query fragments. Reject inputs "
                .. "whose type does not match the schema - a username field that arrives as an object should fail "
                .. "validation before reaching the database driver. In Express/Node, sanitize keys starting with `$` "
                .. "(e.g. via express-mongo-sanitize) or disable bracket-object expansion in the body parser / qs.",
}

local BODY_CAP = 64 * 1024

local function new_canary()
  local hex = "0123456789abcdef"
  local out = { "hpzc" }
  for _ = 1, 12 do
    local r = math.random(1, 16)
    out[#out + 1] = string.sub(hex, r, r)
  end
  return table.concat(out)
end

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

-- do_no_follow: NoSQL operator payloads ({"$gt":""} and friends) ride
-- into query / form sinks, and reflective endpoints (open-redirect /
-- crlf shapes) drop them verbatim into Location on a 302. Following
-- through would not only fail to parse but also issue a wasted
-- request; the boolean oracle wants the immediate response anyway.
local function send_value(ctx, sink, wire_value)
  local req, mut_err = sink:mutate_request(wire_value)
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

local function send_operator(ctx, sink, op_name, op_value)
  local req, build_err = ctx.body.nosqli_build_operator_request(sink, op_name, op_value)
  if build_err then return nil, nil, nil, false, build_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

local function probe(ctx, sink)
  local _, base_resp, base_body, _, base_err = send_value(ctx, sink, sink.value)
  if base_err then return nil, base_err end
  local base_status = base_resp and base_resp:status() or 0

  local base_prep = strip_all(base_body, sink.value)
  local baseline_snap = { status = base_status, body = base_prep }

  for _, op in ipairs(ctx.payloads.nosqli_boolean_ops()) do
    local canary = new_canary()
    local _, t_resp, t_body, _, t_err = send_operator(ctx, sink, op.name, sink.value)
    if t_err then
      ctx:report(string.format("nosqli truthy %s %s=%s op=%s: %s",
        sink.loc, sink.name, sink.url, op.name, t_err))
    else
      local f_req, f_resp, f_body, f_truncated, f_err = send_operator(ctx, sink, op.name, canary)
      if f_err then
        ctx:report(string.format("nosqli falsy %s %s=%s op=%s: %s",
          sink.loc, sink.name, sink.url, op.name, f_err))
      else
        local t_stripped = strip_all(t_body, sink.value)
        local f_stripped = strip_all(strip_all(f_body, sink.value), canary)
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
            title    = string.format('NoSQL injection (operator injection) in %s parameter "%s"', sink.loc, sink.name),
            detail   = string.format(
              'Parameter %q (%s) is deserialized into a MongoDB-style query operator: pair nosqli/%s '
                .. 'produced truthy~baseline (sim=%.3f, status=%d) and falsy!=baseline (sim=%.3f, status=%d). '
                .. '%s. An attacker can bypass authentication checks, enumerate records, or extract data '
                .. 'by sending operator objects in place of literal values.',
              sink.name, sink.loc, op.name,
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

  for _, payload in ipairs(ctx.payloads.nosqli_error_payloads()) do
    local wire = sink.value .. payload
    local req, resp, body, truncated, err = send_value(ctx, sink, wire)
    if err then
      ctx:report(string.format("nosqli error-based %s %s=%s payload=%q: %s",
        sink.loc, sink.name, sink.url, payload, err))
    else
      local new_hits = ctx.body.mongo_error_new_matches(body, base_body)
      if #new_hits > 0 then
        local probe_url = req:url()
        return {
          severity = ctx.severity.high,
          url      = probe_url,
          title    = string.format('NoSQL injection (error-based) in %s parameter "%s"', sink.loc, sink.name),
          detail   = string.format(
            'Parameter %q (%s) appears to flow into a NoSQL query: payload %q provoked driver error '
              .. 'signature %q. An attacker can probably extract data or bypass logic by sending operator '
              .. 'objects in place of literal values.',
            sink.name, sink.loc, payload, new_hits[1]),
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
    if ctx.body.nosqli_sink_probable(sink.loc) and ctx.scope:allows(sink.url) then
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
