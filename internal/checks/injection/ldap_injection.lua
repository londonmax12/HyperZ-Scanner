-- ldap-injection: two arms per probable sink:
--   1. Filter-break (boolean): append truthy / falsy suffixes that
--      close the value literal and inject an LDAP filter operator.
--      BooleanCompare verdicts the canonical truthy~baseline /
--      falsy!=baseline shape as vulnerable. Severity High.
--   2. Error-based: append payloads engineered to break LDAP filter
--      parsing (unbalanced parens, lone backslash, empty-operand
--      filter). A driver-error pattern not already in baseline body
--      fires the finding. Severity High.
--
-- Probable sinks (ldapi_sink_probable): query, form, JSON body,
-- path values. Headers and cookies are skipped; LDAP filter strings
-- are built from application inputs, not request metadata.

local check = {
  name        = "ldapi",
  level       = levels.default,
  scope       = scopes.param,
  cwe         = "CWE-90",
  owasp       = "A03:2021 Injection",
  remediation = "Escape every metacharacter LDAP filters treat specially (RFC 4515 lists `( ) * \\ NUL`) "
                .. "before concatenating user input into a filter string. Prefer libraries that build filters from typed "
                .. "values (FilterBuilder APIs) over string concatenation. For authentication, bind with the user's DN "
                .. "rather than embedding the username and password in a search filter.",
  consumes    = { kinds.page, kinds.param },
}

local BODY_CAP = body_caps.probe

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

local function send(ctx, sink, wire_value)
  local req, mut_err = sink:mutate_request(wire_value)
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

local function probe(ctx, sink)
  local _, base_resp, base_body, _, base_err = send(ctx, sink, sink.value)
  if base_err then return nil, base_err end
  local base_status = base_resp and base_resp:status() or 0

  -- Pre-strip the sink's value from the baseline body. Both truthy
  -- and falsy variants carry sink.value as the wire prefix, so leaving
  -- the value's echo in place would inflate baseline~truthy similarity
  -- on echo-only pages while artificially deflating baseline~falsy.
  local base_prep = strip_all(base_body, sink.value)
  local baseline_snap = { status = base_status, body = base_prep }

  local placeholder = ctx.payloads.ldapi_canary_placeholder()

  for _, pair in ipairs(ctx.payloads.ldapi_boolean_pairs()) do
    local canary = new_canary()
    local falsy_suffix = string.gsub(pair.falsy_template, placeholder, canary)
    local truthy_wire = sink.value .. pair.truthy
    local falsy_wire = sink.value .. falsy_suffix

    local _, t_resp, t_body, _, t_err = send(ctx, sink, truthy_wire)
    if t_err then
      ctx:report(string.format("ldapi truthy %s %s=%s pair=%s: %s",
        sink.loc, sink.name, sink.url, pair.name, t_err))
    else
      local f_req, f_resp, f_body, f_truncated, f_err = send(ctx, sink, falsy_wire)
      if f_err then
        ctx:report(string.format("ldapi falsy %s %s=%s pair=%s: %s",
          sink.loc, sink.name, sink.url, pair.name, f_err))
      else
        local t_stripped = strip_all(strip_all(t_body, sink.value), pair.truthy)
        local f_stripped = strip_all(strip_all(strip_all(f_body, sink.value), falsy_suffix), canary)
        local t_status = t_resp and t_resp:status() or 0
        local f_status = f_resp and f_resp:status() or 0

        local result = ctx.oracle.boolean_compare(
          baseline_snap,
          { status = t_status, body = t_stripped },
          { status = f_status, body = f_stripped })

        if result.decision == "vulnerable" then
          local probe_url = f_req:url()
          return {
            severity = severity.high,
            url      = probe_url,
            title    = string.format('LDAP injection (filter-break) in %s parameter "%s"', sink.loc, sink.name),
            detail   = string.format(
              'Parameter %q (%s) is concatenated into an LDAP search filter: pair ldapi/%s '
                .. 'produced truthy~baseline (sim=%.3f, status=%d) and falsy!=baseline (sim=%.3f, status=%d). '
                .. '%s. An attacker can bypass authentication, enumerate directory entries, or extract '
                .. 'attributes by injecting filter operators in place of literal values.',
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

  for _, payload in ipairs(ctx.payloads.ldapi_error_payloads()) do
    local wire = sink.value .. payload
    local req, resp, body, truncated, err = send(ctx, sink, wire)
    if err then
      ctx:report(string.format("ldapi error-based %s %s=%s payload=%q: %s",
        sink.loc, sink.name, sink.url, payload, err))
    else
      local new_hits = ctx.body.ldap_error_new_matches(body, base_body)
      if #new_hits > 0 then
        local probe_url = req:url()
        return {
          severity = severity.high,
          url      = probe_url,
          title    = string.format('LDAP injection (error-based) in %s parameter "%s"', sink.loc, sink.name),
          detail   = string.format(
            'Parameter %q (%s) appears to flow into an LDAP search filter: payload %q provoked driver '
              .. 'error signature %q in the response. An attacker can probably extract directory contents or '
              .. 'bypass authentication by injecting filter operators in place of literal values.',
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
    if ctx.body.ldapi_sink_probable(sink.loc) and ctx.scope:allows(sink.url) then
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
