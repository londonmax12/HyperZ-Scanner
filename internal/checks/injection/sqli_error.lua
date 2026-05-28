-- sqli-error: per sink, send a baseline canary then iterate the
-- curated SQLi-error payload list. A finding fires when a payload
-- introduces a SQLErrorPatterns substring that was NOT present in
-- the baseline body - the subtraction is what makes the check
-- precise on debug pages that legitimately echo driver text.
--
-- The pattern catalogue and new-match scanner live behind
-- ctx.injection.sqli_error_payloads / ctx.injection.sqli_error_new_matches so
-- the regex set is the single source of truth.

local check = {
  name        = "sqli-error",
  level       = levels.default,
  scope       = scopes.param,
  cwe         = "CWE-89",
  owasp       = "A03:2021 Injection",
  remediation = "Use parameterized queries / prepared statements so user input is passed as a value, never "
                .. "concatenated into SQL text. Disable verbose database error reporting in production responses regardless - "
                .. "leaked error traces accelerate exploitation even when the underlying bug is patched.",
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

local function send(ctx, sink, wire_value)
  local req, mut_err = sink:mutate_request(wire_value)
  if mut_err then return nil, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

local function probe(ctx, sink)
  -- Baseline: a benign canary keeps request shape identical to the
  -- payload probes (same method, same param name, same Content-Type)
  -- so any pattern that fires here is purely a property of the page.
  local canary = new_canary()
  local _, _, baseline_body, _, base_err = send(ctx, sink, canary)
  if base_err then return nil, base_err end

  for _, payload in ipairs(ctx.injection.sqli_error_payloads()) do
    -- Append onto the existing value rather than replace it: in a
    -- numeric context (id=42) `42'` produces an unterminated literal,
    -- while a bare `'` becomes `''` (valid empty string) and slips by.
    local wire = sink.value .. payload.template
    local req, resp, body, truncated, err = send(ctx, sink, wire)
    if err then return nil, err end

    local new_hits = ctx.injection.sqli_error_new_matches(body, baseline_body)
    if #new_hits > 0 then
      local probe_url = req:url()
      return {
        severity = severity.high,
        url      = probe_url,
        title    = string.format('SQL injection (error-based) in %s parameter "%s"', sink.loc, sink.name),
        detail   = string.format(
          'Parameter %q (%s) appears to be concatenated into a SQL statement: payload sqli-error/%s '
            .. '(wire value %q) provoked driver error signature %q in the response. '
            .. 'An attacker can extract or modify database contents via crafted values.',
          sink.name, sink.loc, payload.name, wire, new_hits[1]),
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
    end
  end

  if first_err and #findings == 0 then return nil, first_err end
  return findings
end

return check
