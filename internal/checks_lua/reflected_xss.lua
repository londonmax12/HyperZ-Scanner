-- reflected-xss: Lua port of internal/checks/reflected_xss.go.
--
-- Per sink:
--   1. Send a bare canary. FindReflections classifies the surrounding
--      HTML / JS context. Non-reflecting sinks are dropped here so
--      the per-page request count stays bounded.
--   2. For each reflection context, render the curated XSS payload
--      variant whose breakout shape matches. A finding fires only
--      when the rendered payload bytes round-trip intact - that is
--      the discriminator between "reflected unescaped" (exploitable)
--      and "reflected with HTML-encoding" (safe).
--
-- The Go-side helper xss_payloads_for_contexts owns the
-- context-to-payload mapping + level-based ordering so the Lua port
-- iterates payloads in the same order the Go check uses.

local check = {
  name        = "reflected-xss",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-79",
  owasp       = "A03:2021 Injection",
  remediation = "Context-aware output encoding: HTML-encode user input rendered into HTML text, "
                .. "attribute-encode for values placed in tag attributes, and JavaScript-encode (or hand off via JSON) for values "
                .. "placed inside <script>. Prefer templating engines that auto-escape by default; never concatenate user input into HTML.",
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

local function send(ctx, sink, payload)
  local req, mut_err = sink:mutate_request(payload)
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

local function probe(ctx, sink)
  local canary = new_canary()
  local _, resp1, body1, canary_truncated, send_err = send(ctx, sink, canary)
  if send_err then return nil, send_err end

  local headers1 = resp1 and resp1:headers() or nil
  local reflections = ctx.body.find_reflections(body1, headers1, canary)
  if #reflections == 0 then
    if canary_truncated then
      ctx:report(string.format("probe %s %s=%s: canary response body truncated at %d bytes, reflection may have been missed",
        sink.loc, sink.name, sink.url, BODY_CAP))
    end
    return nil
  end

  -- Flatten the reflection-context list (every entry's `context`
  -- field) for the Go-side payload selector. context_summary collapses
  -- duplicates and preserves source order, same as the Go check's
  -- contextSummary helper.
  local context_strings = {}
  for i, r in ipairs(reflections) do
    context_strings[i] = r.context
  end

  local payloads = ctx.body.xss_payloads_for_contexts(context_strings, ctx.level)
  if #payloads == 0 then return nil end

  local any_truncated = canary_truncated
  for _, payload in ipairs(payloads) do
    local tok = new_canary()
    local rendered = ctx.payloads.render(payload.template, tok, 0)
    local req, resp2, body2, truncated, pl_err = send(ctx, sink, rendered)
    if pl_err then return nil, pl_err end
    if truncated then any_truncated = true end
    if string.find(body2, rendered, 1, true) then
      local probe_url = req:url()
      local context_summary = ctx.body.xss_context_summary(context_strings)
      return {
        severity = ctx.severity.high,
        url      = probe_url,
        title    = string.format('Reflected XSS in %s parameter "%s"', sink.loc, sink.name),
        detail   = string.format(
          'Parameter %q (%s) is reflected unescaped into the response (%s context). '
            .. 'Payload xss/%s round-tripped intact - an attacker can craft a link to %s that executes script in the victim\'s browser.',
          sink.name, sink.loc, context_summary, payload.name, probe_url),
        evidence = ctx.evidence.from_exchange {
          request   = req,
          response  = resp2,
          body      = body2,
          truncated = truncated,
        },
        dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
      }
    end
  end

  if any_truncated then
    ctx:report(string.format("probe %s %s=%s: response body truncated at %d bytes during payload sweep, breakout may have been missed",
      sink.loc, sink.name, sink.url, BODY_CAP))
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
