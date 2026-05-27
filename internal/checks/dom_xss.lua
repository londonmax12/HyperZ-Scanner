-- dom-xss: DOM-only cross-site scripting detection. Catches XSS that
-- lives entirely in client JavaScript: the server never reflects the
-- payload but the page's JS reads it from a DOM source
-- (location.hash, location.search, document.referrer, postMessage)
-- and pipes it into a sink (innerHTML, document.write, eval, Function,
-- setTimeout-string, javascript: URI).
--
-- Detection runs through ctx.browser:visit{...}, which loads the probe
-- URL in a headless tab with a CDP binding installed; a payload that
-- achieves script execution calls the binding with a canary token and
-- the visit returns fired = true. The signal is proof of execution, so
-- there are no false positives from encoded-but-reflected echoes.
--
-- When ctx.browser is not attached (operator did not pass --js) the
-- check silently no-ops: ctx.browser:visit returns (false, nil) on
-- every call so the per-probe loop produces no findings without
-- raising any errors.

local check = {
  name        = "dom-xss",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-79",
  owasp       = "A03:2021 Injection",
  remediation = "Treat DOM sources (location.*, document.referrer, document.cookie, postMessage "
              .. "event.data) as untrusted. Never pass them to innerHTML, document.write, eval, Function, "
              .. "setTimeout/setInterval with a string argument, or as a javascript: URI. Use textContent "
              .. "or setAttribute; when HTML is unavoidable, sanitize through a vetted library (DOMPurify) "
              .. "before injection.",
  consumes    = {"page", "param"},
}

-- Long enough for typical event-loop work (DOMContentLoaded handlers,
-- framework hydration that reads location.hash on mount) to finish;
-- short enough that a 50-page crawl with a handful of sinks each
-- doesn't dominate scan time.
local DOM_XSS_SETTLE_MS = 1500

-- payloads_for(binding) returns the {payload, sink_hint} pairs the
-- check fires through fragment and query sources, parameterised by
-- the active browser binding name. The set is intentionally small -
-- every entry costs one tab. Add only payloads that catch a sink
-- shape the existing set misses.
--
--   {{token}} is replaced per probe with a fresh canary so the
--   controller can correlate a binding fire back to the payload that
--   caused it (and silently ignore noise calls if a site happens to
--   expose its own debug binding with the same name).
local function payloads_for(binding)
  return {
    {
      -- HTML-context: <img onerror> works inside text and most
      -- attribute breakouts; the leading `">` handles the common case
      -- where the source is interpolated into an unquoted or double-
      -- quoted attr.
      payload   = '"><img src=x onerror="' .. binding .. "('{{token}}')\">",
      sink_hint = "HTML-context sink (innerHTML / document.write / insertAdjacentHTML)",
    },
    {
      -- SVG-onload is a fallback for pages that strip <img> or
      -- sanitize `src`; <svg onload> survives many partial sanitizers.
      payload   = '<svg onload="' .. binding .. "('{{token}}')\">",
      sink_hint = "HTML-context sink (innerHTML / document.write / insertAdjacentHTML)",
    },
    {
      -- javascript: URI - catches sinks like
      -- `location.href = userInput` or `<a href={userInput}>` followed
      -- by a programmatic click.
      payload   = "javascript:" .. binding .. "('{{token}}')",
      sink_hint = "URL-navigation sink (location.href / anchor href / window.open with attacker-controlled URL)",
    },
  }
end

local function substitute(template, token)
  return (string.gsub(template, "{{token}}", token))
end

-- One finding per (page, source, param). The same source firing
-- across many crawl entry points collapses to one row; two distinct
-- vulnerable params on the same page stay distinct.
local function build_finding(ctx, target, probe_url, source, param, token, payload, sink_hint)
  local title
  if param ~= "" then
    title = string.format('DOM XSS via %s in parameter %q', source, param)
  else
    title = "DOM XSS via " .. source
  end
  return {
    target   = target,
    url      = probe_url,
    severity = ctx.severity.high,
    title    = title,
    detail   = string.format(
      "Client-side JavaScript read the payload from %s and piped it into a %s. "
        .. "The headless-browser canary fired with token %q after loading the probe URL - "
        .. "the payload reached executable JS without round-tripping through the server, "
        .. "so the bug is in client code, not server output encoding.",
      source, sink_hint, token),
    evidence = ctx.evidence.build {
      method      = "GET",
      request_url = probe_url,
      snippet     = "headless-browser execution; payload: " .. payload,
    },
    dedupe_parts = { "source:" .. source, "param:" .. param },
  }
end

-- visit runs one probe through the browser pool. Reports navigation
-- errors via ctx.report so a flaky page still leaves breadcrumbs but
-- the scan continues; returns nil on a clean miss or an error path,
-- the finding table on a binding-confirmed hit.
local function visit(ctx, target, probe_url, source, param, token, payload, sink_hint)
  local fired, err = ctx.browser:visit {
    url       = probe_url,
    token     = token,
    settle_ms = DOM_XSS_SETTLE_MS,
  }
  if err then
    ctx.report("dom-xss visit " .. probe_url .. ": " .. err)
    return nil
  end
  if not fired then return nil end
  return build_finding(ctx, target, probe_url, source, param, token, payload, sink_hint)
end

function check.run(ctx)
  if not ctx.browser.attached() then return nil end

  local u, _ = ctx.url.parse(ctx.page.url)
  if not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local binding = ctx.browser.binding_name()
  local payloads = payloads_for(binding)
  local findings = {}
  local seen = {}

  -- Fragment sink: the server never sees `#...`, so this case can
  -- only be caught by client-side execution. One probe per payload
  -- against the bare URL; first fire on this page collapses via the
  -- dedupe key so we don't keep firing the remaining payloads.
  for _, probe in ipairs(payloads) do
    local token = ctx.browser.new_canary()
    local payload = substitute(probe.payload, token)
    local probe_url = u.string .. "#" .. payload
    local f = visit(ctx, ctx.page.url, probe_url, "location.hash", "", token, payload, probe.sink_hint)
    if f then
      local key = ctx.dedupe.key {
        check = check.name, scope = check.scope, target = f.target,
        parts = f.dedupe_parts,
      }
      if not seen[key] then
        seen[key] = true
        findings[#findings + 1] = f
      end
      break
    end
  end

  -- Query-param sinks: pages that read location.search via JS and
  -- pipe it into a sink without the param ever being reflected by
  -- the server. Reflected-xss already covers the reflected path; the
  -- DOM-only path is the unique value here.
  for _, sink in ipairs(ctx.sinks.for_page()) do
    if sink.loc == ctx.locs.query then
      for _, probe in ipairs(payloads) do
        local token = ctx.browser.new_canary()
        local payload = substitute(probe.payload, token)
        local req, mut_err = sink:mutate_request(payload)
        if req and not mut_err then
          local probe_url = req:url()
          if probe_url ~= "" then
            local f = visit(ctx, ctx.page.url, probe_url, "location.search", sink.name, token, payload, probe.sink_hint)
            if f then
              local key = ctx.dedupe.key {
                check = check.name, scope = check.scope, target = f.target,
                parts = f.dedupe_parts,
              }
              if not seen[key] then
                seen[key] = true
                findings[#findings + 1] = f
              end
              -- First payload that fires for this param is enough -
              -- the dedupe key would collapse the rest anyway.
              break
            end
          end
        end
      end
    end
  end

  return findings
end

return check
