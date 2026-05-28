-- form-action-insecure: flags <form action=...> (or <button
-- formaction=...> / <input formaction=...> overrides) that resolve to
-- a plaintext http:// URL when the containing page is served over
-- HTTPS. Any value the user submits is then trivially recoverable by
-- anyone on the network path despite the page looking secure.
--
-- Severity escalates to Critical when the affected form carries a
-- credential-shaped field (password / token / payment); plaintext
-- submits without credentials stay High.

local check = {
  name        = "form-action-insecure",
  level       = levels.passive,
  scope       = scopes.page,
  cwe         = "CWE-319",
  owasp       = "A02:2021 Cryptographic Failures",
  tier        = tiers.passive,
}

local function format_inputs(inputs)
  if #inputs == 0 then return "" end
  local pieces = {}
  for _, in_ in ipairs(inputs) do
    local entry = string.format("%s (%s)", in_.name, in_.type)
    if in_.sensitive then entry = entry .. " [sensitive]" end
    pieces[#pieces + 1] = entry
  end
  table.sort(pieces)
  return table.concat(pieces, ", ")
end

local function build_title(has_credential_field, override)
  local subject = "form"
  if override then subject = "formaction override" end
  if has_credential_field then
    return subject .. " on HTTPS page submits credentials to plaintext http:// (cleartext credential leak)"
  end
  return subject .. " on HTTPS page submits to plaintext http:// (data integrity / leak risk)"
end

local function build_detail(page_url, cand, has_credential_field)
  local subject = "Form"
  if cand.override then subject = "Submit-button formaction override" end
  local b = string.format(
    "%s on HTTPS page %s has action=%q which resolves to %s (method %s).",
    subject, page_url, cand.raw, cand.resolved, cand.method)
  if cand.method == "GET" then
    b = b .. " Because this is a GET submission, the submitted values are appended to the URL itself, "
          .. "leaving copies in browser history, HTTP referer headers, and any intermediate proxy access logs."
  end
  if has_credential_field then
    b = b .. " The form carries at least one credential-shaped field (see below); "
          .. "any password / token / payment value the user enters is transmitted in cleartext and "
          .. "trivially recoverable by anyone on the network path despite the page itself being served over TLS."
  else
    b = b .. " Any data the form submits (session tokens, CSRF tokens, free-form PII) is transmitted in cleartext "
          .. "and recoverable by anyone on the network path despite the page itself being served over TLS."
  end
  local names = format_inputs(cand.inputs)
  if names ~= "" then
    b = b .. " Form fields: " .. names .. "."
  end
  return b
end

local function build_remediation(method)
  local base = "Change the form's action to an https:// URL on the same origin (or a trusted origin). "
            .. "If the form must POST off-host, ensure the target supports HTTPS and use that URL. "
            .. "Protocol-relative URLs (//host/path) or same-origin relative URLs both inherit the page scheme and are safe on HTTPS pages."
  if method == "GET" then
    base = base .. " For forms that handle credentials or other sensitive data, also change the form's method to POST so submitted values are not appended to the request URL where they would persist in browser history and proxy access logs."
  end
  return base
end

function check.run(ctx)
  -- HTTPS-only. On a plaintext page the wider story is the page
  -- itself, which other checks (HSTS, mixed-content) already cover.
  if string.sub(string.lower(ctx.page.url), 1, 8) ~= "https://" then
    return nil
  end

  local snap, err = ctx:ensure_response{ max_body = 2 * 1024 * 1024 }
  if err then return nil, err end
  if not ctx.body.is_html_ct(snap.headers:get("Content-Type")) then
    return nil
  end
  if snap.body == "" then return nil end

  local cands = ctx.html.scan_form_actions(snap.body, ctx.page.url)
  if #cands == 0 then return nil end

  local evidence = ctx.evidence.build {
    method  = methods.get,
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }

  local findings = {}
  local seen = {}
  for _, cand in ipairs(cands) do
    -- ctx.html.scan_form_actions already resolved the action, so a
    -- substring match on the lowercased scheme avoids a re-parse.
    local lower = string.lower(cand.resolved)
    if string.sub(lower, 1, 7) == "http://" then
      local key = "action:" .. cand.resolved
      if not seen[key] then
        seen[key] = true
        local sev_key = "high"
        if cand.has_credential_field then sev_key = "critical" end
        findings[#findings + 1] = {
          severity    = severity[sev_key],
          title       = build_title(cand.has_credential_field, cand.override),
          detail      = build_detail(ctx.page.url, cand, cand.has_credential_field),
          remediation = build_remediation(cand.method),
          evidence    = evidence,
          dedupe_parts = { key },
        }
      end
    end
  end
  return findings
end

return check
