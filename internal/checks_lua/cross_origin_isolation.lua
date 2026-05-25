-- cross-origin-isolation: Lua port of
-- internal/checks/cross_origin_isolation.go.
--
-- Inspects COOP / COEP headers on HTML responses and flags every
-- configuration that prevents the document from reaching the cross-
-- origin isolated state. The check fires only when at least one of
-- the two headers is present - the author was reaching for isolation
-- - and surfaces the ways that goal is undone (wrong values, multi-
-- header confusion, COEP without matching COOP, ...).
--
-- Parity contract: every weakness, dedupe id, and severity must
-- match internal/checks/cross_origin_isolation.go exactly. The Go
-- test cases double as a parity oracle.

local check = {
  name        = "cross-origin-isolation",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-693",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Aim for Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp on every HTML document that should be cross-origin isolated. "
                .. "Tag every cross-origin subresource (images, scripts, fonts, frames) with Cross-Origin-Resource-Policy: same-origin or cross-origin so require-corp does not block them. "
                .. "During rollout, deploy Cross-Origin-Embedder-Policy-Report-Only first to inventory subresources that would break under require-corp, then switch to enforcement once the report stream is clean.",
}

local COOP_VALID = {
  ["unsafe-none"]              = true,
  ["same-origin-allow-popups"] = true,
  ["same-origin"]              = true,
  ["noopener-allow-popups"]    = true,
}
local COEP_VALID = {
  ["unsafe-none"]    = true,
  ["require-corp"]   = true,
  ["credentialless"] = true,
}

-- coi_policy_of mirrors coiPolicyOf in the Go check. Returns the
-- lower-cased token, the original value (for human-readable text),
-- and whether any non-empty value was seen.
local function coi_policy_of(values)
  for _, v in ipairs(values) do
    local trimmed = (v:gsub("^%s+", ""):gsub("%s+$", ""))
    if trimmed ~= "" then
      local token = trimmed
      local sc = token:find(";", 1, true)
      if sc then token = token:sub(1, sc - 1) end
      token = (token:gsub("^%s+", ""):gsub("%s+$", ""))
      return string.lower(token), trimmed, true
    end
  end
  return "", "", false
end

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  -- COOP / COEP only meaningful on top-level HTML 200s. The Go
  -- check applies the same gate to keep findings tracking real
  -- attack surface and not non-document responses that happen to
  -- carry the header.
  if snap.status ~= 200 or not ctx.body.is_html_ct(snap.headers:get("Content-Type")) then
    return nil
  end

  local coop_values = snap.headers:values("Cross-Origin-Opener-Policy")
  local coep_values = snap.headers:values("Cross-Origin-Embedder-Policy")
  if #coop_values == 0 and #coep_values == 0 then
    return nil
  end

  local coop_policy, coop_raw, coop_present = coi_policy_of(coop_values)
  local coep_policy, coep_raw, coep_present = coi_policy_of(coep_values)

  local weaknesses = {}
  local function add(sev, id, detail)
    weaknesses[#weaknesses + 1] = { severity = sev, id = id, detail = detail }
  end

  -- Multi-header confusion: structured headers concatenate on
  -- multiple lines and a multi-token parse fails the sf-item rule,
  -- so browsers drop the entire policy. Surface separately.
  if #coop_values > 1 then
    add("low", "coop-multiple-headers",
      string.format(
        "Response carries %d Cross-Origin-Opener-Policy headers. Browsers concatenate same-named headers and parse the result as a single structured-header item; multiple policy tokens fail that parse and the document falls back to the unsafe-none default, so the entire policy is discarded. Consolidate to a single COOP header.",
        #coop_values))
  end
  if #coep_values > 1 then
    add("low", "coep-multiple-headers",
      string.format(
        "Response carries %d Cross-Origin-Embedder-Policy headers. Browsers concatenate same-named headers and parse the result as a single structured-header item; multiple policy tokens fail that parse and the document falls back to the unsafe-none default, so the entire policy is discarded. Consolidate to a single COEP header.",
        #coep_values))
  end

  if coop_present then
    if not COOP_VALID[coop_policy] then
      add("low", "coop-invalid-value:" .. coop_policy,
        string.format(
          'Cross-Origin-Opener-Policy value "%s" is not a recognized policy. Browsers fall back to the unsafe-none default, so this header has no protective effect. Use same-origin (for full isolation and window.opener hardening) or same-origin-allow-popups (when popups still need a live window.opener handle, e.g. OAuth flows).',
          coop_raw))
    elseif coop_policy == "unsafe-none" then
      add("low", "coop-unsafe-none",
        "Cross-Origin-Opener-Policy is explicitly set to unsafe-none. This is the browser default; the header has no protective effect, the document remains exposed to cross-origin window.opener attacks, and no cross-origin isolation is possible. Use same-origin (or same-origin-allow-popups when popups must keep a window.opener handle).")
    elseif coop_policy == "same-origin-allow-popups" or coop_policy == "noopener-allow-popups" then
      if coep_present and coep_policy ~= "unsafe-none" then
        add("low", "coop-allow-popups-with-coep",
          string.format(
            'Cross-Origin-Opener-Policy is "%s" while Cross-Origin-Embedder-Policy is set to "%s". The allow-popups COOP variants do not enable cross-origin isolation; the document will not be cross-origin isolated and SharedArrayBuffer, performance.measureUserAgentSpecificMemory(), and high-resolution timers remain unavailable despite the COEP header. Switch COOP to same-origin if isolation is the goal.',
            coop_raw, coep_raw))
      end
    end
  end

  if coep_present then
    if not COEP_VALID[coep_policy] then
      add("low", "coep-invalid-value:" .. coep_policy,
        string.format(
          'Cross-Origin-Embedder-Policy value "%s" is not a recognized policy. Browsers fall back to the unsafe-none default, so this header has no protective effect. Use require-corp (strict; requires Cross-Origin-Resource-Policy on every cross-origin subresource) or credentialless (newer; cross-origin subresources are fetched without credentials and skipped if they need them).',
          coep_raw))
    elseif coep_policy == "unsafe-none" then
      add("low", "coep-unsafe-none",
        "Cross-Origin-Embedder-Policy is explicitly set to unsafe-none. This is the browser default; the document is not cross-origin isolated and cross-origin subresources can be embedded without their CORP consent. Use require-corp (strict) or credentialless (less invasive rollout) to enable isolation.")
    end
  end

  if coep_present and not coop_present
      and (coep_policy == "require-corp" or coep_policy == "credentialless") then
    add("medium", "coop-missing-with-coep",
      "Cross-Origin-Embedder-Policy is set but Cross-Origin-Opener-Policy is missing. Cross-origin isolation requires BOTH Cross-Origin-Opener-Policy: same-origin and a strong COEP value; with only COEP, require-corp still enforces CORP on cross-origin subresources (and can break embeds that lack a CORP header) but does not enable SharedArrayBuffer, performance.measureUserAgentSpecificMemory(), or high-resolution timers. Add Cross-Origin-Opener-Policy: same-origin.")
  end

  if #weaknesses == 0 then return nil end

  -- Stable order so reports diff cleanly across runs.
  table.sort(weaknesses, function(a, b) return a.id < b.id end)

  local severity_rank = { info = 0, low = 1, medium = 2, high = 3, critical = 4 }
  local max_sev = "info"
  local details = {}
  local id_parts = {}
  for _, w in ipairs(weaknesses) do
    if severity_rank[w.severity] > severity_rank[max_sev] then
      max_sev = w.severity
    end
    details[#details + 1] = "[" .. w.severity .. "]: " .. w.detail
    id_parts[#id_parts + 1] = w.id
  end

  local title
  if #weaknesses == 1 then
    title = "cross-origin isolation has 1 weakness"
  else
    title = string.format("cross-origin isolation has %d weaknesses", #weaknesses)
  end

  local lead_in = string.format(
    "Response from %s carries cross-origin isolation headers but the configuration materially weakens or undoes the protection COOP / COEP are meant to provide. Each entry below names the weakness and how to fix it.",
    ctx.page.url)

  return {{
    severity = ctx.severity[max_sev],
    title    = title,
    detail   = lead_in,
    details  = details,
    evidence = ctx.evidence.build {
      method  = "GET",
      url     = ctx.page.url,
      status  = snap.status,
      headers = snap.headers,
    },
    dedupe_parts = id_parts,
  }}
end

return check
