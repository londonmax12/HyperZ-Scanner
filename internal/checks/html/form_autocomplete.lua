-- form-autocomplete: detects sensitive <input> fields that allow
-- browser autocomplete. The threat model is narrow (attacker with
-- browser access), so the severity tops out at Low / Info - this is
-- a hardening hint, not an exploitable bug.

local check = {
  name  = "form-autocomplete",
  level = levels.passive,
  scope = scopes.page,
  cwe   = "CWE-1021",
  owasp = "A05:2021 Security Misconfiguration",
  tier  = tiers.passive,
}

-- input type -> severity. Every entry is Info today; the per-type
-- map exists so an author can override individual types without
-- rewriting the lookup.
local SENSITIVE_INPUTS = {
  password = "info",
  email    = "info",
  tel      = "info",
  phone    = "info",
  url      = "info",
  search   = "info",
}

-- Name-substring patterns that bump a plain text input to sensitive
-- (credit card, SSN, ...).
local SENSITIVE_NAME_PATTERNS = {
  card     = "low",
  cvv      = "low",
  cvc      = "low",
  ssn      = "low",
  passport = "low",
  tax      = "low",
  account  = "info",
  pin      = "low",
}

local SAFE_AUTOCOMPLETE = {
  ["off"]              = true,
  ["new-password"]     = true,
  ["current-password"] = true,
  ["new"]              = true,
}

local function detect_by_pattern(name)
  local lower = string.lower(name)
  for pat, sev in pairs(SENSITIVE_NAME_PATTERNS) do
    if string.find(lower, pat, 1, true) then
      return sev, true
    end
  end
  return nil, false
end

function check.run(ctx)
  if ctx.page.body == "" then return nil end

  local tags = ctx.html.iter_tags(ctx.page.body, { "input" })
  local findings = {}
  local seen = {}
  local evidence = ctx.evidence.build {
    method  = methods.get,
    url     = ctx.page.url,
    status  = ctx.page.status,
    headers = ctx.page.headers,
  }

  for _, tag in ipairs(tags) do
    local name_attr     = tag.attr["name"] or ""
    local type_attr     = string.lower(tag.attr["type"] or "")
    local autocomplete  = string.lower(tag.attr["autocomplete"] or "")
    if name_attr ~= "" then
      local sev_key = SENSITIVE_INPUTS[type_attr]
      local is_sensitive = sev_key ~= nil
      if not is_sensitive then
        sev_key, is_sensitive = detect_by_pattern(name_attr)
      end
      if is_sensitive and not SAFE_AUTOCOMPLETE[autocomplete] then
        local key = "field:" .. name_attr
        if not seen[key] then
          seen[key] = true
          findings[#findings + 1] = {
            severity = severity[sev_key],
            title    = string.format('sensitive form field "%s" allows browser autocomplete', name_attr),
            detail   = string.format(
              'Input field "%s" (type="%s") at %s does not disable autocomplete. An attacker with access to the browser (malware, physical theft) can retrieve previously entered values from browser history or password manager integration.',
              name_attr, type_attr, ctx.page.url),
            remediation = 'Add autocomplete="off" (or "new-password" for password fields) to the <input> element to prevent browser autocomplete for this field.',
            evidence    = evidence,
            dedupe_parts = { key },
          }
        end
      end
    end
  end

  return findings
end

return check
