-- hsts-weak: Lua port of internal/checks/hsts_weak.go.
--
-- Inspects a present Strict-Transport-Security header for
-- configurations that materially weaken or undo the downgrade
-- protection HSTS provides: short max-age, missing
-- includeSubDomains, the max-age=0 un-pin signal, malformed
-- directives, multi-header duplication, or the header being
-- delivered over plain HTTP.
--
-- Directive parsing (split, duplicate detection, quoted-string
-- handling) is delegated to the Go ctx.body.parse_hsts helper so the
-- spec-fatal duplicate-detection lives in exactly one place. The
-- per-weakness severity bands and detail text are the Lua port's job.

local check = {
  name        = "hsts-weak",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-319",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Aim for Strict-Transport-Security: max-age=63072000; includeSubDomains; preload. "
                .. "Confirm every subdomain serves HTTPS before enabling includeSubDomains. "
                .. "Once max-age >= 31536000, includeSubDomains, and preload are in place, submit the host at https://hstspreload.org so first-visit downgrade is also defeated.",
}

local HSTS_MAX_AGE_RECOMMENDED = 31536000  -- 1 year
local HSTS_MAX_AGE_SHORT       = 15552000  -- 6 months
local HSTS_MAX_AGE_VERY_SHORT  = 86400     -- 1 day

local SEVERITY_RANK = { info = 0, low = 1, medium = 2, high = 3, critical = 4 }

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  local values = snap.headers:values("Strict-Transport-Security")
  if #values == 0 then
    -- Absence is security-headers' job; nothing for us to say.
    return nil
  end

  -- Per RFC 6797 §8.1 the UA processes only the first HSTS header
  -- when multiple are present. parse_hsts honors that; duplication
  -- is surfaced separately so an author notices the masking.
  local parsed = ctx.body.parse_hsts(values[1])

  local weaknesses = {}
  local function add(sev, id, detail)
    weaknesses[#weaknesses + 1] = { severity = sev, id = id, detail = detail }
  end

  -- HSTS over plain HTTP is silently ignored by browsers; flag it
  -- separately because authors often miss that the header has no
  -- effect on the upgrade-path response.
  local u, perr = ctx.url.parse(ctx.page.url)
  if not perr and u and string.lower(u.scheme) == "http" then
    add("low", "over-http",
      "Strict-Transport-Security is delivered over plain HTTP. RFC 6797 §8.1 requires user agents to ignore HSTS headers received over insecure transport, so this header provides no protection at all. Serve HSTS only over HTTPS, and redirect HTTP to HTTPS so the first secure response can set the pin.")
  end

  if #values > 1 then
    add("low", "multiple-headers",
      string.format(
        "Response carries %d Strict-Transport-Security headers. RFC 6797 §8.1 directs the user agent to process only the first; subsequent headers are silently dropped, masking whichever policy the author actually intended. Consolidate to a single header.",
        #values))
  end

  for _, pe in ipairs(parsed.errors) do
    add("low", "malformed:" .. pe.id, pe.detail)
  end

  local max_age_raw = parsed.directives["max-age"]
  if max_age_raw == nil then
    add("high", "missing-max-age",
      "max-age is required by RFC 6797 §6.1; a Strict-Transport-Security header without it is invalid and browsers discard the whole policy. Set max-age=63072000; includeSubDomains; preload (or at minimum max-age=31536000) to actually pin the host.")
  else
    local trimmed = (max_age_raw:gsub("^%s+", ""):gsub("%s+$", ""))
    local v = tonumber(trimmed)
    if v == nil or v ~= math.floor(v) or v < 0 then
      add("high", "max-age-invalid",
        string.format(
          'max-age="%s" is not a non-negative integer; browsers treat the entire HSTS header as invalid and discard it. Set max-age to a positive number of seconds, e.g. max-age=63072000.',
          max_age_raw))
    elseif v == 0 then
      add("high", "max-age-zero",
        "max-age=0 instructs browsers to immediately forget any HSTS pin they previously cached for this host, effectively turning HSTS off. Unless this is a deliberate, time-boxed rollback, ship a real max-age (e.g. 63072000) so the host stays pinned.")
    elseif v < HSTS_MAX_AGE_VERY_SHORT then
      add("high", "max-age-tiny",
        string.format(
          "max-age=%d (less than one day) is short enough that an attacker who can keep a victim off HTTPS even briefly will see the pin expire. Raise to at least max-age=31536000 (one year).",
          v))
    elseif v < HSTS_MAX_AGE_SHORT then
      add("medium", "max-age-short",
        string.format(
          "max-age=%d (less than six months) is below the preload-list floor and well under standard guidance. Raise to max-age=31536000 (one year) or 63072000 (two years) so the pin survives long enough to actually defeat downgrade attempts.",
          v))
    elseif v < HSTS_MAX_AGE_RECOMMENDED then
      add("low", "max-age-below-year",
        string.format(
          "max-age=%d is below the one-year (31536000) value required for the HSTS preload list and recommended by Mozilla Observatory. Raise to at least max-age=31536000.",
          v))
    end
  end

  if parsed.directives["includesubdomains"] == nil then
    add("low", "missing-include-subdomains",
      "includeSubDomains is not set. Subdomains of this host (login.example.com, api.example.com, ...) get no HSTS protection from this policy, leaving cookie-stealing downgrade vectors via any HTTP-served subdomain. Confirm every subdomain serves HTTPS, then add includeSubDomains.")
  end

  if #weaknesses == 0 then return nil end

  table.sort(weaknesses, function(a, b) return a.id < b.id end)

  local max_sev = "info"
  local details = {}
  local id_parts = {}
  for _, w in ipairs(weaknesses) do
    if SEVERITY_RANK[w.severity] > SEVERITY_RANK[max_sev] then max_sev = w.severity end
    details[#details + 1] = "[" .. w.severity .. "]: " .. w.detail
    id_parts[#id_parts + 1] = w.id
  end

  local title
  if #weaknesses == 1 then
    title = "Strict-Transport-Security has 1 weakness"
  else
    title = string.format("Strict-Transport-Security has %d weaknesses", #weaknesses)
  end

  local lead_in = string.format(
    "Response from %s ships a Strict-Transport-Security header but its configuration materially weakens the downgrade-attack protection HSTS is meant to provide. Each entry below names the weakness and how to fix it.",
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
