-- js-libs-known-vuln: scans <script src> tags on an HTML response,
-- identifies known JS libraries from their URL pattern, and emits one
-- finding per (library, version) pair. A version that matches a row
-- in the per-library vulnerable-versions table escalates to medium
-- with a CVE / vuln-class list; an unmatched version stays info.

local check = {
  name  = "js-libs-known-vuln",
  level = levels.passive,
  scope = scopes.host,
  tier  = tiers.fingerprint,
}

function check.run(ctx)
  local snap, err = ctx:ensure_response{ max_body = 1024 * 1024 }
  if err then return nil, err end

  -- HTML-only; non-HTML responses (JSON APIs, asset files) carry no
  -- <script src> markup for the scanner to walk.
  if not ctx.body.is_html_ct(snap.headers:get("Content-Type")) then
    return nil
  end
  if snap.body == "" then return nil end

  local hits = ctx.supply_chain.scan_known_js_libs(snap.body)
  if #hits == 0 then return nil end

  local evidence = ctx.evidence.build {
    method  = methods.get,
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }

  local findings = {}
  for _, h in ipairs(hits) do
    if #h.vulnerabilities == 0 then
      -- Library detected but no known vulns at this version - info.
      findings[#findings + 1] = {
        severity    = severity.info,
        title       = "detected JavaScript library: " .. h.name,
        detail      = string.format(
          "script analysis detected %s version %s; no known vulnerabilities for this version",
          h.name, h.version),
        cwe         = "CWE-200",
        owasp       = "A05:2021 Security Misconfiguration",
        remediation = "Ensure all JavaScript libraries are kept up-to-date. Monitor security advisories for the libraries used.",
        evidence    = evidence,
        dedupe_parts = { "lib:" .. h.name },
      }
    else
      -- Vulnerable version detected; the title carries the library +
      -- version so the report row distinguishes "jquery 1.7" from
      -- "jquery 2.1" without forcing the reader into Details.
      local detail
      if #h.vulnerabilities == 1 then
        detail = string.format(
          "detected %s version %s which has a known vulnerability: %s",
          h.name, h.version, h.vulnerabilities[1])
      else
        detail = string.format(
          "detected %s version %s which has known vulnerabilities: %s",
          h.name, h.version, table.concat(h.vulnerabilities, ", "))
      end
      findings[#findings + 1] = {
        severity    = severity.medium,
        title       = string.format("%s (version %s) detected with known vulnerabilities", h.name, h.version),
        detail      = detail,
        cwe         = "CWE-1104",
        owasp       = "A06:2021 Vulnerable and Outdated Components",
        remediation = string.format(
          "Update %s to the latest stable version. Check the project's security advisory page for details on what vulnerabilities have been patched.",
          h.name),
        evidence    = evidence,
        dedupe_parts = { "vuln:" .. h.name .. ":" .. h.version },
      }
    end
  end
  return findings
end

return check
