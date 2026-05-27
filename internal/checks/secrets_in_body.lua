-- secrets-in-body: scans response bodies for high-confidence
-- credential patterns (cloud keys, VCS tokens, AI provider keys,
-- private keys, JWTs). Pattern catalogue and the redaction format
-- sit behind ctx.body.find_secrets / ctx.body.redact_secret.

local check = {
  name        = "secrets-in-body",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-200, CWE-798",
  owasp       = "A02:2021 Cryptographic Failures",
  remediation = "Rotate every leaked credential immediately - assume it is already public from the moment it was served. "
                .. "Audit access logs for the affected key during the exposure window. "
                .. "Remove the embedded value from the source that generated this response (HTML template, JS bundle, JSON serializer, error/debug handler) and replace it with a server-side lookup or a short-lived, scoped token issued per request. "
                .. "For build-time leaks (keys baked into JS bundles), move the secret to an environment variable consumed only by the backend and front the third-party call with a same-origin proxy endpoint.",
}

local SEVERITY_RANK = { info = 0, low = 1, medium = 2, high = 3, critical = 4 }

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end
  if snap.body == "" then return nil end
  if not ctx.body.is_scannable_ct(snap.headers:get("Content-Type")) then
    return nil
  end

  local hits = ctx.body.find_secrets(snap.body)
  if #hits == 0 then return nil end

  local max_sev = "info"
  local details = {}
  local id_parts = {}
  for _, h in ipairs(hits) do
    if SEVERITY_RANK[h.severity] > SEVERITY_RANK[max_sev] then
      max_sev = h.severity
    end
    local occ = ""
    if h.count > 1 then
      occ = string.format(" (%d occurrences)", h.count)
    end
    details[#details + 1] = string.format("%s [%s]: %s%s", h.label, h.severity, h.redacted, occ)
    -- DedupeKey parts mix pattern id with redacted token so two
    -- distinct keys of the same type on the same host stay distinct
    -- findings, but the same key surfaced from several crawled pages
    -- collapses to one.
    id_parts[#id_parts + 1] = h.id .. ":" .. h.redacted
  end

  local title
  if #hits == 1 then
    title = "Response body leaks a credential (" .. hits[1].label .. ")"
  else
    title = string.format("Response body leaks %d distinct credentials", #hits)
  end

  local lead_in = string.format(
    "Response from %s contains values that match known credential patterns. Each entry below names the credential type and a redacted form of what was found in the body; treat every match as compromised the moment the response was served.",
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
