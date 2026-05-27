-- subdomain-takeover: flags hostnames whose DNS still points at a
-- third-party SaaS provider (GitHub Pages, S3, Heroku, Azure, Fastly,
-- ...) but where the upstream resource is unclaimed. Two detection
-- paths:
--
--   1. CNAME-confirmed: the host CNAMEs into a known provider AND
--      the edge serves its "unclaimed" body fingerprint. High.
--   2. Fingerprint-only: DNS does not surface a provider CNAME but
--      the host root returns body + provider-identifying headers
--      that pin the response to the SaaS edge anyway. Medium.
--
-- The scanner algorithm (DNS lookups, provider-pattern matching,
-- body/header fingerprint scans, per-scan per-host cache) lives behind
-- ctx.takeover.evaluate, which returns raw scan facts; everything else
-- (title, severity, detail, remediation, dedupe key, evidence) is
-- composed here.

local check = {
  name  = "subdomain-takeover",
  level = "passive",
  scope = "host",
  cwe   = "CWE-1104",
  owasp = "A05:2021 Security Misconfiguration",
}

-- Generic suffixes appended to the per-provider guidance prefix the
-- bridge returns.
local REMEDIATION_TAIL_CNAME = " " ..
  "Before remediating, audit cookies scoped to the parent domain (Domain=.example.com) and any OAuth / SSO callbacks that trust the hostname - a successful takeover would have inherited both. " ..
  "As a longer-term control, gate DNS record creation on proof of upstream ownership and add periodic checks (or a SIEM rule) that re-resolves CNAMEs and probes the listed providers for unclaimed-resource fingerprints."

local REMEDIATION_TAIL_FINGERPRINT = " " ..
  "Confirm the hostname's DNS chain (CNAME, A, fronting proxies) before treating this as exploitable - the edge response alone proves the upstream is unclaimed, but a fronting proxy may limit claimability. " ..
  "As a longer-term control, gate DNS record creation on proof of upstream ownership and add periodic checks that probe known SaaS edges for unclaimed-resource fingerprints regardless of DNS shape."

-- Per-header clip on the "matched headers" line.
local HEADER_VALUE_CAP = 80

local function matched_headers_summary(matched)
  if not matched or #matched == 0 then return "(none captured)" end
  local parts = {}
  for i, hit in ipairs(matched) do
    local value = hit.value
    if #value > HEADER_VALUE_CAP then
      value = value:sub(1, HEADER_VALUE_CAP) .. "..."
    end
    parts[i] = hit.name .. ": " .. value
  end
  return table.concat(parts, "; ")
end

-- compose_cname builds the High-severity finding for the CNAME-
-- confirmed path.
local function compose_cname(ctx, facts)
  local details = {
    string.format("Hostname resolves via CNAME to %q, which matches %s's edge.",
      facts.cname, facts.provider),
  }
  if facts.dns_note ~= "" then
    details[#details + 1] = facts.dns_note
  end
  if facts.status ~= 0 then
    details[#details + 1] = string.format(
      "The %s edge responded with status %d and the provider's canonical \"unclaimed resource\" fingerprint.",
      facts.provider, facts.status)
  end
  details[#details + 1] = "An attacker who registers the freed-up resource on their own account will host arbitrary content at this hostname, with valid TLS and any cookies the parent domain scopes to it."

  -- Synthetic evidence markers (X-Subdomain-Takeover-*) label the
  -- evidence with the detection that produced it. Only attached when
  -- a probe response existed; the NXDOMAIN-only path leaves status=0
  -- and therefore no headers / body to render.
  local evidence_headers = {}
  if facts.status ~= 0 then
    evidence_headers["X-Subdomain-Takeover-Provider"] = facts.provider
    evidence_headers["X-Subdomain-Takeover-CNAME"]    = facts.cname
  end

  return {
    severity = ctx.severity.high,
    title    = "subdomain takeover via dangling " .. facts.provider .. " CNAME",
    detail   = string.format(
      "Hostname's DNS still points at %s but the upstream resource is unclaimed; the edge serves its canonical \"this resource does not exist\" page. Each entry below explains the evidence.",
      facts.provider),
    details     = details,
    remediation = facts.provider_guidance .. REMEDIATION_TAIL_CNAME,
    evidence    = ctx.evidence.build {
      method  = "GET",
      url     = facts.probe_url,
      status  = facts.status,
      headers = evidence_headers,
      body    = facts.body_preview,
    },
    -- Dedupe target is the probed host root, not the current page,
    -- so a 50-page crawl of one vulnerable subdomain collapses to one
    -- finding. The marshal layer's default `dedupe_parts` path would
    -- key off the current page URL; we override with an explicit key.
    dedupe_key = ctx.dedupe.key {
      check  = "subdomain-takeover",
      scope  = "host",
      target = facts.probe_url,
      parts  = { "cname:" .. facts.cname, "provider:" .. facts.provider },
    },
  }
end

-- compose_fingerprint builds the Medium-severity finding for the
-- DNS-blind path. The matched provider-identifying headers come back
-- in facts.matched_headers and are re-attached to the evidence so the
-- report shows exactly which response markers triggered the match.
local function compose_fingerprint(ctx, facts)
  local matched_summary = matched_headers_summary(facts.matched_headers)
  local details = {
    string.format(
      "The edge at this hostname responded with status %d, the canonical %s \"unclaimed resource\" body, and the provider-identifying response header(s) %s.",
      facts.status, facts.provider, matched_summary),
    "DNS does not surface a CNAME to this provider, so the chain is either A-recorded straight at the provider, fronted by a CDN/proxy that hides the upstream, or served through a third-party DNS that flattens it. Either way, the public-facing edge is the provider's and the upstream resource is unclaimed.",
    "Verify who controls the DNS record and whether the upstream resource can be claimed under the provider's account model; if so, an attacker can host arbitrary content at this hostname with valid TLS and inherit cookies the parent domain scopes to it.",
  }

  -- evidence_headers is built as a Lua table-of-arrays because the
  -- matched provider-identifying headers can legitimately repeat
  -- (e.g. multiple X-Served-By entries on Fastly). evidence.build
  -- accepts a string OR string-array per name.
  local evidence_headers = {
    ["X-Subdomain-Takeover-Provider"]  = facts.provider,
    ["X-Subdomain-Takeover-Detection"] = "response-fingerprint",
  }
  for _, hit in ipairs(facts.matched_headers or {}) do
    local existing = evidence_headers[hit.name]
    if existing == nil then
      evidence_headers[hit.name] = hit.value
    elseif type(existing) == "string" then
      evidence_headers[hit.name] = { existing, hit.value }
    else
      existing[#existing + 1] = hit.value
    end
  end

  return {
    severity = ctx.severity.medium,
    title    = "possible subdomain takeover: " .. facts.provider .. " edge serves unclaimed-resource page",
    detail   = string.format(
      "The hostname's edge response identifies it as %s and matches the provider's canonical \"unclaimed resource\" page, but DNS does not surface a CNAME to this provider. Each entry below explains the evidence.",
      facts.provider),
    details     = details,
    remediation = facts.provider_guidance .. REMEDIATION_TAIL_FINGERPRINT,
    evidence    = ctx.evidence.build {
      method  = "GET",
      url     = facts.probe_url,
      status  = facts.status,
      headers = evidence_headers,
      body    = facts.body_preview,
    },
    dedupe_key = ctx.dedupe.key {
      check  = "subdomain-takeover",
      scope  = "host",
      target = facts.probe_url,
      parts  = { "fingerprint", "provider:" .. facts.provider },
    },
  }
end

function check.run(ctx)
  local facts, err = ctx.takeover.evaluate("saas", ctx.page.url)
  if err then
    ctx:report("subdomain-takeover: " .. err)
    return nil
  end
  if facts == nil then return nil end

  local finding
  if facts.detection == "fingerprint" then
    finding = compose_fingerprint(ctx, facts)
  else
    finding = compose_cname(ctx, facts)
  end
  return { finding }
end

return check
