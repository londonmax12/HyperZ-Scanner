-- mixed-content: scans the HTML body of an HTTPS page for subresources
-- loaded over plaintext http://. Active loads (script, iframe, link,
-- form) are High; passive loads (img, audio, video, ...) are Low. One
-- finding per unique URL; the same offending URL referenced N times
-- collapses to one report row.

local check = {
  name        = "mixed-content",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-319",
  owasp       = "A02:2021 Cryptographic Failures",
  remediation = "Serve the referenced resource over HTTPS, host it locally on the same origin, or remove the reference.",
  tier        = "passive",
}

-- Per tag: { attribute_carrying_the_url, is_active }. <a href> is
-- intentionally absent (anchor links are navigation, not subresource
-- loads). All <link> uses are flagged active as a simplification.
local TAGS = {
  script = { attr = "src",    active = true  },
  iframe = { attr = "src",    active = true  },
  frame  = { attr = "src",    active = true  },
  link   = { attr = "href",   active = true  },
  form   = { attr = "action", active = true  },
  img    = { attr = "src",    active = false },
  video  = { attr = "src",    active = false },
  audio  = { attr = "src",    active = false },
  source = { attr = "src",    active = false },
  embed  = { attr = "src",    active = false },
  track  = { attr = "src",    active = false },
}

local TAG_NAMES = {
  "script","iframe","frame","link","form",
  "img","video","audio","source","embed","track",
}

function check.run(ctx)
  -- Mixed content only exists on an HTTPS page; on http:// the page
  -- itself is the bigger story, surfaced elsewhere.
  if string.sub(string.lower(ctx.page.url), 1, 8) ~= "https://" then
    return nil
  end

  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  -- Skip non-HTML responses (image, JSON, binary). Absent CT is
  -- treated as possibly-HTML - we'd rather scan an unlabeled HTML
  -- page than silently miss one.
  local ct = string.lower(snap.headers:get("Content-Type"))
  if ct ~= "" and not string.find(ct, "html", 1, true) then
    return nil
  end
  if snap.body == "" then
    return nil
  end

  local tags = ctx.html.iter_tags(snap.body, TAG_NAMES)
  -- Group by offending URL so a resource referenced N times produces
  -- one finding. If both an active and a passive tag reference the
  -- same URL, keep the active classification - it's the higher
  -- impact.
  local refs = {}
  for _, tag in ipairs(tags) do
    local spec = TAGS[tag.tag]
    if spec then
      local url = tag.attr[spec.attr]
      if url and string.sub(string.lower(url), 1, 7) == "http://" then
        local prev = refs[url]
        if not prev or (spec.active and not prev.active) then
          refs[url] = { active = spec.active, tag = tag.tag }
        end
      end
    end
  end

  -- Stable URL order so reports diff cleanly across runs.
  local urls = {}
  for u, _ in pairs(refs) do urls[#urls + 1] = u end
  table.sort(urls)

  if #urls == 0 then return nil end

  local findings = {}
  local evidence = ctx.evidence.build {
    method  = "GET",
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }

  for _, u in ipairs(urls) do
    local r = refs[u]
    local severity, kind = "low", "passive"
    if r.active then severity, kind = "high", "active" end
    findings[#findings + 1] = {
      severity = ctx.severity[severity],
      title    = string.format("%s mixed content: <%s> loads %s", kind, r.tag, u),
      detail   = string.format("HTTPS page %s loads %s subresource over plaintext via <%s>: %s",
                               ctx.page.url, kind, r.tag, u),
      evidence = evidence,
      -- Per-host + offending URL: same insecure resource shared
      -- across many crawled pages is one issue. Tag excluded from
      -- the key - the URL is what actually needs fixing.
      dedupe_parts = { "url:" .. u },
    }
  end
  return findings
end

return check
