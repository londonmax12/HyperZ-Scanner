-- sri-missing: flags <script src> / <link rel="stylesheet|preload|
-- modulepreload|prefetch" href> loaded from a different host without
-- integrity=... Same-origin loads and <iframe> (which has no SRI
-- mechanism in any browser) are deliberately excluded.

local check = {
  name        = "sri-missing",
  level       = levels.passive,
  scope       = scopes.host,
  cwe         = "CWE-345",
  owasp       = "A08:2021 Software and Data Integrity Failures",
  remediation = 'Add integrity="sha384-<base64-hash>" (and crossorigin="anonymous" for cross-origin loads) to the tag. '
                .. "Most public CDNs (jsDelivr, unpkg, cdnjs) publish SRI hashes alongside their URLs; "
                .. "for self-hosted assets generate one with `openssl dgst -sha384 -binary <file> | openssl base64 -A`. "
                .. "Alternatively, host the file from the same origin so the integrity question collapses to TLS.",
  tier        = tiers.passive,
}

local LINK_RELS = {
  stylesheet    = true,
  preload       = true,
  modulepreload = true,
  prefetch      = true,
}

-- rel is a space-separated token list; any one of LINK_RELS qualifies.
-- Empty rel is inert in browsers and skipped.
local function link_rel_is_sri_eligible(rel)
  for tok in string.gmatch(rel, "%S+") do
    if LINK_RELS[string.lower(tok)] then return true end
  end
  return false
end

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end
  if not ctx.body.is_html_ct(snap.headers:get("Content-Type")) then
    return nil
  end
  if snap.body == "" then return nil end

  local page_url, perr = ctx.url.parse(ctx.page.url)
  if perr or not page_url or page_url.host == "" then return nil end

  local tags = ctx.html.iter_tags(snap.body, { "script", "link" })
  local findings = {}
  local seen = {}
  local evidence = ctx.evidence.build {
    method  = methods.get,
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }

  for _, tag in ipairs(tags) do
    local resource_attr
    if tag.tag == "script" then
      resource_attr = "src"
    elseif tag.tag == "link" then
      resource_attr = "href"
    end
    if resource_attr then
      local rel = tag.attr["rel"] or ""
      local resource_url = tag.attr[resource_attr] or ""
      local integrity = tag.attr["integrity"] or ""

      -- <link> only fetches an SRI-eligible resource for specific
      -- rels; everything else (icon, canonical, dns-prefetch, ...)
      -- has no SRI either-way.
      local eligible = true
      if tag.tag == "link" and not link_rel_is_sri_eligible(rel) then
        eligible = false
      end

      if eligible and integrity == "" and (resource_url:gsub("^%s+", ""):gsub("%s+$", "")) ~= "" then
        -- ctx.html.resolve_ref handles the non-network skip set
        -- (data:, javascript:, blob:, fragment).
        local resolved, ok = ctx.html.resolve_ref(ctx.page.url, resource_url)
        if ok then
          local ru, rperr = ctx.url.parse(resolved)
          if not rperr and ru and ru.host ~= "" then
            -- Same-origin: SRI adds nothing. hostname() strips port
            -- so default-port mismatches don't false-positive.
            if string.lower(ru.hostname) ~= string.lower(page_url.hostname) then
              local key = "url:" .. resolved
              if not seen[key] then
                seen[key] = true
                local sev_key = "medium"
                if tag.tag == "script" then sev_key = "high" end
                findings[#findings + 1] = {
                  severity = severity[sev_key],
                  title    = string.format("cross-origin <%s> loaded without Subresource Integrity", tag.tag),
                  detail   = string.format(
                    "Page %s loads <%s> from %s without an integrity attribute. "
                      .. "An attacker who compromises that origin or sits on the network path between the "
                      .. "browser and the CDN can substitute the file with malicious content and the browser "
                      .. "will execute it as if it were trusted first-party code.",
                    ctx.page.url, tag.tag, resolved),
                  evidence = evidence,
                  dedupe_parts = { key },
                }
              end
            end
          end
        end
      end
    end
  end

  return findings
end

return check
