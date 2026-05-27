-- target-blank-noopener: flags <a>, <area>, <form> with
-- target="_blank" that omit rel="noopener" / "noreferrer". The new
-- browsing context receives a live window.opener handle - reverse-
-- tabnabbing surface. Severity climbs to Medium for cross-origin
-- destinations.

local check = {
  name  = "target-blank-noopener",
  level = "passive",
  scope = "page",
  cwe   = "CWE-1022",
  owasp = "A05:2021 Security Misconfiguration",
  tier  = "passive",
}

local INTERESTING_TAGS = { "base", "a", "area", "form" }

-- rel is space-separated; any of noopener / noreferrer counts as safe.
local function rel_has_safe_token(rel)
  for tok in string.gmatch(rel, "%S+") do
    local lo = string.lower(tok)
    if lo == "noopener" or lo == "noreferrer" then
      return true
    end
  end
  return false
end

local function attr_label_for(tag)
  if tag == "form" then return "action" end
  return "href"
end

local function href_attr_for(tag)
  if tag == "form" then return "action" end
  return "href"
end

local function build_title(tag, cross_origin)
  local origin = "same-origin"
  if cross_origin then origin = "cross-origin" end
  return string.format('<%s target="_blank"> to %s URL without rel="noopener"', tag, origin)
end

local function build_detail(page_url, tag, raw, resolved, cross_origin)
  local detail = string.format(
    'Page %s contains <%s target="_blank" %s="%s"> resolving to %s without rel="noopener" or rel="noreferrer". ',
    page_url, tag, attr_label_for(tag), raw, resolved)
  detail = detail .. "The new browsing context receives a live window.opener handle to this page; "
  detail = detail .. 'script in the destination can call window.opener.location = "..." to silently navigate this tab to a phishing page (reverse tabnabbing). '
  if cross_origin then
    detail = detail .. "The destination is cross-origin, so any compromise or hostile content on that origin can pivot back into this site's tab."
  else
    detail = detail .. "The destination is same-origin, so direct impact is limited, but the missing attribute is still defense-in-depth worth fixing."
  end
  return detail
end

local function build_remediation(tag)
  if tag == "form" then
    return 'Add rel="noopener noreferrer" to the <form> element. Forms with target="_blank" did not get the same browser-default noopener treatment that anchors received, so the explicit attribute is the only portable guarantee.'
  end
  return 'Add rel="noopener noreferrer" to the element (e.g. <a href="..." target="_blank" rel="noopener noreferrer">). Modern browsers default anchors with target="_blank" to noopener, but older browsers, embedded webviews, and any code that opens windows via JavaScript still rely on the explicit attribute. noreferrer additionally suppresses the Referer header for cases where the destination should not see where the click came from.'
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

  local tags = ctx.html.iter_tags(snap.body, INTERESTING_TAGS)
  local base_url = ctx.page.url

  local evidence = ctx.evidence.build {
    method  = "GET",
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }

  local findings = {}
  local seen = {}

  for _, tag in ipairs(tags) do
    if tag.tag == "base" then
      local href = tag.attr["href"]
      if href and href ~= "" then
        local resolved, ok = ctx.html.resolve_ref(base_url, href)
        if ok then base_url = resolved end
      end
    else
      local target = string.lower((tag.attr["target"] or ""):gsub("^%s+", ""):gsub("%s+$", ""))
      if target == "_blank" then
        local rel = tag.attr["rel"] or ""
        if not rel_has_safe_token(rel) then
          local href = tag.attr[href_attr_for(tag.tag)] or ""
          local resolved, ok = ctx.html.resolve_ref(base_url, href)
          if ok then
            local ru, urerr = ctx.url.parse(resolved)
            if not urerr and ru and ru.host ~= ""
                and (ru.scheme == "http" or ru.scheme == "https") then
              local key = "ref:" .. tag.tag .. "|" .. resolved
              if not seen[key] then
                seen[key] = true
                local cross_origin = string.lower(ru.hostname) ~= string.lower(page_url.hostname)
                local severity = "low"
                if cross_origin then severity = "medium" end
                findings[#findings + 1] = {
                  severity    = ctx.severity[severity],
                  title       = build_title(tag.tag, cross_origin),
                  detail      = build_detail(ctx.page.url, tag.tag, href, resolved, cross_origin),
                  remediation = build_remediation(tag.tag),
                  evidence    = evidence,
                  dedupe_parts = { key },
                }
              end
            end
          end
        end
      end
    end
  end

  -- Stable order so per-page reports diff cleanly across runs.
  table.sort(findings, function(a, b)
    return a.dedupe_parts[1] < b.dedupe_parts[1]
  end)

  return findings
end

return check
