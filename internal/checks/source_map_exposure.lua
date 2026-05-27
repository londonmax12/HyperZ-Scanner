-- source-map-exposure: detects publicly-served JS/CSS source maps.
-- Chains two signals so the check stays high-confidence:
--
--   1) The JS/CSS response advertises a source map (header or
--      `//# sourceMappingURL=` trailing comment for JS,
--      `/*# sourceMappingURL=... */` for CSS).
--   2) The referenced URL fetches successfully AND the body parses
--      as a Source Map v3 document.

local check = {
  name        = "source-map-exposure",
  level       = levels.passive,
  scope       = scopes.host,
  cwe         = "CWE-540",
  owasp       = "A05:2021 Security Misconfiguration",
  tier        = tiers.passive,
}

local SOURCE_MAP_PROBE_BODY_CAP = 64 * 1024

local function inline_finding(ctx, snap, data_uri)
  local preview = data_uri
  if #preview > 80 then preview = string.sub(preview, 1, 80) .. "..." end
  return {
    severity = severity.medium,
    title    = "inline source map embedded in deployed bundle",
    detail   = string.format(
      "%s carries an inline `sourceMappingURL=data:...` declaration. The full pre-minified source (original file paths, comments, variable names, and any literals the minifier preserved) is base64-embedded in the bundle every visitor downloads.",
      ctx.page.url),
    remediation = "Disable inline source maps in the production build (webpack `devtool: 'hidden-source-map'` or false, Vite `build.sourcemap: false` or 'hidden', Rollup `sourcemap: false`, esbuild `--sourcemap=external` paired with deploy-time exclusion). "
                  .. "If maps are needed for crash deobfuscation, upload them to a private symbol service (Sentry, Datadog, Bugsnag) at build time and ship the bundle without the embedded copy.",
    evidence = ctx.evidence.build {
      method  = methods.get,
      url     = ctx.page.url,
      status  = snap.status,
      headers = snap.headers,
      body    = "sourceMappingURL: " .. preview,
    },
    dedupe_parts = { "inline:" .. ctx.page.url },
  }
end

local function external_finding(ctx, resp, map_url)
  return {
    severity = severity.medium,
    url      = map_url,
    title    = "source map exposed at " .. map_url,
    detail   = string.format(
      "%s advertises a source map at %s, and that URL returns a valid Source Map document. The map exposes the pre-minified source: original file paths (revealing internal directory structure and naming intent), comments, full variable names, and any literals the minifier preserved (build-time constants, internal URLs, occasionally credentials).",
      ctx.page.url, map_url),
    remediation = "Stop serving .map files from the public document root. Either build production bundles without source maps (webpack `devtool: false`, Vite `build.sourcemap: false`) or generate them and upload to a private symbol service (Sentry, Datadog) for crash deobfuscation instead of the asset host. "
                  .. "If maps must remain on disk for tooling, add a web-server rule that returns 404 for `*.map` requests and strip the `sourceMappingURL` reference from the bundle (webpack/Vite `'hidden-source-map'`). "
                  .. "Before remediating, audit the leaked map for hardcoded API keys, internal hostnames, and unreleased feature names; rotate or remove anything sensitive.",
    evidence = ctx.evidence.build {
      method  = methods.get,
      url     = map_url,
      status  = resp:status(),
      headers = resp:headers(),
    },
    dedupe_parts = { "map:" .. map_url },
  }
end

-- resolve_source_map_url turns a (possibly relative) ref into the
-- absolute http(s) URL the browser would fetch. Returns ("",
-- err_string) for refs that don't resolve to an http(s) target.
local function resolve_source_map_url(ctx, base, ref)
  -- ctx.html.resolve_ref applies the same skip-set (data:, fragment,
  -- javascript:, ...) but data: is already handled by the caller.
  local resolved, ok = ctx.html.resolve_ref(base, ref)
  if not ok then return "", "source map reference does not resolve" end
  local u, perr = ctx.url.parse(resolved)
  if perr or not u then return "", "parse: " .. (perr or "nil") end
  if u.scheme ~= "http" and u.scheme ~= "https" then
    return "", "non-http scheme"
  end
  return resolved
end

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end
  local kind, ok = ctx.body.source_map_kind(snap.headers:get("Content-Type"))
  if not ok then return nil end

  local ref = ctx.body.find_source_map_ref(snap.headers, snap.body, kind)
  if ref == "" then return nil end

  -- Inline (data:) map - the .map content is embedded in the bundle
  -- every visitor downloads. No follow-up fetch can add information.
  if string.sub(string.lower(ref), 1, 5) == "data:" then
    return { inline_finding(ctx, snap, ref) }
  end

  local resolved, rerr = resolve_source_map_url(ctx, ctx.page.url, ref)
  if rerr or resolved == "" then return nil end
  if not ctx.scope:allows(resolved) then return nil end

  local resp, do_err = ctx.client:get(resolved)
  if do_err then
    -- One probe failure is not a fatal scan error; leave a breadcrumb
    -- and move on so a flaky CDN doesn't blank the report.
    ctx:report("source-map-exposure probe " .. resolved .. ": " .. do_err)
    return nil
  end

  -- Redirect chain may have landed off-scope; drop rather than
  -- report on an out-of-scope host.
  local final_url = resp:request_url()
  if final_url ~= "" and not ctx.scope:allows(final_url) then
    return nil
  end
  if resp:status() ~= 200 then return nil end

  local body, _, read_err = resp:read_body_capped(SOURCE_MAP_PROBE_BODY_CAP)
  if read_err then
    ctx:report("source-map-exposure read " .. resolved .. ": " .. read_err)
    return nil
  end
  if not ctx.body.looks_like_source_map(body) then return nil end

  return { external_finding(ctx, resp, resolved) }
end

return check
