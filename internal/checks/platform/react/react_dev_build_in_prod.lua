-- react-dev-build-in-prod: flags pages that ship the React or
-- ReactDOM development bundle to production visitors.
--
-- The development build is an unminified, untreeshaken copy of React
-- compiled with `__DEV__ = true`. It is intended for local
-- development only and the React team explicitly warns against
-- deploying it. Two reasons to flag it:
--
--   * Information disclosure: dev-build invariants throw with full
--     human-readable messages (component stack traces, prop names,
--     internal hook state) instead of the production build's minified
--     error code lookup. An attacker triggering an error during a
--     probe gets a free map of the component tree.
--   * Lower-friction exploitation: the dev build performs runtime
--     validation that nudges developers but masks the much faster
--     production code paths. Sites running it in prod are also more
--     likely to be running other dev-mode integrations (verbose
--     logging endpoints, React DevTools relays) that expand the
--     observable surface.
--
-- Detection is passive: scan the HTML body for script srcs that
-- include `react.development.js` or `react-dom.development.js`
-- (UMD on a CDN), or the in-bundle marker string React itself emits
-- when initialized in development mode. The check is host-scoped
-- because a single seed page is enough to prove the bundle is being
-- shipped; later pages on the same host re-use the cache.

local check = {
  name        = "react-dev-build-in-prod",
  level       = levels.passive,
  scope       = scopes.host,
  cwe         = "CWE-489",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Build and deploy the production React bundle. With a bundler, set NODE_ENV=production before the build step (Webpack / Rollup / esbuild will then pull in `react.production.min.js` and dead-code-eliminate `__DEV__` branches). When loading React from a CDN, replace `react.development.js` / `react-dom.development.js` with `react.production.min.js` / `react-dom.production.min.js`.",
  tier        = tiers.passive,
  applies_to  = { framework = { framework.react, framework.nextjs } },
}

-- DEV_PATTERNS match the unminified-bundle name shape used by every
-- shipping React major (UMD on a CDN, the file name copied into a
-- self-hosted /static/ dir, an import-maps entry on jspm). The match
-- is case-insensitive because the few sites that mirror the bundle
-- to S3 occasionally upper-case the path component.
local DEV_PATTERNS = {
  { label = "react.development.js",     pattern = "[Rr][Ee][Aa][Cc][Tt]%.development%.js"     },
  { label = "react-dom.development.js", pattern = "[Rr][Ee][Aa][Cc][Tt]%-[Dd][Oo][Mm]%.development%.js" },
}

-- In-bundle dev-only symbol from React's internal stack-trace
-- machinery. Present in every shipping react-dom dev UMD on the 16,
-- 17, and 18 streams; stripped from the production minified bundle
-- by the build pipeline because the symbol is only referenced from
-- code guarded by `__DEV__`. Matching the inline source is the only
-- signal available when the bundler renamed `react.js` to a hash-
-- suffixed chunk and there's no `.development.` path component left
-- on the wire.
--
-- Earlier revisions of this check probed for a "You are running
-- React in development mode" banner; React never actually emitted
-- that string from the bundle on any shipped major, so the fallback
-- silently never fired. ReactDebugCurrentFrame is a real dev-only
-- token verified against unminified UMDs across React 16.14, 17.0.2,
-- and 18.3.1, and absent from each of their production-min siblings.
local DEV_MARKER = "ReactDebugCurrentFrame"

-- find_dev_evidence returns the first matched marker label (one of
-- the script-src filenames, or the in-bundle dev-only symbol) or ""
-- when the body carries no dev-build signal.
local function find_dev_evidence(body)
  for _, m in ipairs(DEV_PATTERNS) do
    if body:find(m.pattern) ~= nil then return m.label end
  end
  if body:find(DEV_MARKER, 1, true) ~= nil then return DEV_MARKER end
  return ""
end

function check.run(ctx)
  local host_root, ok = ctx.host:claim_from_page()
  if not ok then return nil end

  local snap, err = ctx:ensure_response{ max_body = body_caps.corpus }
  if err then return nil, err end
  if snap == nil or snap.body == "" then return nil end
  if not ctx.body.is_html_ct(snap.headers:get("Content-Type")) then return nil end

  local marker = find_dev_evidence(snap.body)
  if marker == "" then return nil end

  return {
    {
      severity = severity.low,
      target   = host_root,
      url      = ctx.page.url,
      title    = "React development build shipped to production",
      detail   = string.format(
        "Page %s loads the React development build (signal: %q). The development build is " ..
        "unminified, ~10x larger than the production bundle, and emits full human-readable error " ..
        "messages with component stack traces - useful during local development, but a free recon " ..
        "aid for an attacker probing the live site.",
        ctx.page.url, marker),
      evidence = ctx.evidence.build{
        method  = methods.get,
        url     = ctx.page.url,
        status  = snap.status,
        headers = snap.headers,
      },
      dedupe_parts = { "marker:" .. marker },
    },
  }
end

return check
