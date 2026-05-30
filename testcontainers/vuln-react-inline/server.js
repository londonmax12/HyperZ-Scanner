// vuln-react-inline: serves a single HTML page that inlines the real
// React + ReactDOM development UMD source between <script> tags, with
// the filename literals scrubbed so the only dev-mode signal left in
// the body is the in-bundle DEV_MARKER symbol.
//
// Why this fixture exists: react-dev-build-in-prod has three
// detection signals:
//
//   1. <script src> referencing react.development.js
//   2. <script src> referencing react-dom.development.js
//   3. The literal "ReactDebugCurrentFrame" anywhere in the page body
//      - a dev-only React-internal stack-trace symbol that the
//        production minifier strips, so its presence is a high-
//        confidence signal that an unminified dev bundle is on the
//        wire.
//
// The vuln-react sibling exercises 1 and 2 against script-src
// references to externally-served bundles. This container exercises 3
// - the fallback the check uses when the bundler renamed its output
// to a content-hashed chunk and the `.development.` path component is
// no longer on the wire. To prove the fallback works against real
// React, we inline the genuine dev-bundle source (preserving the
// dev-only symbol React itself emits) but strip the two places the
// filename literal would otherwise appear (the leading @license
// header and the trailing sourceMappingURL pragma), so the check
// cannot satisfy itself via path 1 or 2 first.
//
// The __REACT_DEVTOOLS_GLOBAL_HOOK__ reference embedded in the
// inlined source is what pins framework=react via the fingerprinter's
// react-devtools-hook rule, since there's no react-dom script-src
// for the bundle rule to match against.

const express = require("express");
const fs = require("fs");
const path = require("path");

// prepareBundleForInline removes the two places the React UMD source
// names its own file:
//   * the leading /** @license ... */ header block (where Facebook's
//     standard React license comment lists the source filename)
//   * the trailing //# sourceMappingURL=react-dom.development.js.map
//     pragma the bundler appends
// then escapes any "</script>" sequences (the bundle is valid JS that
// may contain such substrings in string literals; an unescaped one
// would prematurely close the inline <script> tag and corrupt the
// fixture). What's served to the wire is the real bundle body - the
// same JavaScript a browser would execute, minus only the two
// metadata strings whose presence in the seed HTML would otherwise
// let the check's primary filename pattern short-circuit before the
// banner fallback ever runs.
function prepareBundleForInline(source) {
  let body = source;
  body = body.replace(/^\s*\/\*\*[\s\S]*?\*\/\s*/, "");
  body = body.replace(/\/\/#\s*sourceMappingURL=[^\n]*\n?/g, "");
  body = body.replace(/<\/script>/gi, "<\\/script>");
  return body;
}

const reactDevSrc = prepareBundleForInline(
  fs.readFileSync(
    path.join(__dirname, "node_modules", "react", "umd", "react.development.js"),
    "utf8",
  ),
);
const reactDomDevSrc = prepareBundleForInline(
  fs.readFileSync(
    path.join(__dirname, "node_modules", "react-dom", "umd", "react-dom.development.js"),
    "utf8",
  ),
);

// Startup invariants. If a future React drop ever:
//   * sneaks the .development. filename into the bundle body outside
//     the two header/footer slots prepareBundleForInline scrubs, OR
//   * drops the ReactDebugCurrentFrame dev-only symbol the check's
//     DEV_MARKER fallback keys on,
// fail loudly here rather than silently degrading this fixture into a
// duplicate of vuln-react's filename-path coverage or a silently-
// skipped check.
const DEV_MARKER = "ReactDebugCurrentFrame";
for (const [label, body] of [
  ["react", reactDevSrc],
  ["react-dom", reactDomDevSrc],
]) {
  if (/\breact(?:-dom)?\.development\.js\b/.test(body)) {
    throw new Error(
      `${label} bundle still contains a .development.js filename literal after stripping; ` +
      `update prepareBundleForInline to cover the new occurrence so the fallback-marker ` +
      `detection path is the only signal left in the body.`,
    );
  }
}
if (!reactDomDevSrc.includes(DEV_MARKER)) {
  throw new Error(
    `react-dom dev bundle does not contain DEV_MARKER ${JSON.stringify(DEV_MARKER)}; ` +
    `the react-dev-build-in-prod check's fallback-marker detection path would have no ` +
    `signal to match. Either React removed the symbol (update the check + this fixture ` +
    `together) or the wrong bundle is being loaded.`,
  );
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vuln-react-inline</title>
</head>
<body>
<div id="root">vuln-react-inline demo</div>
<script>${reactDevSrc}</script>
<script>${reactDomDevSrc}</script>
</body>
</html>`;

// The fingerprinter and the check both cap body reads at 256 KiB
// (defaultMaxBodyBytes / body_caps.corpus). For this fixture to
// exercise the fallback-marker detection path, DEV_MARKER and
// __REACT_DEVTOOLS_GLOBAL_HOOK__ (the fingerprinter's framework=react
// signal) must BOTH fall within the first 256 KiB of the served
// HTML. React 18.3 places the first occurrence of each near the top
// of react-dom.development.js (~byte 8KB into the bundle, ~byte 60-70KB
// into the HTML once react.development.js precedes it), so today's
// version comfortably fits - but a future React rev that grows the
// bundle and pushes the symbols past the cap would silently turn
// this fixture into a no-signal HTML page. Fail loudly here instead.
const BODY_READ_CAP = 256 * 1024;
const FINGERPRINT_FRAMEWORK_MARKER = "__REACT_DEVTOOLS_GLOBAL_HOOK__";
for (const symbol of [DEV_MARKER, FINGERPRINT_FRAMEWORK_MARKER]) {
  const offset = html.indexOf(symbol);
  if (offset < 0 || offset >= BODY_READ_CAP) {
    throw new Error(
      `${symbol} is at byte offset ${offset} of the served HTML (cap ${BODY_READ_CAP}); ` +
      `the scanner would read past the cap before reaching it. Reorder the inlined ` +
      `bundles so react-dom comes first, or trim react.development.js, so both the ` +
      `framework fingerprint and the check's dev marker fall within the read window.`,
    );
  }
}

const app = express();

// Express defaults to X-Powered-By: Express on every response. The
// fingerprinter pins Framework=express on that header and the
// downstream body rule that would otherwise pick up React's devtools
// hook reference defers to the already-set framework. Disabling the
// header lets the react-devtools-hook body rule win, satisfying
// react-dev-build-in-prod's applies_to gate. See the matching
// rationale in vuln-react/server.js.
app.disable("x-powered-by");

app.get("/", (_req, res) => {
  res.type("html").send(html);
});

app.listen(8086, "0.0.0.0", () => {
  console.log("vuln-react-inline listening on :8086");
});
