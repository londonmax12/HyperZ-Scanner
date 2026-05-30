// vuln-react: serves an HTML page that loads the real React +
// ReactDOM development UMD bundles from the npm-installed packages.
// The page is the dev-build smoke test the react-dev-build-in-prod
// check targets:
//
//   * the body references react.development.js / react-dom.development.js
//     by name in <script src> attributes - which is the check's primary
//     script-src signal and the most common shape of the real-world
//     misconfiguration (a developer who left the dev CDN URL in
//     production, or a bundler set to NODE_ENV=development);
//   * the script-tag src context also pins framework=react via the
//     fingerprinter's react-dom-bundle rule, satisfying the check's
//     applies_to gate;
//   * GET /static/react-dom/react-dom.development.js actually returns
//     the genuine unminified UMD source - prepareScan asserts this on
//     test startup so the fixture cannot quietly rot into serving
//     stubs while the in-band string match keeps passing.
//
// The check itself only inspects the seed HTML body (it never fetches
// the bundles), so the in-band detection is purely body-pattern
// driven. The integrity assertion in integration_test.go's
// prepareScan is what proves this fixture is observationally
// indistinguishable from a real misconfigured production deployment.

const express = require("express");
const path = require("path");

const app = express();

// Express defaults to X-Powered-By: Express on every response. The
// fingerprinter's header rule pins Framework=express on that header,
// and once framework is non-empty the setReactIfUnknown branch in the
// react-dom-bundle body rule defers to it - so the seed page would
// fingerprint as express, applies_to = { framework = { react, nextjs
// } } on react-dev-build-in-prod would reject the host, and the check
// would never run. A real production React deployment also strips
// this header for the same fingerprinting / disclosure reason, so the
// fixture is more realistic with it off too.
app.disable("x-powered-by");

// express.static expects a directory root - mount the umd/ folders
// from each package and let the file-name segment of the URL resolve
// within them. The earlier shape (express.static of a single file
// path) silently 404'd; the script-tag references that follow would
// have been honored as far as HTML parsing goes, but a curl against
// the asset path returned nothing.
app.use(
  "/static/react",
  express.static(path.join(__dirname, "node_modules", "react", "umd")),
);
app.use(
  "/static/react-dom",
  express.static(path.join(__dirname, "node_modules", "react-dom", "umd")),
);

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vuln-react</title>
</head>
<body>
<div id="root">vuln-react demo</div>
<script crossorigin src="/static/react/react.development.js"></script>
<script crossorigin src="/static/react-dom/react-dom.development.js"></script>
</body>
</html>`);
});

app.listen(8083, "0.0.0.0", () => {
  console.log("vuln-react listening on :8083");
});
