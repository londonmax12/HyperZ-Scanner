// vuln-ws: a minimal WebSocket endpoint that deliberately accepts
// any Origin and carries cookies/Authorization across the upgrade
// without re-checking. ws-audit looks for both behaviors.
//
// The /echo path is discovered by ws-audit either from a body
// reference (new WebSocket("ws://...:8081/echo")) on a crawled page,
// or by direct probe when the operator points the scanner at this
// container.

const http = require("http");
const { WebSocketServer } = require("ws");

const server = http.createServer((req, res) => {
  // A plain GET so the crawler can discover the host. Body references
  // the ws endpoint so ws-audit's URL extractor picks it up even when
  // this container is scanned standalone. The host is rewritten into
  // the literal so the regex-based discovery sees an absolute ws://
  // URL (host concatenation at runtime hides the URL from the static
  // scanner).
  const host = req.headers.host || "localhost:8081";
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(`<!doctype html>
<title>vuln-ws</title>
<script>
  var ws = new WebSocket("ws://${host}/echo");
</script>`);
});

const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws) => {
  ws.on("message", (msg) => ws.send("echo: " + msg.toString()));
  ws.send("welcome");
});

server.on("upgrade", (req, socket, head) => {
  if (req.url !== "/echo") {
    socket.destroy();
    return;
  }
  // Deliberately no Origin allowlist - that's the ws-audit bug.
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
});

server.listen(8081, "0.0.0.0", () => {
  console.log("vuln-ws listening on :8081");
});
