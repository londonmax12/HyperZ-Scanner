// pages/dashboard.js: the "protected" page. Without the bypass header
// the request is redirected by middleware.js before this handler ever
// runs (baseline 307 -> /login). With CVE-2025-29927's
// x-middleware-subrequest depth-saturation header, the runtime skips
// middleware entirely and this handler renders directly with HTTP
// 200, which is the status-class change the nextjs-middleware-bypass
// check uses as its load-bearing oracle.
export default function Dashboard() {
  return (
    <main>
      <h1>Dashboard</h1>
      <p>This page is protected by middleware.js.</p>
    </main>
  );
}
