// pages/index.js: public landing page. Pages Router automatically
// injects the __NEXT_DATA__ JSON blob into the rendered HTML, which
// the fingerprinter's next-data body rule matches to pin
// framework=nextjs - that's the gate the nextjs-middleware-bypass
// check's applies_to requires before its active probe runs.
export default function Home() {
  return (
    <main>
      <h1>vuln-nextjs</h1>
      <ul>
        <li>
          <a href="/dashboard">/dashboard (middleware-gated)</a>
        </li>
        <li>
          <a href="/login">/login (public)</a>
        </li>
      </ul>
    </main>
  );
}
