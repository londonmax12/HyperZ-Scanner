// pages/login.js: redirect destination for the middleware bounce. The
// middleware-bypass check fetches with follow_redirects=false so the
// /login body itself is never read; this page just needs to exist so
// the redirect target is a real route in production traffic.
export default function Login() {
  return (
    <main>
      <h1>Login</h1>
      <p>Please log in to continue.</p>
    </main>
  );
}
