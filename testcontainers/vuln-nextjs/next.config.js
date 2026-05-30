/** @type {import('next').NextConfig} */
module.exports = {
  // Strip X-Powered-By: Next.js. A security-conscious production
  // deployment hides framework versions, so the integration test
  // proves the fingerprinter still pins framework=nextjs from the
  // page-level __NEXT_DATA__ blob (and /_next/static/ asset refs)
  // alone - the load-bearing signals in real-world Next.js traffic.
  poweredByHeader: false,
  images: {
    // Wide-open remotePatterns - the canonical misconfiguration the
    // nextjs-image-ssrf check exists to flag. Any hostname matched by
    // "**" is allowed through Next.js's URL allow-list, so the
    // /_next/image optimizer fetches whatever URL the caller hands it
    // - including the scanner's OOB canary URL. With a properly
    // narrow allow-list (e.g. [{ hostname: "images.example.com" }])
    // the optimizer would reject the canary's hostname pre-fetch and
    // no callback would ever reach the listener.
    remotePatterns: [
      { protocol: "http", hostname: "**" },
      { protocol: "https", hostname: "**" },
    ],
    // dangerouslyAllowSVG keeps the optimizer in the most permissive
    // configuration - it doesn't change the SSRF surface (the fetch
    // happens regardless of content type) but mirrors the
    // worst-case real-world deployment.
    dangerouslyAllowSVG: true,
  },
};
