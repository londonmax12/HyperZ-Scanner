package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// SubdomainTakeover flags hostnames whose DNS still points at a third-party
// SaaS provider that no longer claims them: the CNAME resolves to a known
// service domain (GitHub Pages, S3, Heroku, Azure, Fastly, ...) and the
// provider's edge returns its canonical "this resource is unclaimed" page.
// When both halves line up an attacker can register the freed-up resource
// on their own account and host arbitrary content on the original
// hostname; from there they get session cookies scoped to the parent
// domain, valid TLS for the subdomain, and a phishing surface that
// inherits whatever trust the parent brand carries.
//
// Detection chains two signals so the check stays high-confidence:
//
//  1. The hostname resolves via CNAME to a domain matching one of the
//     known providers in subdomainTakeoverProviders. A hostname that
//     IS the provider domain (e.g. user.github.io itself being scanned)
//     is skipped: there is no dangling CNAME there, the page is served
//     directly from the canonical address.
//
//  2. Issuing a fresh GET against the hostname's root returns the
//     provider's "claim this" fingerprint (status code + body
//     substring). A working, claimed deployment never matches; only
//     the unclaimed edge response does. NXDOMAIN on the CNAME target
//     itself also counts as confirmation - the underlying resource is
//     gone, which is the same condition the fingerprint detects.
//
// Severity is High when both halves confirm: a successful takeover is
// trivial-to-exploit and the impact (cookie theft on the parent
// domain, valid-cert phishing, brand abuse) is substantial. Findings
// dedupe per host so a 50-page crawl of one vulnerable subdomain
// produces one finding, not 50. Probing is cached per hostname for
// the lifetime of the scan to keep DNS and probe traffic bounded
// regardless of how many crawled pages share a host.
type SubdomainTakeover struct {
	once  sync.Once
	mu    sync.Mutex
	cache map[string]subdomainTakeoverCacheEntry
}

func (c *SubdomainTakeover) Name() string { return "subdomain-takeover" }

func (c *SubdomainTakeover) Level() Level { return LevelPassive }

// subdomainTakeoverCacheEntry memoizes the per-host result so each
// hostname is resolved + probed once per scan, no matter how many
// crawled pages share it. A nil finding pointer represents a confirmed
// non-vulnerable host (skip without re-probing); a non-nil pointer is
// re-emitted with the new page URL attached.
type subdomainTakeoverCacheEntry struct {
	finding *Finding
}

// takeoverProvider describes one SaaS edge that can be probed for an
// unclaimed-resource response. cnameSuffixes are matched as
// case-insensitive trailing-domain suffixes against the CNAME chain;
// fingerprints are case-sensitive substrings searched in the response
// body returned by the provider's edge; statuses, when non-empty,
// restricts matching to the listed HTTP status codes (most providers
// answer 404, S3 answers 404 with NoSuchBucket, Fastly answers 500
// when the host is unknown, etc.).
//
// headerFingerprints are provider-identifying response headers (Server,
// Via, X-Served-By, etc.) that pin the response to a specific SaaS
// edge regardless of how DNS got there. They power the fingerprint-only
// detection path: when DNS does not surface a known CNAME (CDN proxy
// in front, A record straight to a provider IP, third-party DNS that
// hides the chain), a body fingerprint alone is too weak to fire on,
// but body+header together is high-confidence proof the request reached
// the provider's edge and the edge is serving its claim-this page.
//
// guidance describes the takeover path the provider exposes so the
// remediation can be specific.
type takeoverProvider struct {
	name               string
	cnameSuffixes      []string
	fingerprints       []string
	headerFingerprints []headerFingerprint
	statuses           []int
	guidance           string
}

// headerFingerprint matches one response header that identifies the
// provider's edge. name is the header to read (case-insensitive). value
// is a substring matched case-insensitively against the header value;
// an empty value means "header must be present with any non-empty
// value", which is the right shape for headers whose mere presence is
// the signal (x-amz-request-id, x-shopid) regardless of the opaque
// value the edge fills in.
type headerFingerprint struct {
	name  string
	value string
}

// Curated provider list. Each entry pairs a CNAME suffix (or family of
// suffixes) with the unmistakable "unclaimed" response that provider's
// edge serves. The list is deliberately conservative: every entry's
// fingerprint is one a working deployment cannot produce, so the
// false-positive rate stays near zero. Add new providers by following
// the same shape - CNAME suffix(es) + a fingerprint that only the
// edge's claim-this page emits.
var subdomainTakeoverProviders = []takeoverProvider{
	{
		name:          "GitHub Pages",
		cnameSuffixes: []string{".github.io"},
		fingerprints: []string{
			"There isn't a GitHub Pages site here.",
			"For root URLs (like http://example.com/) you must provide an A record",
		},
		// GitHub Pages serves through its own fronting layer that
		// stamps "GitHub.com" in Server on the claim-this 404. A
		// healthy Pages site also carries this header, so it only
		// becomes a takeover signal when combined with the body
		// fingerprint above.
		headerFingerprints: []headerFingerprint{
			{name: "Server", value: "GitHub.com"},
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Register the GitHub Pages site under the GitHub account you control (or remove the CNAME if Pages is no longer in use).",
	},
	{
		name: "AWS S3",
		cnameSuffixes: []string{
			".s3.amazonaws.com",
			".s3-website.amazonaws.com",
			".s3-website-us-east-1.amazonaws.com",
			".s3-website-us-east-2.amazonaws.com",
			".s3-website-us-west-1.amazonaws.com",
			".s3-website-us-west-2.amazonaws.com",
			".s3-website-eu-west-1.amazonaws.com",
			".s3-website-eu-central-1.amazonaws.com",
			".s3-website-ap-south-1.amazonaws.com",
			".s3-website-ap-southeast-1.amazonaws.com",
			".s3-website-ap-southeast-2.amazonaws.com",
			".s3-website-ap-northeast-1.amazonaws.com",
			".s3-website-sa-east-1.amazonaws.com",
		},
		fingerprints: []string{
			"<Code>NoSuchBucket</Code>",
			"The specified bucket does not exist",
		},
		// S3's edge always stamps these on every response, claimed or
		// not - the body fingerprint is what flags "unclaimed". The
		// pair is essentially "the request reached S3" + "S3 has no
		// bucket of this name".
		headerFingerprints: []headerFingerprint{
			{name: "Server", value: "AmazonS3"},
			{name: "x-amz-request-id"},
			{name: "x-amz-id-2"},
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Create an S3 bucket with the exact name the hostname expects in the AWS account you control, or remove the CNAME if the bucket is no longer in use.",
	},
	{
		name:          "Heroku",
		cnameSuffixes: []string{".herokuapp.com", ".herokudns.com"},
		fingerprints: []string{
			"No such app",
			"There's nothing here, yet.",
			"no-such-app.html",
		},
		// Heroku's router stamps "1.1 vegur" in Via on every response
		// it proxies (vegur is the router's name); the Cowboy server
		// header is what the dyno layer historically emits. Either is
		// a strong signal the response came through Heroku's edge.
		headerFingerprints: []headerFingerprint{
			{name: "Via", value: "vegur"},
			{name: "Server", value: "Cowboy"},
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Re-create the Heroku app with the same name under the account you control, or remove the CNAME if the app has been retired.",
	},
	{
		name: "Microsoft Azure",
		cnameSuffixes: []string{
			".azurewebsites.net",
			".cloudapp.net",
			".cloudapp.azure.com",
			".trafficmanager.net",
			".blob.core.windows.net",
			".azure-api.net",
			".azureedge.net",
		},
		fingerprints: []string{
			"404 Web Site not found.",
			"Our services aren't available right now",
		},
		// Azure App Service / IIS edge identifiers. The 404 page comes
		// straight from the IIS layer, so "Microsoft-IIS" in Server
		// pairs cleanly with the body fingerprint. Azure-specific
		// custom headers (x-ms-*) are also unmistakable.
		headerFingerprints: []headerFingerprint{
			{name: "Server", value: "Microsoft-IIS"},
			{name: "Server", value: "Microsoft-Azure"},
			{name: "x-ms-request-id"},
			{name: "x-powered-by", value: "ASP.NET"},
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Re-deploy the Azure resource with the exact name the hostname expects, or remove the CNAME if the service has been decommissioned.",
	},
	{
		name:          "Fastly",
		cnameSuffixes: []string{".fastly.net"},
		fingerprints: []string{
			"Fastly error: unknown domain",
		},
		// X-Served-By: cache-<pop> and the Fastly Via signature are the
		// canonical edge markers. A bare "Varnish" Server header on its
		// own is too generic - Varnish runs in many places - so we key
		// on the headers Fastly's edge actually stamps.
		headerFingerprints: []headerFingerprint{
			{name: "X-Served-By", value: "cache-"},
			{name: "Via", value: "varnish"},
			{name: "X-Cache", value: "HIT"},
			{name: "X-Timer"},
		},
		// Fastly's "unknown domain" message ships on 500 status when the
		// edge has no service mapped to the hostname; some configurations
		// can also surface it on 404 depending on routing.
		statuses: []int{http.StatusInternalServerError, http.StatusNotFound},
		guidance: "Attach the hostname to a Fastly service under the account you control, or remove the CNAME if the property no longer uses Fastly.",
	},
	{
		name:          "Shopify",
		cnameSuffixes: []string{".myshopify.com"},
		fingerprints: []string{
			"Sorry, this shop is currently unavailable.",
		},
		// Shopify stamps its custom headers on every storefront response,
		// claimed or not. Pairing one of these with the body fingerprint
		// is "the request reached Shopify" + "Shopify has no shop here".
		headerFingerprints: []headerFingerprint{
			{name: "x-shopid"},
			{name: "x-shopify-stage"},
			{name: "Server", value: "ShopifyCloud"},
		},
		guidance: "Attach the hostname to the Shopify store under the account you control, or remove the CNAME if the store has been closed.",
	},
	{
		name:          "Pantheon",
		cnameSuffixes: []string{".pantheonsite.io"},
		fingerprints: []string{
			"The gods are wise, but do not know of the site which you seek.",
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Add the custom domain to the Pantheon site under the account you control, or remove the CNAME.",
	},
	{
		name:          "Tumblr",
		cnameSuffixes: []string{"domains.tumblr.com"},
		fingerprints: []string{
			"Whatever you were looking for doesn't currently exist at this address.",
		},
		guidance: "Re-claim the custom domain in Tumblr blog settings under the account you control, or remove the CNAME.",
	},
	{
		name:          "Unbounce",
		cnameSuffixes: []string{".unbouncepages.com"},
		fingerprints: []string{
			"The requested URL was not found on this server.",
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Republish or reattach the landing page in Unbounce under the account you control, or remove the CNAME.",
	},
	{
		name:          "Surge.sh",
		cnameSuffixes: []string{".surge.sh"},
		fingerprints: []string{
			"project not found",
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Re-deploy the Surge project with the matching domain under the account you control, or remove the CNAME.",
	},
	{
		name:          "Bitbucket",
		cnameSuffixes: []string{".bitbucket.io"},
		fingerprints: []string{
			"Repository not found",
		},
		statuses: []int{http.StatusNotFound},
		guidance: "Re-create the Bitbucket Pages repository with the matching name under the workspace you control, or remove the CNAME.",
	},
	{
		name:          "Helpjuice",
		cnameSuffixes: []string{".helpjuice.com"},
		fingerprints: []string{
			"We could not find what you're looking for.",
		},
		guidance: "Re-add the custom domain in Helpjuice under the account you control, or remove the CNAME.",
	},
	{
		name:          "Readme.io",
		cnameSuffixes: []string{".readme.io"},
		fingerprints: []string{
			"Project doesnt exist... yet!",
		},
		guidance: "Re-attach the hostname to the Readme project under the account you control, or remove the CNAME.",
	},
	{
		name:          "HelpScout",
		cnameSuffixes: []string{".helpscoutdocs.com"},
		fingerprints: []string{
			"No settings were found for this company",
		},
		guidance: "Re-attach the custom domain in HelpScout under the account you control, or remove the CNAME.",
	},
}

const (
	// subdomainTakeoverBodyCap bounds the body the check reads from the
	// provider edge. Every fingerprint we look for is a short, fixed
	// string that lands well within the first response chunk; 64 KiB
	// clears even the long-form Pantheon / HelpScout messages without
	// letting a misbehaving edge pin the worker on a slow stream.
	subdomainTakeoverBodyCap = 64 << 10
)

// subdomainTakeoverLookupCNAME is indirected so tests can inject a
// deterministic resolver response without touching the host network.
// In production it delegates to the default resolver, which honors ctx
// cancellation. A name with no CNAME record returns the original name
// with a trailing dot; callers normalize before comparing.
var subdomainTakeoverLookupCNAME = func(ctx context.Context, host string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, host)
}

// subdomainTakeoverLookupHost is indirected so tests can simulate
// NXDOMAIN on the CNAME target (an explicit takeover sign for some
// providers - the freed-up resource is gone, the DNS edge serves
// nothing) without depending on the host resolver's view of the world.
var subdomainTakeoverLookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (c *SubdomainTakeover) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	c.once.Do(func() {
		c.cache = map[string]subdomainTakeoverCacheEntry{}
	})

	u, err := url.Parse(p.URL)
	if err != nil || u.Host == "" {
		return nil, nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, nil
	}
	// IP literals cannot meaningfully CNAME to a SaaS edge. They naturally
	// fall out via the "cname equals host" short-circuit downstream, but
	// only when there is no CNAME record - we still let the lookup run so
	// tests can drive synthetic CNAMEs against a local edge bound to
	// 127.0.0.1.
	// A scan targeted directly at the provider's canonical address has
	// no dangling CNAME to inspect - the host IS the provider domain.
	// Skip without probing so we do not noise-flag legitimate hosting.
	if matchProviderByHost(host) != nil {
		return nil, nil
	}

	// Per-host cache short-circuits repeat work across every crawled
	// page on the same hostname. A nil finding entry is a confirmed
	// negative; re-emit a confirmed positive with the current page URL
	// so the report ties the finding to the URL the user actually saw.
	c.mu.Lock()
	entry, cached := c.cache[host]
	c.mu.Unlock()
	if cached {
		if entry.finding == nil {
			return nil, nil
		}
		f := *entry.finding
		f.Target = p.URL
		f.URL = p.URL
		return []Finding{f}, nil
	}

	finding, err := c.evaluateHost(ctx, client, sc, u, host)
	c.mu.Lock()
	c.cache[host] = subdomainTakeoverCacheEntry{finding: finding}
	c.mu.Unlock()
	if err != nil {
		// A DNS or probe error against one host should not fail the scan -
		// leave a breadcrumb and move on so a flaky resolver does not
		// blank the whole report.
		Report(ctx, fmt.Errorf("subdomain-takeover %s: %w", host, err))
		return nil, nil
	}
	if finding == nil {
		return nil, nil
	}
	f := *finding
	f.Target = p.URL
	f.URL = p.URL
	return []Finding{f}, nil
}

// evaluateHost runs the two-stage check for one hostname. The CNAME-
// gated path runs first - it carries the strongest evidence (a dangling
// DNS chain we can name end-to-end). When DNS does not surface a known
// provider (CDN proxy in front, A record straight to a provider IP,
// third-party DNS that hides the chain), the fingerprint-only path
// fires off one probe and looks for a provider's body+header pair in
// the response. A nil finding return means "not vulnerable" and is
// cached as such.
func (c *SubdomainTakeover) evaluateHost(ctx context.Context, client *httpclient.Client, sc *scope.Scope, u *url.URL, host string) (*Finding, error) {
	finding, err := c.evaluateViaDNS(ctx, client, sc, u, host)
	if err != nil {
		return nil, err
	}
	if finding != nil {
		return finding, nil
	}
	return c.evaluateViaFingerprint(ctx, client, sc, u)
}

// evaluateViaDNS is the original two-signal check: CNAME match + body
// fingerprint. Returns nil/nil when DNS does not point at a known
// provider so the caller can fall back to the fingerprint-only path.
func (c *SubdomainTakeover) evaluateViaDNS(ctx context.Context, client *httpclient.Client, sc *scope.Scope, u *url.URL, host string) (*Finding, error) {
	cname, err := subdomainTakeoverLookupCNAME(ctx, host)
	if err != nil {
		// A LookupCNAME failure is not by itself a takeover signal: many
		// hostnames legitimately have no CNAME and just an A record. Let
		// the fingerprint-only path decide.
		return nil, nil
	}
	cnameNormalized := strings.TrimSuffix(strings.ToLower(cname), ".")
	// No CNAME record at all: LookupCNAME returns the input itself.
	if cnameNormalized == "" || cnameNormalized == host {
		return nil, nil
	}
	provider := matchProvider(cnameNormalized)
	if provider == nil {
		return nil, nil
	}

	probeURL, ok := c.buildProbeURL(sc, u)
	if !ok {
		return nil, nil
	}

	// NXDOMAIN on the CNAME target is itself proof: the upstream
	// resource has been released and the provider edge no longer serves
	// anything at that name. The fingerprint probe would just return a
	// connection / resolution error in that case.
	if _, hostErr := subdomainTakeoverLookupHost(ctx, cnameNormalized); hostErr != nil {
		if isDNSNotFound(hostErr) {
			return c.buildDNSFinding(probeURL, provider, cnameNormalized, 0, "", "CNAME target resolves to NXDOMAIN; the upstream resource has been released."), nil
		}
		// Other lookup errors (transient) leave the question open; the
		// edge probe below decides.
	}

	status, _, body, probeErr := c.fetchProbe(ctx, client, sc, probeURL)
	if probeErr != nil {
		return nil, probeErr
	}
	if status == 0 || !matchesFingerprint(status, body, provider) {
		return nil, nil
	}
	return c.buildDNSFinding(probeURL, provider, cnameNormalized, status, string(body), ""), nil
}

// evaluateViaFingerprint is the DNS-blind path: probe the host root
// once and walk every provider, requiring both the body fingerprint
// (the "claim-this" message) AND a provider-identifying header
// (Server, Via, x-amz-*, etc.). Body alone is too weak without DNS
// confirmation - a benign mirror could echo the same string - but
// body+header together pins the response to the actual SaaS edge.
//
// Severity is Medium for these findings: without the CNAME chain we
// can name, the resource may be fronted by a proxy / CDN that limits
// trivial claimability, so the operator should verify the DNS
// configuration before treating this as a guaranteed takeover.
func (c *SubdomainTakeover) evaluateViaFingerprint(ctx context.Context, client *httpclient.Client, sc *scope.Scope, u *url.URL) (*Finding, error) {
	probeURL, ok := c.buildProbeURL(sc, u)
	if !ok {
		return nil, nil
	}
	status, headers, body, err := c.fetchProbe(ctx, client, sc, probeURL)
	if err != nil {
		return nil, err
	}
	if status == 0 {
		return nil, nil
	}
	for i := range subdomainTakeoverProviders {
		p := &subdomainTakeoverProviders[i]
		if matchesProviderEdge(status, headers, body, p) {
			return c.buildFingerprintFinding(probeURL, p, status, headers, string(body)), nil
		}
	}
	return nil, nil
}

// buildProbeURL returns the host root URL and a "in scope" flag.
// Probing the root rather than p.URL means a deep-link in the crawl
// still surfaces the edge's claim-this fingerprint, which providers
// serve uniformly regardless of path. A nil scope is permissive.
func (c *SubdomainTakeover) buildProbeURL(sc *scope.Scope, u *url.URL) (string, bool) {
	probeURL := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}).String()
	if sc != nil {
		pu, perr := url.Parse(probeURL)
		if perr != nil || !sc.Allows(pu) {
			return "", false
		}
	}
	return probeURL, true
}

// matchProvider returns the provider whose CNAME suffix list contains
// cname, or nil if none match. Matching is case-insensitive and treats
// each suffix as a trailing-domain match so e.g. ".github.io" matches
// "user.github.io" but not "imitatorgithub.io".
func matchProvider(cname string) *takeoverProvider {
	cname = strings.ToLower(cname)
	for i := range subdomainTakeoverProviders {
		p := &subdomainTakeoverProviders[i]
		for _, suf := range p.cnameSuffixes {
			s := strings.ToLower(suf)
			if strings.HasPrefix(s, ".") {
				// Leading dot: domain-suffix match so ".github.io" hits
				// "user.github.io" but not "imitatorgithub.io".
				if strings.HasSuffix(cname, s) {
					return p
				}
				continue
			}
			// No leading dot: exact-host entry (e.g. "domains.tumblr.com").
			// A plain HasSuffix would let "notdomains.tumblr.com" bleed in,
			// so gate these on exact equality only.
			if cname == s {
				return p
			}
		}
	}
	return nil
}

// matchProviderByHost is matchProvider applied to the scan target itself
// so we can skip hosts that ARE the provider canonical name (e.g.
// `username.github.io` directly). The same suffix table feeds both
// matchers to keep the two views consistent.
func matchProviderByHost(host string) *takeoverProvider {
	return matchProvider(host)
}

// fetchProbe issues one GET against the provider edge and returns the
// raw observation: status, headers, body. Both detection paths share
// this so the host root is probed at most once per hostname per scan.
// status == 0 means "skipped" (transport error or out-of-scope) and is
// the signal callers use to bail without firing.
//
// A connection error is consistent with the upstream resource being
// released, but firing on it alone would noise-flag flaky networks, so
// we report it as a silent skip rather than as confirmation.
func (c *SubdomainTakeover) fetchProbe(ctx context.Context, client *httpclient.Client, sc *scope.Scope, probeURL string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return 0, nil, nil, nil
	}
	defer resp.Body.Close()
	if sc != nil && resp.Request != nil && resp.Request.URL != nil && !sc.Allows(resp.Request.URL) {
		return 0, nil, nil, nil
	}
	body, err := httpclient.ReadBody(resp, subdomainTakeoverBodyCap)
	if err != nil {
		return resp.StatusCode, resp.Header.Clone(), nil, err
	}
	return resp.StatusCode, resp.Header.Clone(), body, nil
}

// matchesFingerprint reports whether status + body together satisfy
// the provider's claim-this signature. statuses on a provider entry
// is advisory: when set, the response status must be in the list; when
// empty, any status passes the gate. The body match is mandatory and
// uses case-sensitive substring search to keep each fingerprint
// unambiguous.
//
// This is the matcher the CNAME-gated path uses; the CNAME match
// already supplies the "this is the provider's edge" half of the
// evidence, so body alone is enough to confirm. The DNS-blind
// fingerprint path uses matchesProviderEdge instead, which requires
// an additional response-header match to compensate for the missing
// CNAME signal.
func matchesFingerprint(status int, body []byte, provider *takeoverProvider) bool {
	if len(provider.statuses) > 0 {
		ok := false
		for _, s := range provider.statuses {
			if s == status {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, fp := range provider.fingerprints {
		if bytesContainsString(body, fp) {
			return true
		}
	}
	return false
}

// matchesProviderEdge is the stricter, DNS-blind matcher. It requires
// every gate to pass: status (when restricted), a body fingerprint,
// AND at least one provider-identifying header. A provider with no
// headerFingerprints declared cannot match through this path - body
// alone is too weak without DNS confirmation, so we deliberately do
// not fall through to body-only.
func matchesProviderEdge(status int, headers http.Header, body []byte, provider *takeoverProvider) bool {
	if len(provider.headerFingerprints) == 0 {
		return false
	}
	if !matchesFingerprint(status, body, provider) {
		return false
	}
	for _, hf := range provider.headerFingerprints {
		if matchesHeaderFingerprint(headers, hf) {
			return true
		}
	}
	return false
}

// matchesHeaderFingerprint reports whether headers contains a value
// for hf.name that satisfies hf.value. The header lookup is case-
// insensitive (http.Header handles this) and the value match is a
// case-insensitive substring search. An empty hf.value means "header
// must be present with any non-empty value", which is the right shape
// for opaque identifiers like x-amz-request-id whose mere presence is
// the signal.
func matchesHeaderFingerprint(headers http.Header, hf headerFingerprint) bool {
	if headers == nil || hf.name == "" {
		return false
	}
	values := headers.Values(hf.name)
	if len(values) == 0 {
		return false
	}
	if hf.value == "" {
		for _, v := range values {
			if strings.TrimSpace(v) != "" {
				return true
			}
		}
		return false
	}
	needle := strings.ToLower(hf.value)
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

// bytesContainsString is a tiny helper to keep the call sites tidy
// without importing bytes just for one substring search.
func bytesContainsString(haystack []byte, needle string) bool {
	return strings.Contains(string(haystack), needle)
}

// isDNSNotFound reports whether err is the resolver's NXDOMAIN signal.
// net.DNSError carries IsNotFound (Go 1.13+); other errors (transient
// network failures, refused queries) are not the takeover signal we
// want to fire on.
func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// buildDNSFinding emits a finding for the CNAME-confirmed path. The
// CNAME chain we can name end-to-end gives unambiguous proof the
// hostname is delegated to the provider, so severity is High.
func (c *SubdomainTakeover) buildDNSFinding(probeURL string, provider *takeoverProvider, cname string, status int, bodyPreview, dnsNote string) *Finding {
	var detailLines []string
	detailLines = append(detailLines, fmt.Sprintf("Hostname resolves via CNAME to %q, which matches %s's edge.", cname, provider.name))
	if dnsNote != "" {
		detailLines = append(detailLines, dnsNote)
	}
	if status != 0 {
		detailLines = append(detailLines, fmt.Sprintf("The %s edge responded with status %d and the provider's canonical \"unclaimed resource\" fingerprint.", provider.name, status))
	}
	detailLines = append(detailLines, "An attacker who registers the freed-up resource on their own account will host arbitrary content at this hostname, with valid TLS and any cookies the parent domain scopes to it.")

	preview := bodyPreview
	const previewCap = 512
	if len(preview) > previewCap {
		preview = preview[:previewCap] + "..."
	}

	headers := http.Header{}
	if status != 0 {
		headers.Set("X-Subdomain-Takeover-Provider", provider.name)
		headers.Set("X-Subdomain-Takeover-CNAME", cname)
	}

	return &Finding{
		Check:    "subdomain-takeover",
		Target:   probeURL,
		URL:      probeURL,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("subdomain takeover via dangling %s CNAME", provider.name),
		Detail:   fmt.Sprintf("Hostname's DNS still points at %s but the upstream resource is unclaimed; the edge serves its canonical \"this resource does not exist\" page. Each entry below explains the evidence.", provider.name),
		Details:  detailLines,
		CWE:      "CWE-1104",
		OWASP:    "A05:2021 Security Misconfiguration",
		Remediation: provider.guidance + " " +
			"Before remediating, audit cookies scoped to the parent domain (Domain=.example.com) and any OAuth / SSO callbacks that trust the hostname - a successful takeover would have inherited both. " +
			"As a longer-term control, gate DNS record creation on proof of upstream ownership and add periodic checks (or a SIEM rule) that re-resolves CNAMEs and probes the listed providers for unclaimed-resource fingerprints.",
		Evidence:  BuildEvidence("GET", probeURL, status, headers, preview),
		DedupeKey: MakeKey("subdomain-takeover", ScopeHost, probeURL, "cname:"+cname, "provider:"+provider.name),
	}
}

// buildFingerprintFinding emits a finding for the DNS-blind path: body
// fingerprint AND a provider-identifying header both matched but the
// CNAME chain we resolved did not pin the hostname to the provider.
// Severity is Medium: the provider's edge is clearly serving the
// unclaimed page (otherwise we would not have matched), but without
// the DNS chain we cannot tell whether the resource is fronted by a
// proxy/CDN that limits trivial claimability, so the operator should
// verify the DNS configuration before treating it as a guaranteed
// takeover.
func (c *SubdomainTakeover) buildFingerprintFinding(probeURL string, provider *takeoverProvider, status int, headers http.Header, bodyPreview string) *Finding {
	matchedHeaders := matchedHeaderSummary(headers, provider)
	detailLines := []string{
		fmt.Sprintf("The edge at this hostname responded with status %d, the canonical %s \"unclaimed resource\" body, and the provider-identifying response header(s) %s.", status, provider.name, matchedHeaders),
		"DNS does not surface a CNAME to this provider, so the chain is either A-recorded straight at the provider, fronted by a CDN/proxy that hides the upstream, or served through a third-party DNS that flattens it. Either way, the public-facing edge is the provider's and the upstream resource is unclaimed.",
		"Verify who controls the DNS record and whether the upstream resource can be claimed under the provider's account model; if so, an attacker can host arbitrary content at this hostname with valid TLS and inherit cookies the parent domain scopes to it.",
	}

	preview := bodyPreview
	const previewCap = 512
	if len(preview) > previewCap {
		preview = preview[:previewCap] + "..."
	}

	evidenceHeaders := http.Header{}
	evidenceHeaders.Set("X-Subdomain-Takeover-Provider", provider.name)
	evidenceHeaders.Set("X-Subdomain-Takeover-Detection", "response-fingerprint")
	for _, hf := range provider.headerFingerprints {
		for _, v := range headers.Values(hf.name) {
			evidenceHeaders.Add(hf.name, v)
		}
	}

	return &Finding{
		Check:    "subdomain-takeover",
		Target:   probeURL,
		URL:      probeURL,
		Severity: SeverityMedium,
		Title:    fmt.Sprintf("possible subdomain takeover: %s edge serves unclaimed-resource page", provider.name),
		Detail:   fmt.Sprintf("The hostname's edge response identifies it as %s and matches the provider's canonical \"unclaimed resource\" page, but DNS does not surface a CNAME to this provider. Each entry below explains the evidence.", provider.name),
		Details:  detailLines,
		CWE:      "CWE-1104",
		OWASP:    "A05:2021 Security Misconfiguration",
		Remediation: provider.guidance + " " +
			"Confirm the hostname's DNS chain (CNAME, A, fronting proxies) before treating this as exploitable - the edge response alone proves the upstream is unclaimed, but a fronting proxy may limit claimability. " +
			"As a longer-term control, gate DNS record creation on proof of upstream ownership and add periodic checks that probe known SaaS edges for unclaimed-resource fingerprints regardless of DNS shape.",
		Evidence:  BuildEvidence("GET", probeURL, status, evidenceHeaders, preview),
		DedupeKey: MakeKey("subdomain-takeover", ScopeHost, probeURL, "fingerprint", "provider:"+provider.name),
	}
}

// matchedHeaderSummary renders the provider-identifying headers that
// were present on the response into a human-readable list, for the
// finding's Details. Keeps the rendering deterministic by iterating
// over the provider's declared headerFingerprints in order.
func matchedHeaderSummary(headers http.Header, provider *takeoverProvider) string {
	var summaries []string
	renderedHeader := map[string]bool{}
	for _, fingerprint := range provider.headerFingerprints {
		if !matchesHeaderFingerprint(headers, fingerprint) {
			continue
		}
		// Render once per header name even if the provider declared
		// multiple value variants on the same header.
		canonicalName := http.CanonicalHeaderKey(fingerprint.name)
		if renderedHeader[canonicalName] {
			continue
		}
		renderedHeader[canonicalName] = true
		values := headers.Values(fingerprint.name)
		if len(values) == 0 {
			continue
		}
		const headerValueCap = 80
		headerValue := values[0]
		if len(headerValue) > headerValueCap {
			headerValue = headerValue[:headerValueCap] + "..."
		}
		summaries = append(summaries, fmt.Sprintf("%s: %s", canonicalName, headerValue))
	}
	if len(summaries) == 0 {
		return "(none captured)"
	}
	return strings.Join(summaries, "; ")
}
