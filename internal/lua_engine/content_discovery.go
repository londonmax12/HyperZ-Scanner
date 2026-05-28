package lua_engine

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// contentDiscoveryBodyCap bounds how much body we read per probe.
	// All markers ride near the top of the file (.git/HEAD is <50
	// bytes; .env rarely exceeds a few KiB), and we never need to read
	// the disclosed file in full to confirm its presence. 16 KiB also
	// keeps the SHA1 fingerprint bounded so a single bad URL streaming
	// a 10 MB response can't pin a worker slot.
	contentDiscoveryBodyCap = 16 << 10

	// contentDiscoveryBaselineProbes is how many random-canary paths we
	// send to learn the host's missing-resource signature. Two probes
	// are enough to fingerprint a deterministic soft-404: matching
	// status+hash across both confirms the response is catch-all-shaped
	// rather than coincidentally aligned with one entry.
	contentDiscoveryBaselineProbes = 2

	// contentDiscoveryLenSlack is the absolute byte slack we allow when
	// comparing a candidate body length to the baseline. Without a
	// floor, a tiny baseline (100 bytes) wouldn't tolerate any drift
	// at all and a single byte of timestamp jitter would look like a
	// real hit.
	contentDiscoveryLenSlack = 64

	// contentDiscoveryLenRelSlack is the relative tolerance applied on
	// top of the absolute floor. 5% catches typical SPA shells that
	// inject a request ID without inflating false positives on pages
	// that genuinely changed shape.
	contentDiscoveryLenRelSlack = 0.05
)

// hostBackupEntries synthesizes the host-named backup probes a sweep
// should always try at the document root: /<host>.zip, /<host>.sql,
// /<host>.tar.gz, /<host>.bak, plus the bare-label variants
// (example.com -> example) when a label sits before the first dot.
// Backups named after the deployed site are common enough that bolting
// them onto every sweep costs little and routinely catches misplaced
// archives.
//
// Every synthetic carries an ExpectedContentTypes filter so a soft-200
// HTML wrapper served for an unknown extension can't fire the check.
func hostBackupEntries(rawHost string) []discoveryEntry {
	host := strings.ToLower(strings.TrimSpace(rawHost))
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return nil
	}
	// Preserve insertion order so the probe sequence is deterministic
	// across runs; map-only would randomize it.
	var names []string
	seen := map[string]struct{}{}
	add := func(n string) {
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	add(host)
	if dot := strings.IndexByte(host, '.'); dot > 0 {
		add(host[:dot])
	}

	type ext struct {
		suffix string
		cts    []string
	}
	exts := []ext{
		{".zip", []string{"application/zip", "application/x-zip-compressed", "application/octet-stream"}},
		{".tar.gz", []string{"application/gzip", "application/x-gzip", "application/x-tar", "application/octet-stream"}},
		{".sql", []string{"text/plain", "application/sql", "application/x-sql", "application/octet-stream"}},
		{".bak", []string{"application/octet-stream", "text/plain"}},
	}
	out := make([]discoveryEntry, 0, len(names)*len(exts))
	for _, n := range names {
		for _, e := range exts {
			out = append(out, discoveryEntry{
				Path:                 "/" + n + e.suffix,
				Severity:             SeverityCritical,
				Title:                fmt.Sprintf("host-named backup reachable (%s%s)", n, e.suffix),
				Detail:               "A backup or archive named after the target host is served at the document root; these typically contain the full site source or database contents.",
				CWE:                  "CWE-538",
				OWASP:                "A05:2021 Security Misconfiguration",
				Remediation:          "Store backups outside the document root and rotate any credentials present in the archive.",
				ExpectedContentTypes: e.cts,
			})
		}
	}
	return out
}

// bodyHashPrefix returns the leading 16 hex chars of a SHA1 over body.
// 64 bits of fingerprint is enough to make accidental collisions
// astronomically unlikely across a per-host probe sweep, while keeping
// the value short enough to be readable in evidence if we ever surface
// it. SHA1's collision weakness is irrelevant - there is no adversary
// choosing the body content of /etc/passwd to collide with an SPA's
// catch-all hash.
func bodyHashPrefix(body []byte) string {
	h := sha1.Sum(body)
	return hex.EncodeToString(h[:8])
}

// contentTypeFamily strips parameters from a media type, returning the
// bare "type/subtype" in lowercase. text/html;charset=utf-8 collapses
// to text/html so a charset reshuffle doesn't make a catch-all look
// content-type-distinct.
func contentTypeFamily(ct string) string {
	ct = strings.ToLower(ct)
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

// contentTypeFamilyAllowed reports whether a response's content-type is
// permitted under entry.ExpectedContentTypes. An empty allow list means
// "no constraint" (the entry never asked). An empty/missing CT header
// is treated as permissive - some servers genuinely omit Content-Type
// on binary downloads, so requiring it would surface false negatives
// on real /backup.zip exposures.
func contentTypeFamilyAllowed(ct string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	family := contentTypeFamily(ct)
	if family == "" {
		return true
	}
	for _, a := range allowed {
		if family == strings.ToLower(strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

// lengthCloseTo reports whether two byte lengths are within the
// discovery slack. Absolute floor (contentDiscoveryLenSlack) handles
// tiny bodies; relative slack (contentDiscoveryLenRelSlack) handles
// larger ones where a few bytes of timestamp jitter is meaningless.
func lengthCloseTo(a, b int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	if d <= contentDiscoveryLenSlack {
		return true
	}
	if b == 0 {
		return false
	}
	return float64(d)/float64(b) < contentDiscoveryLenRelSlack
}
