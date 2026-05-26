package lua_engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Pattern classifies a sink value into an identifier family and produces
// tampering candidates of the same shape. The IDOR check uses Pattern to
// decide both whether a sink looks like a resource reference at all
// (Classify returning nil short-circuits the sink) and which payloads to
// send when probing it.
//
// Match reports whether v is a representative of this family. Generate
// produces up to want tampering candidates given a seed (the value the
// sink already carried) and the scan-lifetime Corpus. Generate may return
// fewer than want when the family has no further variants worth probing -
// the IDOR check tolerates a short return.
//
// Precedence orders patterns when several would match the same value.
// Higher precedence wins, so the most specific family attaches: numeric
// (highest) ahead of slug ahead of base64ish (the catch-all).
//
// Learned is true for patterns the corpus promoted from observed shape
// signatures; false for built-ins. Findings name the pattern so a reader
// can tell at a glance whether the engine relied on a learned shape.
type Pattern struct {
	Name       string
	Precedence int
	Learned    bool
	Match      func(string) bool
	Generate   func(seed string, corpus *Corpus, want int) []string
}

// builtinPatterns is the static set the engine ships with. Order is not
// significant - Classify sorts by Precedence on every call to keep
// learned patterns interleaved correctly with built-ins. The slice is
// cloned (not aliased) into Corpus.Patterns() so callers may mutate
// without disturbing the package-level list.
var builtinPatterns = []Pattern{
	patternNumeric(),
	patternUUID(),
	patternMongoID(),
	patternHex(),
	patternEmail(),
	patternUsername(),
	patternSlug(),
	patternBase64ish(),
}

// classifyValue picks the highest-precedence pattern whose Match accepts
// value, considering both built-ins and the corpus's learned patterns.
// name is the lowercase param name; some patterns gate on it (username
// only fires when the param name reads like an account handle). Returns
// nil when no pattern matches - the IDOR check skips such sinks.
func classifyValue(name, value string, learned []Pattern) *Pattern {
	var best *Pattern
	consider := func(p *Pattern) {
		if !p.Match(value) {
			return
		}
		if p.Name == patternNameUsername && !usernameParamHint(name) {
			return
		}
		if best == nil || p.Precedence > best.Precedence {
			best = p
		}
	}
	for i := range builtinPatterns {
		consider(&builtinPatterns[i])
	}
	for i := range learned {
		consider(&learned[i])
	}
	return best
}

// ShapeSignature collapses a value into its character-class skeleton so
// values that share a layout (`ORD-A12B3C`, `ORD-B47K9P`) hash to the
// same key. Digits map to '9', lowercase to 'a', uppercase to 'A';
// everything else (dashes, dots, underscores) is preserved verbatim so
// the separator structure carries through.
//
// Empty input returns "" - the corpus treats that as "do not learn from
// this value".
func ShapeSignature(v string) string {
	if v == "" {
		return ""
	}
	out := make([]byte, len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			out[i] = '9'
		case c >= 'a' && c <= 'z':
			out[i] = 'a'
		case c >= 'A' && c <= 'Z':
			out[i] = 'A'
		default:
			out[i] = c
		}
	}
	return string(out)
}

// learnedPatternFromShape produces a Pattern that accepts values matching
// shape and generates same-shape randoms. Used by Corpus.promote when a
// shape clusters across enough distinct (param, value) pairs to justify
// learning it. Precedence sits between slug (40) and base64ish (10) so a
// learned shape outranks the catch-all but still loses to specific
// built-ins when one applies.
func learnedPatternFromShape(shape string) Pattern {
	return Pattern{
		Name:       "learned:" + shape,
		Precedence: 30,
		Learned:    true,
		Match: func(v string) bool {
			return ShapeSignature(v) == shape
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{seed: {}}
			for _, v := range corpus.valuesForShape(shape) {
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			for len(out) < want {
				v := renderShape(shape)
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, v)
			}
			return out
		},
	}
}

// renderShape produces one same-shape random for shape: every '9' becomes
// a random digit, 'a' a random lowercase, 'A' a random uppercase, other
// bytes pass through. Used by learned-pattern Generate when the corpus
// has run out of real values to swap in.
func renderShape(shape string) string {
	out := make([]byte, len(shape))
	for i := 0; i < len(shape); i++ {
		switch shape[i] {
		case '9':
			out[i] = byte('0' + randIntn(10))
		case 'a':
			out[i] = byte('a' + randIntn(26))
		case 'A':
			out[i] = byte('A' + randIntn(26))
		default:
			out[i] = shape[i]
		}
	}
	return string(out)
}

// randIntn returns a crypto-random int in [0, n). Used by renderShape and
// the built-in UUID generator; the IDOR check never depends on randomness
// for correctness (the oracle compares response bodies), but a
// deterministic PRNG seeded from time would leak the same garbage value
// on retries and confuse caches. crypto/rand sidesteps that.
func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

const (
	patternNameNumeric   = "numeric"
	patternNameUUID      = "uuid"
	patternNameMongoID   = "mongoid"
	patternNameHex       = "hex"
	patternNameEmail     = "email"
	patternNameUsername  = "username"
	patternNameSlug      = "slug"
	patternNameBase64ish = "base64ish"
)

var (
	reNumeric   = regexp.MustCompile(`^\d{1,12}$`)
	reUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reMongoID   = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	reHex       = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	reSlug      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$`)
	reUsername  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{2,32}$`)
	reEmail     = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reBase64ish = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,}$`)
)

// usernameParamHints lists the param names that gate the username
// pattern. A bare alphanumeric value is too ambiguous to classify as a
// username on its own (it could be a SKU, a slug, a coupon code); the
// hint forces an account-like context before we treat the value that
// way and start swapping in `admin` / `root` payloads.
var usernameParamHints = map[string]struct{}{
	"user":     {},
	"username": {},
	"account":  {},
	"owner":    {},
	"handle":   {},
	"login":    {},
	"profile":  {},
	"member":   {},
	"author":   {},
}

func usernameParamHint(name string) bool {
	_, ok := usernameParamHints[strings.ToLower(name)]
	return ok
}

func patternNumeric() Pattern {
	return Pattern{
		Name:       patternNameNumeric,
		Precedence: 100,
		Match: func(v string) bool {
			return reNumeric.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{seed: {}}
			n, err := strconv.ParseInt(seed, 10, 64)
			if err == nil {
				candidates := []int64{n - 1, n + 1, 1, 0, n - 10, n + 10, 999999999}
				for _, c := range candidates {
					if c < 0 {
						continue
					}
					s := strconv.FormatInt(c, 10)
					if _, ok := seen[s]; ok {
						continue
					}
					seen[s] = struct{}{}
					out = append(out, s)
					if len(out) >= want {
						return out
					}
				}
			}
			for _, v := range corpus.valuesForPattern(patternNameNumeric) {
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			return out
		},
	}
}

func patternUUID() Pattern {
	return Pattern{
		Name:       patternNameUUID,
		Precedence: 90,
		Match: func(v string) bool {
			return reUUID.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{strings.ToLower(seed): {}}
			for _, v := range corpus.valuesForPattern(patternNameUUID) {
				lv := strings.ToLower(v)
				if _, ok := seen[lv]; ok {
					continue
				}
				seen[lv] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			if len(out) < want {
				out = append(out, "00000000-0000-0000-0000-000000000000")
			}
			for len(out) < want {
				out = append(out, randomUUID())
			}
			return out
		},
	}
}

// randomUUID returns a 16-byte random UUID (RFC 4122 layout - version 4,
// variant 1) rendered with dashes. Used by the UUID pattern's Generate
// when the corpus runs out of real UUIDs to swap in.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-0000-0000-000000000001"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

func patternMongoID() Pattern {
	return Pattern{
		Name:       patternNameMongoID,
		Precedence: 80,
		Match: func(v string) bool {
			// Must be exactly 24 hex AND not look like a UUID minus the
			// dashes (UUIDs are 32 hex). 24 is the tell-tale Mongo size.
			return reMongoID.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{strings.ToLower(seed): {}}
			for _, v := range corpus.valuesForPattern(patternNameMongoID) {
				lv := strings.ToLower(v)
				if _, ok := seen[lv]; ok {
					continue
				}
				seen[lv] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			if len(out) < want {
				out = append(out, "000000000000000000000000")
			}
			for len(out) < want {
				out = append(out, randomMongoID())
			}
			return out
		},
	}
}

func randomMongoID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "000000000000000000000001"
	}
	return hex.EncodeToString(b[:])
}

func patternHex() Pattern {
	return Pattern{
		Name:       patternNameHex,
		Precedence: 60,
		Match: func(v string) bool {
			// Mongoid (exactly 24) is handled at higher precedence; the
			// hex pattern catches "any 8+ hex string" beyond that.
			if reMongoID.MatchString(v) {
				return false
			}
			return reHex.MatchString(v) && !reUUID.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{strings.ToLower(seed): {}}
			for _, v := range corpus.valuesForPattern(patternNameHex) {
				if len(v) != len(seed) {
					continue
				}
				lv := strings.ToLower(v)
				if _, ok := seen[lv]; ok {
					continue
				}
				seen[lv] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			for len(out) < want {
				out = append(out, randomHex(len(seed)))
			}
			return out
		},
	}
}

func randomHex(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", n)
	}
	return hex.EncodeToString(buf)[:n]
}

func patternEmail() Pattern {
	return Pattern{
		Name:       patternNameEmail,
		Precedence: 70,
		Match: func(v string) bool {
			return reEmail.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{strings.ToLower(seed): {}}
			for _, v := range corpus.valuesForPattern(patternNameEmail) {
				lv := strings.ToLower(v)
				if _, ok := seen[lv]; ok {
					continue
				}
				seen[lv] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			if len(out) < want {
				if at := strings.IndexByte(seed, '@'); at >= 0 {
					out = append(out, "admin"+seed[at:])
				} else {
					out = append(out, "admin@example.com")
				}
			}
			return out
		},
	}
}

func patternUsername() Pattern {
	return Pattern{
		Name:       patternNameUsername,
		Precedence: 50,
		Match: func(v string) bool {
			return reUsername.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{strings.ToLower(seed): {}}
			for _, v := range corpus.valuesForPattern(patternNameUsername) {
				lv := strings.ToLower(v)
				if _, ok := seen[lv]; ok {
					continue
				}
				seen[lv] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			for _, v := range []string{"admin", "root", "test"} {
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			return out
		},
	}
}

func patternSlug() Pattern {
	return Pattern{
		Name:       patternNameSlug,
		Precedence: 40,
		Match: func(v string) bool {
			// Pure numeric is handled at higher precedence; slug requires
			// at least one non-digit to avoid catching IDs that already
			// matched numeric.
			if reNumeric.MatchString(v) {
				return false
			}
			return reSlug.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{seed: {}}
			for _, v := range corpus.valuesForPattern(patternNameSlug) {
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			for _, v := range []string{"admin", "test", "root"} {
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			return out
		},
	}
}

func patternBase64ish() Pattern {
	return Pattern{
		Name:       patternNameBase64ish,
		Precedence: 10,
		Match: func(v string) bool {
			if reUUID.MatchString(v) || reMongoID.MatchString(v) || reHex.MatchString(v) || reEmail.MatchString(v) {
				return false
			}
			return reBase64ish.MatchString(v)
		},
		Generate: func(seed string, corpus *Corpus, want int) []string {
			out := make([]string, 0, want)
			seen := map[string]struct{}{seed: {}}
			for _, v := range corpus.valuesForPattern(patternNameBase64ish) {
				if _, ok := seen[v]; ok {
					continue
				}
				seen[v] = struct{}{}
				out = append(out, v)
				if len(out) >= want {
					return out
				}
			}
			for len(out) < want {
				out = append(out, renderShape(ShapeSignature(seed)))
			}
			return out
		},
	}
}

// controlPayloadFor returns a sentinel value of the same shape as seed
// that is overwhelmingly unlikely to resolve to a real resource on the
// target. The IDOR check sends one as a false-positive backstop: if the
// app returns 200 with content similar to the baseline for this
// guaranteed-garbage value, the endpoint either ignores the parameter
// (public resource) or rendered a SPA shell - either way, not IDOR.
func controlPayloadFor(p *Pattern, seed string) string {
	switch p.Name {
	case patternNameNumeric:
		return "999999999999"
	case patternNameUUID:
		return "00000000-0000-0000-0000-000000000000"
	case patternNameMongoID:
		return "000000000000000000000000"
	case patternNameHex:
		return strings.Repeat("0", len(seed))
	case patternNameEmail:
		return "nobody-hyperz-canary@invalid.local"
	case patternNameUsername:
		return "__hyperz_no_such_user__"
	case patternNameSlug:
		return "hyperz-no-such-slug-canary"
	case patternNameBase64ish:
		return renderShape(ShapeSignature(seed))
	}
	if p.Learned {
		return renderShape(ShapeSignature(seed))
	}
	return seed + "_hyperz_canary"
}
