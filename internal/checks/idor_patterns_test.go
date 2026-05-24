package checks

import (
	"regexp"
	"strings"
	"testing"
)

func TestShapeSignature(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"42", "99"},
		{"alice", "aaaaa"},
		{"ORD-A12B3C", "AAA-A99A9A"},
		{"2024-01-15", "9999-99-99"},
		{"user@example.com", "aaaa@aaaaaaa.aaa"},
		{"AbC_42-xyZ", "AaA_99-aaA"},
	}
	for _, c := range cases {
		if got := ShapeSignature(c.in); got != c.want {
			t.Errorf("ShapeSignature(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClassifyBuiltins(t *testing.T) {
	corpus := NewCorpus()
	cases := []struct {
		name    string
		value   string
		want    string
		wantNil bool
	}{
		{"id", "42", patternNameNumeric, false},
		{"user_id", "1001", patternNameNumeric, false},
		{"uuid", "11112222-3333-4444-5555-666677778888", patternNameUUID, false},
		{"_id", "507f1f77bcf86cd799439011", patternNameMongoID, false},
		{"token", "deadbeefcafebabe1234abcd", patternNameMongoID, false},
		{"sha", "deadbeefcafebabe1234", patternNameHex, false},
		{"email", "alice@example.com", patternNameEmail, false},
		{"username", "alice", patternNameUsername, false},
		{"slug", "summer-sale-2024", patternNameSlug, false},
		{"opaque", "AbCdEf012345xyzABC", patternNameBase64ish, false},
		{"q", "", "", true},
		{"foo", "?!@&", "", true},
	}
	for _, c := range cases {
		got := corpus.Classify(c.name, c.value)
		if c.wantNil {
			if got != nil {
				t.Errorf("Classify(%q, %q) = %q, want nil", c.name, c.value, got.Name)
			}
			continue
		}
		if got == nil {
			t.Errorf("Classify(%q, %q) = nil, want %q", c.name, c.value, c.want)
			continue
		}
		if got.Name != c.want {
			t.Errorf("Classify(%q, %q) = %q, want %q", c.name, c.value, got.Name, c.want)
		}
	}
}

func TestClassifyUsernameRequiresHint(t *testing.T) {
	corpus := NewCorpus()
	// `alice` under an account-shaped param classifies as username
	if got := corpus.Classify("user", "alice"); got == nil || got.Name != patternNameUsername {
		t.Fatalf("Classify(user, alice) = %v, want username", got)
	}
	// `alice` under a non-account param should not light up username -
	// it'll fall through to slug.
	got := corpus.Classify("color", "alice")
	if got == nil {
		t.Fatalf("Classify(color, alice) = nil, want slug")
	}
	if got.Name == patternNameUsername {
		t.Errorf("Classify(color, alice) = username, expected slug or other")
	}
}

func TestNumericGenerateProducesSequentialNeighbors(t *testing.T) {
	corpus := NewCorpus()
	p := corpus.Classify("id", "42")
	if p == nil || p.Name != patternNameNumeric {
		t.Fatalf("expected numeric pattern for id=42, got %v", p)
	}
	cands := p.Generate("42", corpus, 5)
	want := map[string]struct{}{
		"41": {}, "43": {}, "1": {}, "32": {}, "52": {},
	}
	for _, c := range cands {
		delete(want, c)
	}
	// We don't require *every* expected neighbor (the first three carry
	// the strongest signal); but at least 41 and 43 must always appear.
	if !contains(cands, "41") || !contains(cands, "43") {
		t.Errorf("numeric Generate should always emit 41 and 43, got %v", cands)
	}
}

func TestNumericGenerateAvoidsNegatives(t *testing.T) {
	corpus := NewCorpus()
	p := corpus.Classify("id", "0")
	cands := p.Generate("0", corpus, 5)
	for _, c := range cands {
		if strings.HasPrefix(c, "-") {
			t.Errorf("numeric Generate emitted a negative value %q", c)
		}
	}
}

func TestUUIDGenerateEmitsZeroUUIDAndRandom(t *testing.T) {
	corpus := NewCorpus()
	seed := "11112222-3333-4444-5555-666677778888"
	p := corpus.Classify("uuid", seed)
	if p == nil || p.Name != patternNameUUID {
		t.Fatalf("expected uuid pattern, got %v", p)
	}
	cands := p.Generate(seed, corpus, 3)
	if !contains(cands, "00000000-0000-0000-0000-000000000000") {
		t.Errorf("uuid Generate should emit the zero UUID, got %v", cands)
	}
	uuidRe := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	for _, c := range cands {
		if !uuidRe.MatchString(c) {
			t.Errorf("uuid Generate produced non-UUID candidate %q", c)
		}
		if c == seed {
			t.Errorf("uuid Generate should not return the seed")
		}
	}
}

func TestUUIDGenerateDrawsFromCorpus(t *testing.T) {
	corpus := NewCorpus()
	// Pre-seed the corpus with another UUID from a different sink.
	other := "aaaabbbb-cccc-dddd-eeee-ffff00001111"
	corpus.Ingest("ticket_id", other)
	seed := "11112222-3333-4444-5555-666677778888"
	p := corpus.Classify("user_id", seed)
	cands := p.Generate(seed, corpus, 3)
	if !contains(cands, other) {
		t.Errorf("uuid Generate should swap in corpus UUIDs first, got %v", cands)
	}
}

func TestUsernameGenerateIncludesAdminFallbacks(t *testing.T) {
	corpus := NewCorpus()
	p := corpus.Classify("user", "alice")
	if p == nil {
		t.Fatal("expected username pattern")
	}
	cands := p.Generate("alice", corpus, 5)
	if !contains(cands, "admin") {
		t.Errorf("username Generate should include `admin`, got %v", cands)
	}
}

func TestLearnedPatternPromotion(t *testing.T) {
	corpus := NewCorpus()
	// Three same-shape values across two distinct params - thresholds
	// say we should promote.
	corpus.Ingest("order_ref", "ORD-A12B3C")
	corpus.Ingest("order_ref", "ORD-B47K9P")
	corpus.Ingest("purchase_ref", "ORD-Z99X1M")

	learned := corpus.LearnedPatterns()
	if len(learned) == 0 {
		t.Fatalf("expected at least one learned pattern, got %d", len(learned))
	}
	shape := "AAA-A99A9A"
	wantName := "learned:" + shape
	found := false
	for _, p := range learned {
		if p.Name == wantName {
			found = true
		}
	}
	if !found {
		t.Errorf("learned patterns missing %q: %v", wantName, learnedNames(learned))
	}

	// A new sink with the same shape should now classify as the learned
	// pattern instead of falling back to base64ish.
	got := corpus.Classify("another_ref", "ORD-X11Y2Z")
	if got == nil {
		t.Fatalf("Classify returned nil for learned-shape value")
	}
	if got.Name != wantName {
		t.Errorf("Classify(another_ref, ORD-X11Y2Z) = %q, want %q", got.Name, wantName)
	}

	// Generate from the learned pattern should produce same-shape values.
	cands := got.Generate("ORD-X11Y2Z", corpus, 3)
	shapeRe := regexp.MustCompile(`^[A-Z]{3}-[A-Z][0-9]{2}[A-Z][0-9][A-Z]$`)
	for _, c := range cands {
		if !shapeRe.MatchString(c) {
			t.Errorf("learned Generate produced off-shape candidate %q", c)
		}
	}
}

func TestLearnedPromotionGatedOnDistinctParams(t *testing.T) {
	corpus := NewCorpus()
	// Three same-shape values, but all under one param - should NOT
	// promote (distinct-params threshold is 2).
	corpus.Ingest("order_ref", "ORD-A12B3C")
	corpus.Ingest("order_ref", "ORD-B47K9P")
	corpus.Ingest("order_ref", "ORD-Z99X1M")
	if got := len(corpus.LearnedPatterns()); got != 0 {
		t.Errorf("learned patterns = %d, want 0 (single-param shapes should not promote)", got)
	}
}

func TestBuiltinShapesAreNotLearned(t *testing.T) {
	corpus := NewCorpus()
	// Three numerics under two distinct params - shape is `99`, but
	// numeric is a built-in so the engine should not promote it.
	corpus.Ingest("user_id", "11")
	corpus.Ingest("user_id", "22")
	corpus.Ingest("order_id", "33")
	for _, p := range corpus.LearnedPatterns() {
		if strings.HasPrefix(p.Name, "learned:9") {
			t.Errorf("numeric shape should not promote into a learned pattern, got %q", p.Name)
		}
	}
}

func TestControlPayloadForKnownPatterns(t *testing.T) {
	corpus := NewCorpus()
	cases := []struct {
		name, value, want string
	}{
		{"id", "42", "999999999999"},
		{"uuid", "11112222-3333-4444-5555-666677778888", "00000000-0000-0000-0000-000000000000"},
		{"_id", "507f1f77bcf86cd799439011", "000000000000000000000000"},
		{"email", "alice@example.com", "nobody-hyperz-canary@invalid.local"},
		{"user", "alice", "__hyperz_no_such_user__"},
	}
	for _, c := range cases {
		p := corpus.Classify(c.name, c.value)
		if p == nil {
			t.Fatalf("Classify(%q, %q) = nil", c.name, c.value)
		}
		if got := controlPayloadFor(p, c.value); got != c.want {
			t.Errorf("controlPayloadFor(%q, %q) = %q, want %q", p.Name, c.value, got, c.want)
		}
	}
}

func contains(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

func learnedNames(ps []Pattern) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}
