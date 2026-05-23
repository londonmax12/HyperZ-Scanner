package checks

import (
	"strings"
	"testing"
)

func TestPayloadsForReturnsClassEntries(t *testing.T) {
	cases := []PayloadClass{
		PayloadXSS,
		PayloadSQLiError,
		PayloadSQLiTime,
		PayloadTraversal,
		PayloadCmdInject,
	}
	for _, class := range cases {
		got := PayloadsFor(class)
		if len(got) == 0 {
			t.Errorf("PayloadsFor(%q) returned empty list", class)
		}
		for _, p := range got {
			if p.Class != class {
				t.Errorf("payload %q under class %q tagged %q", p.Name, class, p.Class)
			}
			if p.Name == "" {
				t.Errorf("class %q has unnamed payload: %+v", class, p)
			}
			if p.Template == "" {
				t.Errorf("class %q payload %q has empty template", class, p.Name)
			}
		}
	}
}

func TestPayloadsForUnknownClassReturnsNil(t *testing.T) {
	if got := PayloadsFor(PayloadClass("totally-fake")); got != nil {
		t.Errorf("PayloadsFor(unknown) = %+v, want nil", got)
	}
}

func TestPayloadsForReturnsCopy(t *testing.T) {
	// Mutating the returned slice must not corrupt the catalog for the
	// next caller; checks are run from many goroutines in parallel.
	first := PayloadsFor(PayloadXSS)
	if len(first) == 0 {
		t.Fatal("XSS catalog empty")
	}
	first[0] = Payload{Class: PayloadXSS, Name: "mutated", Template: "x"}
	second := PayloadsFor(PayloadXSS)
	if second[0].Name == "mutated" {
		t.Error("catalog leaked the underlying slice; mutation visible across calls")
	}
}

func TestPayloadRenderSubstitutesToken(t *testing.T) {
	p := Payload{Template: `<svg onload=alert("{{TOKEN}}")>`}
	got := p.Render("hpzc0123456789ab", 0)
	want := `<svg onload=alert("hpzc0123456789ab")>`
	if got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
	if strings.Contains(got, tokenPlaceholder) {
		t.Errorf("placeholder not substituted in %q", got)
	}
}

func TestPayloadRenderSubstitutesSleep(t *testing.T) {
	p := Payload{Template: `'; WAITFOR DELAY '0:0:{{SLEEP}}'-- -`}
	got := p.Render("ignored", 5)
	want := `'; WAITFOR DELAY '0:0:5'-- -`
	if got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
}

func TestPayloadRenderLeavesSleepWhenZero(t *testing.T) {
	// Passing 0 means "don't substitute sleep" - useful when a payload
	// happens to contain {{SLEEP}} but the caller is doing a reflection
	// probe rather than a timing one.
	p := Payload{Template: `' AND SLEEP({{SLEEP}})-- -`}
	got := p.Render("tok", 0)
	if !strings.Contains(got, sleepPlaceholder) {
		t.Errorf("expected sleep placeholder retained, got %q", got)
	}
}

func TestPayloadRenderNoPlaceholders(t *testing.T) {
	// Render must not touch templates without placeholders.
	p := Payload{Template: `'`}
	if got := p.Render("tok", 5); got != "'" {
		t.Errorf("Render = %q, want unchanged", got)
	}
}

func TestSQLiBooleanPairsAreNegated(t *testing.T) {
	pairs := SQLiBooleanPairs()
	if len(pairs) == 0 {
		t.Fatal("no boolean pairs registered")
	}
	for _, p := range pairs {
		if p.True == p.False {
			t.Errorf("pair %q: True == False (%q); pairs must negate", p.Name, p.True)
		}
		if p.Name == "" {
			t.Errorf("unnamed boolean pair: %+v", p)
		}
	}
}

func TestSQLiBooleanPairsReturnsCopy(t *testing.T) {
	first := SQLiBooleanPairs()
	first[0] = SQLiBooleanPair{Name: "mutated"}
	second := SQLiBooleanPairs()
	if second[0].Name == "mutated" {
		t.Error("SQLiBooleanPairs leaked underlying slice")
	}
}

func TestSQLErrorPatternsLowercased(t *testing.T) {
	for _, pat := range SQLErrorPatterns() {
		if pat != strings.ToLower(pat) {
			t.Errorf("pattern %q is not lowercase; caller relies on this for case-insensitive matching", pat)
		}
		if pat == "" {
			t.Error("empty SQL error pattern: would match any body")
		}
	}
}

func TestTraversalMarkersStable(t *testing.T) {
	got := TraversalMarkers()
	if len(got) == 0 {
		t.Fatal("no traversal markers registered")
	}
	// Mutation isolation, same property as the other catalogs.
	got[0] = "mutated"
	again := TraversalMarkers()
	if again[0] == "mutated" {
		t.Error("TraversalMarkers leaked underlying slice")
	}
}

func TestXSSPayloadsCarryToken(t *testing.T) {
	// Every XSS payload must include the token placeholder, otherwise the
	// reflection detector can't tell whether the probe round-tripped.
	for _, p := range PayloadsFor(PayloadXSS) {
		if !strings.Contains(p.Template, tokenPlaceholder) {
			t.Errorf("xss payload %q missing %s in template %q", p.Name, tokenPlaceholder, p.Template)
		}
	}
}

func TestTimePayloadsCarrySleep(t *testing.T) {
	for _, p := range PayloadsFor(PayloadSQLiTime) {
		if !strings.Contains(p.Template, sleepPlaceholder) {
			t.Errorf("sqli-time payload %q missing %s in template %q", p.Name, sleepPlaceholder, p.Template)
		}
	}
	for _, p := range PayloadsFor(PayloadCmdInject) {
		if !strings.Contains(p.Template, sleepPlaceholder) {
			t.Errorf("cmd-injection payload %q missing %s in template %q", p.Name, sleepPlaceholder, p.Template)
		}
	}
}
