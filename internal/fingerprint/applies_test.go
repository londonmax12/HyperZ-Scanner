package fingerprint

import "testing"

func TestAppliesSpecIsEmpty(t *testing.T) {
	if !(AppliesSpec{}).IsEmpty() {
		t.Fatalf("zero AppliesSpec should be empty")
	}
	if (AppliesSpec{CMS: []string{"wordpress"}}).IsEmpty() {
		t.Fatalf("AppliesSpec with cms=wordpress should not be empty")
	}
}

func TestAppliesSpecMatchesNilStackIsPermissive(t *testing.T) {
	spec := AppliesSpec{CMS: []string{"wordpress"}}
	if !spec.Matches(nil) {
		t.Fatalf("nil stack must match every spec (permissive on absent fingerprint)")
	}
}

func TestAppliesSpecMatchesEmptySpecIsPermissive(t *testing.T) {
	if !(AppliesSpec{}).Matches(&Stack{CMS: "drupal"}) {
		t.Fatalf("empty spec must match every stack")
	}
}

func TestAppliesSpecMatchesSingleFieldCMS(t *testing.T) {
	spec := AppliesSpec{CMS: []string{"wordpress"}}
	if !spec.Matches(&Stack{CMS: "wordpress"}) {
		t.Fatalf("matching CMS should pass")
	}
	if !spec.Matches(&Stack{CMS: "WordPress"}) {
		t.Fatalf("CMS match must be case-insensitive")
	}
	if spec.Matches(&Stack{CMS: "drupal"}) {
		t.Fatalf("non-matching CMS should fail")
	}
}

func TestAppliesSpecMatchesUnknownValueIsPermissive(t *testing.T) {
	spec := AppliesSpec{CMS: []string{"wordpress"}}
	if !spec.Matches(&Stack{}) {
		t.Fatalf("empty stack value for constrained field must pass (unknown is permissive)")
	}
}

func TestAppliesSpecMatchesMultipleFieldsAreANDed(t *testing.T) {
	spec := AppliesSpec{
		CMS:    []string{"wordpress"},
		Server: []string{"nginx"},
	}
	if !spec.Matches(&Stack{CMS: "wordpress", Server: "nginx"}) {
		t.Fatalf("AND of two matching fields should pass")
	}
	if spec.Matches(&Stack{CMS: "wordpress", Server: "apache"}) {
		t.Fatalf("AND should fail if any constrained field fails")
	}
	// unknown values pass per the contract
	if !spec.Matches(&Stack{CMS: "wordpress"}) {
		t.Fatalf("unknown Server (constrained but stack-empty) must pass")
	}
}

func TestAppliesSpecMatchesORWithinField(t *testing.T) {
	spec := AppliesSpec{CMS: []string{"wordpress", "drupal"}}
	if !spec.Matches(&Stack{CMS: "wordpress"}) {
		t.Fatalf("wordpress in OR-list should pass")
	}
	if !spec.Matches(&Stack{CMS: "drupal"}) {
		t.Fatalf("drupal in OR-list should pass")
	}
	if spec.Matches(&Stack{CMS: "joomla"}) {
		t.Fatalf("joomla not in OR-list should fail")
	}
}

func TestPatchedInInferUnknownBanner(t *testing.T) {
	stack := &Stack{CMS: "wordpress"} // Versions["cms"] absent
	p := PatchedIn{"cms": "6.2"}
	obs := p.Infer(stack)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Kind != "inferred" {
		t.Errorf("Kind = %q, want inferred", obs[0].Kind)
	}
	if obs[0].Field != "cms" || obs[0].DetectedName != "wordpress" || obs[0].PatchedVersion != "6.2" {
		t.Errorf("unexpected observation %+v", obs[0])
	}
}

func TestPatchedInInferBannerBelowPatched(t *testing.T) {
	stack := &Stack{CMS: "wordpress", Versions: map[string]string{"cms": "6.1"}}
	p := PatchedIn{"cms": "6.2"}
	obs := p.Infer(stack)
	if len(obs) != 0 {
		t.Fatalf("expected no observations when banner < patched, got %+v", obs)
	}
}

func TestPatchedInInferBannerAtOrAbovePatched(t *testing.T) {
	for _, v := range []string{"6.2", "6.3", "7.0"} {
		stack := &Stack{CMS: "wordpress", Versions: map[string]string{"cms": v}}
		p := PatchedIn{"cms": "6.2"}
		obs := p.Infer(stack)
		if len(obs) != 1 {
			t.Fatalf("banner=%s: expected 1 observation, got %d", v, len(obs))
		}
		if obs[0].Kind != "patched_but_fired" {
			t.Errorf("banner=%s Kind = %q, want patched_but_fired", v, obs[0].Kind)
		}
		if obs[0].BannerVersion != v {
			t.Errorf("banner=%s BannerVersion = %q, want %q", v, obs[0].BannerVersion, v)
		}
	}
}

func TestPatchedInInferNilStackReturnsNil(t *testing.T) {
	p := PatchedIn{"cms": "6.2"}
	if obs := p.Infer(nil); obs != nil {
		t.Fatalf("nil stack must return nil, got %+v", obs)
	}
}

func TestPatchedInInferUndetectedFieldSkips(t *testing.T) {
	// stack has no CMS detected at all
	stack := &Stack{Server: "nginx"}
	p := PatchedIn{"cms": "6.2"}
	if obs := p.Infer(stack); len(obs) != 0 {
		t.Fatalf("undetected field must not produce observation, got %+v", obs)
	}
}

func TestPatchedInInferUnparseableVersionSkips(t *testing.T) {
	stack := &Stack{CMS: "wordpress", Versions: map[string]string{"cms": "not-a-version"}}
	p := PatchedIn{"cms": "6.2"}
	if obs := p.Infer(stack); len(obs) != 0 {
		t.Fatalf("unparseable banner must not produce observation, got %+v", obs)
	}
}
