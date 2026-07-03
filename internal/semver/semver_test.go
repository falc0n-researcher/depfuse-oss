package semver

import "testing"

func TestCompareStr(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.3.0", "1.2.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0", "1.0.0-rc.1", 1}, // release > prerelease
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-beta", -1},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3+build", "1.2.3", 0}, // build metadata ignored
		{"1.2", "1.2.0", 0},
	}
	for _, c := range cases {
		if got := CompareStr(c.a, c.b); got != c.want {
			t.Errorf("CompareStr(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		v, spec string
		want    bool
	}{
		// exact
		{"4.17.20", "4.17.20", true},
		{"4.17.21", "4.17.20", false},
		{"4.17.20", "=4.17.20", true},
		// any
		{"4.17.20", "*", true},
		{"4.17.20", "", true},
		{"1.0.0-rc.1", "*", false}, // prerelease not matched by bare *
		// caret
		{"4.17.20", "^4.17.0", true},
		{"4.99.0", "^4.17.0", true},
		{"5.0.0", "^4.17.0", false},
		{"3.0.0", "^4.17.0", false},
		{"0.2.5", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false},
		{"0.0.4", "^0.0.3", false},
		{"0.0.3", "^0.0.3", true},
		// tilde
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.5.0", "~1", true},
		{"2.0.0", "~1", false},
		// comparators / AND
		{"1.5.0", ">=1.2.3 <2.0.0", true},
		{"2.0.0", ">=1.2.3 <2.0.0", false},
		{"1.2.2", ">=1.2.3 <2.0.0", false},
		// x-ranges
		{"1.2.9", "1.2.x", true},
		{"1.3.0", "1.2.x", false},
		{"1.9.9", "1.x", true},
		{"2.0.0", "1.x", false},
		// hyphen
		{"1.5.0", "1.2.3 - 2.3.4", true},
		{"2.3.5", "1.2.3 - 2.3.4", false},
		{"2.2.0", "1.2.3 - 2.3", true},
		{"2.4.0", "1.2.3 - 2.3", false},
		// OR
		{"3.0.0", "1.x || >=2.5.0", true},
		{"2.0.0", "1.x || >=2.5.0", false},
		{"1.4.0", "1.x || >=2.5.0", true},
		// prerelease gating
		{"1.2.3-rc.1", ">=1.2.3-rc.0 <2.0.0", true},
		{"2.0.0-rc.1", ">=1.2.3 <2.0.0", false},
	}
	for _, c := range cases {
		if got := Satisfies(c.v, c.spec); got != c.want {
			t.Errorf("Satisfies(%q,%q)=%v want %v", c.v, c.spec, got, c.want)
		}
	}
}

func TestMaxSatisfying(t *testing.T) {
	versions := []string{"4.17.0", "4.17.20", "4.17.21", "5.0.0", "3.10.1"}
	if got := MaxSatisfying(versions, "^4.17.0"); got != "4.17.21" {
		t.Errorf("MaxSatisfying ^4.17.0 = %q want 4.17.21", got)
	}
	if got := MaxSatisfying(versions, "*"); got != "5.0.0" {
		t.Errorf("MaxSatisfying * = %q want 5.0.0", got)
	}
	if got := MaxSatisfying(versions, ">=10.0.0"); got != "" {
		t.Errorf("MaxSatisfying >=10 = %q want empty", got)
	}
}

func TestIsExact(t *testing.T) {
	exact := []string{"1.2.3", "=1.2.3", "v1.2.3", "0.0.1"}
	notExact := []string{"^1.2.3", "~1.2.3", ">=1.2.3", "1.2.x", "1.x", "*", "1.2.3 - 2.0.0", "1.x || 2.x"}
	for _, s := range exact {
		if !IsExact(s) {
			t.Errorf("IsExact(%q)=false want true", s)
		}
	}
	for _, s := range notExact {
		if IsExact(s) {
			t.Errorf("IsExact(%q)=true want false", s)
		}
	}
}
