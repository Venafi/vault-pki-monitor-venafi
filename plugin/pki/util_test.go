package pki

import "testing"

func Test_checkStringArrByRegexp(t *testing.T) {
	cases := []struct {
		values   []string
		regexps  []string
		optional bool
		match    bool
	}{
		{[]string{}, []string{`.*`}, false, true},
		{[]string{}, []string{}, false, false},
		{[]string{}, []string{`RU`, `.*`}, false, true},
		{[]string{}, []string{`.*`, `US`}, false, true},
		{[]string{}, []string{`US`}, false, false},
		{[]string{"US"}, []string{`US`}, false, true},
		{[]string{"US"}, []string{`.*`}, false, true},
		{[]string{"US", "RU"}, []string{`US`, `RU`}, false, true},
		{[]string{"US", "GB"}, []string{`US`, `RU`}, false, false},
		{[]string{"test.vfidev.com"}, []string{`.*\.vfidev\.com`}, false, true},

		{[]string{}, []string{`.*`}, true, true},
		{[]string{}, []string{}, true, true},
		{[]string{}, []string{`RU`, `.*`}, true, true},
		{[]string{}, []string{`.*`, `US`}, true, true},
		{[]string{}, []string{`US`}, true, true},
		{[]string{"US"}, []string{`US`}, true, true},
		{[]string{"US"}, []string{`.*`}, true, true},
		{[]string{"US", "RU"}, []string{`US`, `RU`}, true, true},
		{[]string{"US", "GB"}, []string{`US`, `RU`}, true, false},
		{[]string{"test.vfidev.com"}, []string{`.*\.vfidev\.com`}, true, true},
	}
	for _, c := range cases {
		if checkStringArrByRegexp(c.values, c.regexps, c.optional) != c.match {
			t.Errorf("not valid %+v", c)
		}
	}
}
