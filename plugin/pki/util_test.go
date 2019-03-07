package pki

import "testing"

func Test_checkStringArrByRegexp(t *testing.T) {

	cases := []struct {
		values  []string
		regexps []string
		match   bool
	}{
		{[]string{}, []string{`.*`}, true},
		{[]string{}, []string{}, false},
		{[]string{}, []string{`RU`, `.*`}, true},
		{[]string{}, []string{`.*`, `US`}, true},
		{[]string{}, []string{`US`}, false},
		{[]string{"US"}, []string{`US`}, true},
		{[]string{"US"}, []string{`.*`}, true},
		{[]string{"US", "RU"}, []string{`US`, `RU`}, true},
		{[]string{"US", "GB"}, []string{`US`, `RU`}, false},
	}
	for _, c := range cases {
		if checkStringArrByRegexp(c.values, c.regexps) != c.match {
			t.Errorf("not valid %+v", c)
		}
	}
}
