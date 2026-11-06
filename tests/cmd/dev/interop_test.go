package main

import (
	"strings"
	"testing"
)

func TestInteropCompletionGate(t *testing.T) {
	start := `{"Action":"start","Package":"p"}` + "\n"
	test := `{"Action":"pass","Package":"p","Test":"TestExternal"}` + "\n"
	end := `{"Action":"pass","Package":"p"}` + "\n"
	for _, tc := range []struct {
		name, log string
		valid     bool
	}{
		{"complete", start + test + end, true},
		{"skip", start + `{"Action":"skip","Package":"p","Test":"TestMissingEngine"}` + "\n" + end, false},
		{"failure", start + `{"Action":"fail","Package":"p"}`, false},
		{"truncated", start + test, false},
		{"empty", "", false},
		{"no-tests", start + end, false},
		{"malformed", start + test + end + "invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passed, err := validateInteropLog(strings.NewReader(tc.log))
			if (err == nil) != tc.valid || tc.valid && passed != 1 {
				t.Fatalf("passed=%d error=%v", passed, err)
			}
		})
	}
}
