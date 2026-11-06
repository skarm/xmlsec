package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInteropOracleSourceIdentity(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(t.Context(), "git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	writeFixture(t, root, "go.mod", "module example.test/oracle\n")
	writeFixture(t, root, "transform/testdata/SaxonWorker.java", "class SaxonWorker {}\n")
	before, err := suiteSourceDigest(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "transform/testdata/SaxonWorker.java", "class SaxonWorker { int changed; }\n")
	after, err := suiteSourceDigest(t.Context(), root)
	if err != nil || before == after {
		t.Fatal("oracle change retained the old proof source identity", before, after, err)
	}
	writeFixture(t, root, "oracle-output.log", "disposable run output")
	current, err := suiteSourceDigest(t.Context(), root)
	if err != nil || current != after {
		t.Fatal("disposable logs changed the proof source identity", after, current, err)
	}
}

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
