package main

import (
	"os"
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
	writeFixture(t, root, "tests/interop/testdata/input.xml", "<document/>\n")
	before, err := suiteSourceDigest(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "transform/testdata/SaxonWorker.java", "class SaxonWorker { int changed; }\n")
	after, err := suiteSourceDigest(t.Context(), root)
	if err != nil || before == after {
		t.Fatal("oracle change retained the old proof source identity", before, after, err)
	}
	t.Run("fixture content", func(t *testing.T) {
		writeFixture(t, root, "tests/interop/testdata/input.xml", "<document id=\"new\"/>\n")
		current, err := suiteSourceDigest(t.Context(), root)
		if err != nil || current == after {
			t.Fatal("test input change retained the old proof source identity", after, current, err)
		}
	})
	t.Run("tracked file removed from worktree", func(t *testing.T) {
		withoutFile, err := suiteSourceDigest(t.Context(), root)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, root, "obsolete.go", "package obsolete\n")
		if output, err := exec.CommandContext(t.Context(), "git", "-C", root, "add", "obsolete.go").CombinedOutput(); err != nil {
			t.Fatal(string(output), err)
		}
		if err := os.Remove(filepath.Join(root, "obsolete.go")); err != nil {
			t.Fatal(err)
		}
		current, err := suiteSourceDigest(t.Context(), root)
		if err != nil || current != withoutFile {
			t.Fatal("absent source changed the effective proof source identity", withoutFile, current, err)
		}
	})
	after, err = suiteSourceDigest(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "oracle-output.log", "disposable run output")
	current, err := suiteSourceDigest(t.Context(), root)
	if err != nil || current != after {
		t.Fatal("disposable logs changed the proof source identity", after, current, err)
	}
}

func TestInteropCompletionGate(t *testing.T) {
	start := `{"Action":"start","Package":"p"}` + "\n"
	run := `{"Action":"run","Package":"p","Test":"TestExternal"}` + "\n"
	test := `{"Action":"pass","Package":"p","Test":"TestExternal"}` + "\n"
	subtest := `{"Action":"run","Package":"p","Test":"TestExternal/subtest"}` + "\n" +
		`{"Action":"pause","Package":"p","Test":"TestExternal/subtest"}` + "\n" +
		`{"Action":"cont","Package":"p","Test":"TestExternal/subtest"}` + "\n" +
		`{"Action":"pass","Package":"p","Test":"TestExternal/subtest"}` + "\n"
	end := `{"Action":"pass","Package":"p"}` + "\n"
	for _, tc := range []struct {
		name, log string
		passed    int
	}{
		{"complete", start + run + test + end, 1},
		{"parallel subtest", start + run + subtest + test + end, 2},
		{"repeated run", start + run + test + run + test + end, 2},
		{"test skip", start + run + `{"Action":"skip","Package":"p","Test":"TestExternal"}` + "\n" + end, 0},
		{"package skip", start + `{"Action":"skip","Package":"p"}` + "\n", 0},
		{"failure", start + run + `{"Action":"fail","Package":"p","Test":"TestExternal"}` + "\n" + end, 0},
		{"truncated", start + run + test, 0},
		{"unmatched pass", start + test + end, 0},
		{"duplicate pass", start + run + test + test + end, 0},
		{"duplicate run", start + run + run + test + end, 0},
		{"unfinished test", start + run + test + run + end, 0},
		{"empty", "", 0},
		{"no-tests", start + end, 0},
		{"malformed", start + run + test + end + "invalid", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passed, err := validateInteropLog(strings.NewReader(tc.log))
			if (err == nil) != (tc.passed != 0) || passed != tc.passed {
				t.Fatalf("passed=%d error=%v; want %d passed", passed, err, tc.passed)
			}
		})
	}
}
