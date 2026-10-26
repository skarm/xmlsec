package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLanguageInputConfiguration(t *testing.T) {
	// The cache/environment override is process-wide, so this test stays serial.
	t.Setenv("XMLSEC_LANGUAGE_CACHE", t.TempDir())
	directory, err := languageInputsDirectory("checkout-one")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	inputs := languageInputs{Java: filepath.Join(t.TempDir(), "bin", "java"), Environment: map[string]string{"XMLSEC_QT3_DIR": "cached-qt3"}}
	if err := writeLanguageProofFile(filepath.Join(directory, "inputs.json"), inputs); err != nil {
		t.Fatal(err)
	}
	got, _, err := readLanguageInputs("checkout-one")
	if err != nil || got.Java != inputs.Java || got.Environment["XMLSEC_QT3_DIR"] != "cached-qt3" {
		t.Fatal("configured inputs were not preserved", got, err)
	}
	if _, _, err := readLanguageInputs("checkout-two"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("another checkout inherited configured inputs", err)
	}
	t.Setenv("XMLSEC_QT3_DIR", "explicit-qt3")
	environment := languageInputEnvironment(got)
	// exec.Cmd applies the last value for duplicate environment keys.
	var value string
	for _, entry := range environment {
		if next, ok := strings.CutPrefix(entry, "XMLSEC_QT3_DIR="); ok {
			value = next
		}
	}
	if value != "explicit-qt3" {
		t.Fatal("explicit environment did not override configured input", value)
	}
}

func TestLanguagePreparedSnapshotRejectsStaleOrMissingEvidence(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	stamp := languageProofStamp{SourceSHA256: "source", RegisterSHA256: "register"}
	stream := languageProofStream{SchemaVersion: 1, Before: stamp, After: stamp, Arguments: []string{"test", "-json", "-count=1", "./fixture"}, ExitCode: 0, Events: []languageProofEvent{{Package: "fixture", Action: "start"}, {Package: "fixture", Action: "pass"}}}
	artifact := languageProofArtifact{SchemaVersion: 1, Stamp: stamp, Streams: []languageProofStream{stream}}
	if err := writeLanguageProofFile(filepath.Join(directory, "events.json"), artifact); err != nil {
		t.Fatal(err)
	}
	for _, file := range languagePreparedReports(directory) {
		if err := writeLanguageProofFile(file, suiteReport{SourceSHA256: stamp.SourceSHA256}); err != nil {
			t.Fatal(err)
		}
	}
	if !languagePreparedValid(directory, stamp) {
		t.Fatal("complete current snapshot was not reusable")
	}
	if languagePreparedValid(directory, languageProofStamp{SourceSHA256: "new-source", RegisterSHA256: "register"}) || languagePreparedValid(directory, languageProofStamp{SourceSHA256: "source", RegisterSHA256: "new-register"}) {
		t.Fatal("stale source or register was reused")
	}
	if err := os.Remove(languagePreparedReports(directory)[0]); err != nil {
		t.Fatal(err)
	}
	if languagePreparedValid(directory, stamp) {
		t.Fatal("incomplete snapshot was reused")
	}
}

func TestLanguageIndependentPatternsSelectExactTestNames(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "docs/conformance.json", `[{"file":"transform/comparison_v1_test.go","name":"TestCompareOne"},{"file":"transform/comparison_v1_test.go","name":"TestCompareTwo"},{"file":"transform/comparison_v1_test.go","name":"TestCompareOne"},{"file":"other_test.go","name":"TestCompareOther"}]`)
	patterns, err := languageIndependentPatterns(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		want int
	}{{"TestCompareOne", 1}, {"TestCompareTwo", 1}, {"TestCompareOther", 0}, {"TestCompareOneMore", 0}} {
		matches := 0
		for _, pattern := range patterns {
			if regexp.MustCompile(pattern).MatchString(test.name) {
				matches++
			}
		}
		if matches != test.want {
			t.Fatal(test.name, matches, test.want)
		}
	}
}

func TestLanguagePreparationJobsPreserveAllFailureCauses(t *testing.T) {
	t.Parallel()
	firstFailure := errors.New("first job failed")
	secondFailure := errors.New("second job failed")
	jobs := []func() error{func() error { return firstFailure }, func() error { return secondFailure }}
	if err := runLanguagePreparationJobs(jobs); !errors.Is(err, firstFailure) || !errors.Is(err, secondFailure) {
		t.Fatal("preparation did not retain failed jobs", err)
	}
}

// Ordinary IDE invocations reuse the configured inputs and prepare a fresh
// snapshot automatically. Explicit environment inputs still take precedence.
func configureLanguageTest(t *testing.T, evidence bool) {
	t.Helper()
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	inputs, base, err := readLanguageInputs(root)
	if errors.Is(err, os.ErrNotExist) {
		return // An unconfigured portable checkout retains its external-test mode.
	}
	if err != nil {
		t.Fatal("read configured language test inputs:", err)
	}
	for name, value := range inputs.Environment {
		if os.Getenv(name) == "" {
			t.Setenv(name, value)
		}
	}
	t.Setenv("PATH", filepath.Dir(inputs.Java)+string(os.PathListSeparator)+os.Getenv("PATH"))
	if !evidence || os.Getenv("XMLSEC_P3_TEST_EVENTS") != "" {
		return
	}
	directory, stamp, err := languagePreparedDirectory(t.Context(), root, base, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !languagePreparedValid(directory, stamp) {
		t.Log("Preparing current-source language evidence in the external cache; the first run may take several minutes.")
		command := exec.CommandContext(t.Context(), "go", "run", "./tests/cmd/dev", "proof", "prepare")
		command.Dir = root
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		if err := command.Run(); err != nil {
			t.Fatalf("prepare language evidence: %v\n%s", err, output.String())
		}
	}
	t.Setenv("XMLSEC_P3_TEST_EVENTS", filepath.Join(directory, "events.json"))
	if os.Getenv("XMLSEC_P3_SUITE_REPORTS") == "" {
		t.Setenv("XMLSEC_P3_SUITE_REPORTS", strings.Join(languagePreparedReports(directory), string(os.PathListSeparator)))
	}
}
