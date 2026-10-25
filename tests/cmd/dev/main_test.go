package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	conformanceUnknownState       = "unknown state"
	conformanceMissingDescription = "missing required description"
)

func TestIncrementalProofReport(t *testing.T) {
	stream := languageProofStream{SchemaVersion: 1, Arguments: []string{"test", "<&é"}, Events: []languageProofEvent{{Package: "p", Action: "pass", Output: "\n<&漢字"}}}
	for _, value := range []any{(*languageProofStream)(nil), languageProofStream{}, stream, languageProofArtifact{SchemaVersion: 1, Streams: []languageProofStream{stream, {}}}} {
		path := filepath.Join(t.TempDir(), "proof.json")
		if err := writeLanguageProofFile(path, value); err != nil {
			t.Fatal(err)
		}
		output, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(value)
		var actualValue, expectedValue any
		if err := json.Unmarshal(output, &actualValue); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(want, &expectedValue); err != nil {
			t.Fatal(err)
		}
		actual, _ := json.Marshal(actualValue)
		expected, _ := json.Marshal(expectedValue)
		if !bytes.Equal(actual, expected) {
			t.Fatal("proof JSON values changed", string(actual), string(expected))
		}
	}
	if err := writeLanguageProofJSON(&reportFailWriter{remaining: 200}, stream); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("proof ignored short write", err)
	}

	path := filepath.Join(t.TempDir(), "proof.json")
	if err := writeLanguageProofFile(path, stream); err != nil {
		t.Fatal(err)
	}
	if err := invalidateLanguageProofFile(path); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("late publication failure")
	if err := writeJSONFile(path, false, func(dst io.Writer) error {
		_, _ = io.WriteString(dst, "partial replacement")
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "null\n" {
		t.Fatal("failed publication left a previous proof", string(raw), err)
	}
	empty := filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := invalidateLanguageProofFile(empty); err == nil {
		t.Fatal("directory accepted as a proof file")
	}
	if info, err := os.Stat(empty); err != nil || !info.IsDir() {
		t.Fatal("invalidation removed a directory", err)
	}
}

func TestDocumentationChecks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, "file with spaces.md", "target\n")
	register := string(conformanceFixture(t, root))
	writeFixture(t, root, "docs/conformance.json", register)

	readme := "[target](file%20with%20spaces.md#section) [external](https://example.test/missing)\n```\n[illustration](missing.md)\n```\n"
	writeFixture(t, root, "README.md", readme)
	writeFixture(t, root, "tests/README.md", "[target](../file%20with%20spaces.md)\n")
	writeFixture(t, root, "build/README.md", "[target](../file%20with%20spaces.md)\n")

	var out bytes.Buffer
	if err := checkDocs(root, &out); err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string]string{
		"broken local link": "[target](missing.md)",
		"absolute link":     "[target](" + filepath.ToSlash(filepath.Join(root, "fixture_test.go")) + ")",
		"outside link":      "[target](../outside.md)",
	} {
		t.Run(name, func(t *testing.T) {
			writeFixture(t, root, "README.md", bad)

			if err := checkDocs(root, &out); err == nil {
				t.Fatal("invalid local documentation link accepted")
			}
		})
	}

	writeFixture(t, root, "README.md", readme)

	for _, path := range []string{"tests/README.md", "build/README.md"} {
		writeFixture(t, root, path, "[target](missing.md)")

		if err := checkDocs(root, &out); err == nil {
			t.Fatal("broken support documentation link accepted", path)
		}

		writeFixture(t, root, path, "[target](../file%20with%20spaces.md)\n")
	}

	for _, bad := range []string{
		`{"requirements":[{"id":"dup","tests":[]},{"id":"dup","tests":[]}]}`,
		`{"requirements":[{"id":"missing","tests":["missing_test.go"]}]}`,
		`{"requirements":[{"id":"directory","tests":["docs"]}]}`,
		`{"requirements":[]}`,
		register + `{}`,
	} {
		writeFixture(t, root, "docs/conformance.json", bad)

		if err := checkDocs(root, &out); err == nil {
			t.Fatal("invalid conformance register accepted", bad)
		}
	}
}

func TestNormativeConformanceChecks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	valid := conformanceFixture(t, root)

	count, problems, err := checkConformanceRegister(root, valid)
	if count != 2 || len(problems) != 0 || err != nil {
		t.Fatal(count, problems, err)
	}

	for _, test := range []struct {
		name   string
		want   string
		mutate func(*conformanceRegister)
	}{
		{"duplicate capability", "duplicate capability", func(r *conformanceRegister) { r.Requirements[1].ID = r.Requirements[0].ID }},
		{"duplicate norm", "duplicate normative", func(r *conformanceRegister) { r.Normative = append(r.Normative, r.Normative[0]) }},
		{"duplicate document", "duplicate document", func(r *conformanceRegister) { r.Documents = append(r.Documents, r.Documents[0]) }},
		{"unknown clause source", "document association", func(r *conformanceRegister) { r.Normative[0].Norm.Document = "unknown" }},
		{"invented normative level", conformanceUnknownState, func(r *conformanceRegister) { r.Normative[0].Norm.Level = "probably-required" }},
		{"informative is not executable", "informative material", func(r *conformanceRegister) { r.Normative[0].Norm.Level = "informative" }},
		{"missing clause", conformanceMissingDescription, func(r *conformanceRegister) { r.Normative[0].Norm.Clause = "" }},
		{"wrong mode", "mode is not part", func(r *conformanceRegister) { r.Normative[0].Applies.Mode = "historical" }},
		{"missing code", "missing/nonportable file", func(r *conformanceRegister) { r.Normative[0].Implementation.Code[0] = "missing.go" }},
		{"directory as evidence", "regular file", func(r *conformanceRegister) { r.Normative[0].Implementation.Code[0] = "fixture" }},
		{"unknown API", "missing exported API", func(r *conformanceRegister) { r.Normative[0].Implementation.APIs[0] = "fixture.Missing" }},
		{"renamed test", "missing test", func(r *conformanceRegister) { r.Normative[0].Tests.Positive[0].Name = "TestMissing" }},
		{"missing negative case", "positive/negative tests", func(r *conformanceRegister) { r.Normative[0].Tests.Negative = nil }},
		{"invented local coverage", conformanceUnknownState, func(r *conformanceRegister) { r.Normative[0].Tests.Status = "probably-covered" }},
		{"unexplained local coverage", conformanceMissingDescription, func(r *conformanceRegister) { r.Normative[0].Tests.Reason = "" }},
		{"pending with test claims", "pending local evidence", func(r *conformanceRegister) { r.Normative[0].Tests.Status = conformancePending }},
		{"empty partial evidence", "partial local evidence", func(r *conformanceRegister) {
			r.Normative[0].Tests.Status = conformancePartial
			r.Normative[0].Tests.Positive, r.Normative[0].Tests.Negative = nil, nil
		}},
		{"applicable without test duties", "non-applicable evidence", func(r *conformanceRegister) { r.Normative[0].Tests.Status = normNotApplicable }},
		{"unsupported policy grant", "policy cannot enable", func(r *conformanceRegister) { r.Normative[0].Implementation.Status = "unimplemented" }},
		{"policy is not implementation", conformanceUnknownState, func(r *conformanceRegister) { r.Normative[0].Implementation.Status = "forbidden-by-policy" }},
		{"unsupported mandatory is applicable", "non-applicability requires a different standard role", func(r *conformanceRegister) {
			r.Normative[0].Applies.Status = normNotApplicable
			r.Normative[0].Implementation.Status = normNotApplicable
		}},
		{"unexplained gap", conformanceMissingDescription, func(r *conformanceRegister) { r.Normative[0].Closure = "" }},
		{"unsupported full claim", "full claim requires a complete inventory", func(r *conformanceRegister) { r.Profiles[0].Claim = conformanceFull }},
		{"unreviewed errata", "full claim requires reviewed errata", func(r *conformanceRegister) {
			r.Profiles[0].Claim, r.Profiles[0].Inventory, r.Profiles[0].Gap = conformanceFull, conformanceComplete, ""
			r.Documents[0].Errata.Review = conformancePending
		}},
		{"unclosed obligation", "open obligation", func(r *conformanceRegister) {
			r.Profiles[0].Claim, r.Profiles[0].Inventory, r.Profiles[0].Gap = conformanceFull, conformanceComplete, ""
		}},
		{"invented interop evidence", "independent fixtures", func(r *conformanceRegister) { r.Normative[0].Interop.Status = conformanceCovered }},
		{"missing schema", "schema 4", func(r *conformanceRegister) { r.SchemaVersion = 0 }},
		{"unaccounted document", "document missing from role matrix", func(r *conformanceRegister) { r.Profiles[0].Matrix = nil }},
		{"missing matrix obligation", "missing or mismatched matrix requirement", func(r *conformanceRegister) { r.Profiles[0].Matrix[0].Requirements = []string{"missing"} }},
		{"foreign matrix mode", "matrix mode is not part", func(r *conformanceRegister) { r.Profiles[0].Matrix[0].Modes = []string{"issue"} }},
		{"unassessed operation", "mode has no assessed", func(r *conformanceRegister) { r.Profiles[0].Modes = append(r.Profiles[0].Modes, "issue") }},
		{"empty inventory boundary", "partial inventory must identify", func(r *conformanceRegister) { r.Profiles[0].Matrix[0].Unmapped = nil }},
		{"false complete inventory", "complete inventory has unmapped", func(r *conformanceRegister) { r.Profiles[0].Inventory = conformanceComplete }},
		{"foreign normative source", "source must belong to the pinned", func(r *conformanceRegister) { r.Normative[0].Norm.Source = "https://example.test/different#verify" }},
		{"invented correction", "unknown or unselected correction", func(r *conformanceRegister) { r.Normative[0].Norm.Errata = []string{"E-does-not-exist"} }},
		{"duplicate operation", "empty/duplicate matrix", func(r *conformanceRegister) { r.Profiles[0].Modes = []string{"verify", "verify"} }},
		{"unknown correction disposition", conformanceUnknownState, func(r *conformanceRegister) {
			r.Documents[0].Errata.Items = []standardCorrection{{ID: "E1", Disposition: "automatically-accepted", Clause: "3.2", Reason: "Fixture correction."}}
		}},

		{"invalid date", "ISO date", func(r *conformanceRegister) { r.ReviewedOn = "yesterday" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var register conformanceRegister
			if err := json.Unmarshal(valid, &register); err != nil {
				t.Fatal(err)
			}

			test.mutate(&register)

			raw, err := json.Marshal(register)
			if err != nil {
				t.Fatal(err)
			}

			_, problems, err := checkConformanceRegister(root, raw)
			if combined := errors.Join(append(problems, err)...); combined == nil || !strings.Contains(combined.Error(), test.want) {
				t.Fatalf("wanted %q, got %v", test.want, combined)
			}
		})
	}
}

func TestConformancePendingLocalEvidence(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, coverage := range []string{conformancePartial, conformancePending} {
		t.Run(coverage, func(t *testing.T) {
			var register conformanceRegister
			if err := json.Unmarshal(conformanceFixture(t, root), &register); err != nil {
				t.Fatal(err)
			}

			r := &register.Normative[0]
			r.Tests.Status = coverage

			r.Tests.Reason = "Obligation-specific cases still need assessment."
			if coverage == conformancePending {
				r.Tests.Positive, r.Tests.Negative = nil, nil
			}

			r.Interop.Status = normNotApplicable
			r.Interop.Reason = "This local fixture has no external format."

			raw, err := json.Marshal(register)
			if err != nil {
				t.Fatal(err)
			}

			if _, problems, err := checkConformanceRegister(root, raw); len(problems) != 0 || err != nil {
				t.Fatal("explicit evidence backlog was rejected", problems, err)
			}

			register.Profiles[0].Claim, register.Profiles[0].Inventory, register.Profiles[0].Gap = conformanceFull, conformanceComplete, ""
			register.Profiles[0].Matrix[0].Unmapped = nil
			r.Gap = ""

			raw, err = json.Marshal(register)
			if err != nil {
				t.Fatal(err)
			}

			_, problems, err := checkConformanceRegister(root, raw)
			if combined := errors.Join(append(problems, err)...); combined == nil || !strings.Contains(combined.Error(), "open obligation") {
				t.Fatal("incomplete local evidence permitted a full claim", combined)
			}
		})
	}
}

func TestConformanceOptionalImplementationAndCorrections(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	var register conformanceRegister
	if err := json.Unmarshal(conformanceFixture(t, root), &register); err != nil {
		t.Fatal(err)
	}

	register.Profiles[0].Claim, register.Profiles[0].Inventory, register.Profiles[0].Gap = conformanceFull, conformanceComplete, ""
	register.Profiles[0].Matrix[0].Unmapped = nil
	register.Normative[0].Norm.Level = "OPTIONAL"
	register.Normative[0].Implementation.Status = "unimplemented"
	register.Normative[0].Policy.Default.Status = "unavailable"
	register.Normative[0].Policy.Compatibility.Status = "unavailable"

	raw, err := json.Marshal(register)
	if err != nil {
		t.Fatal(err)
	}

	if _, problems, err := checkConformanceRegister(root, raw); len(problems) != 0 || err != nil {
		t.Fatal(problems, err)
	}

	register.Normative[0].Norm.Level = "MUST"

	raw, err = json.Marshal(register)
	if err != nil {
		t.Fatal(err)
	}

	if _, problems, err := checkConformanceRegister(root, raw); len(problems) == 0 || err != nil {
		t.Fatal("missing mandatory implementation accepted", problems, err)
	}

	register.Normative[0].Norm.Level = "OPTIONAL"

	register.Normative[0].Norm.Errata = []string{"E1"}
	for _, disposition := range []string{"selected", "incorporated", "proposed", "informative"} {
		register.Documents[0].Errata.Items = []standardCorrection{{ID: "E1", Disposition: disposition, Clause: "3.2", Reason: "Fixture correction disposition."}}

		raw, err := json.Marshal(register)
		if err != nil {
			t.Fatal(err)
		}

		_, problems, err := checkConformanceRegister(root, raw)

		accepted := disposition == "selected" || disposition == "incorporated"
		if err != nil || (len(problems) == 0) != accepted {
			t.Fatal(disposition, problems, err)
		}
	}
}

func TestConformanceEvidenceNamesRealTests(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	valid := conformanceFixture(t, root)
	for _, declaration := range []string{
		"// func TestPresent(t *testing.T) {}",
		"type receiver struct{}\nfunc (receiver) TestPresent(t *testing.T) {}",
		"func TestPresent() {}",
		"func TestPresent(t *testing.B) {}",
		"func TestPresent(t, other *testing.T) {}",
		"func TestPresent(t *testing.T) int { return 0 }",
	} {
		writeFixture(t, root, "fixture_test.go", "package fixture_test\nimport \"testing\"\n"+declaration)

		_, problems, err := checkConformanceRegister(root, valid)
		if combined := errors.Join(append(problems, err)...); combined == nil || !strings.Contains(combined.Error(), "missing test") {
			t.Fatalf("non-test evidence accepted: %s (%v)", declaration, combined)
		}
	}
}

func TestConformanceCaseEvidence(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixture := conformanceFixture(t, root)
	writeFixture(t, root, "tests/cmd/dev/main_test.go", "package main\nimport \"testing\"\nfunc TestLanguageNormativeEvidence(t *testing.T) {}\n")
	wantTrue, wantFalse, wantEmpty := "true", "false", ""
	proof := normativeProof{
		Check:  conformanceTest{File: "fixture_test.go", Name: "TestPresent", Case: "table/integer"},
		Oracle: "published-vector", Source: "https://example.test/standard#table", Expected: &wantTrue, Basis: "Integer diagonal cell of the published subtype table.",
	}
	structural := func(register *conformanceRegister, partial bool) {
		base := register.Normative[0]
		base.Interop.Status = conformanceCovered
		base.Interop.Tests = []conformanceTest{proof.Check}
		base.Interop.Fixtures = []string{"fixture_test.go"}
		base.Interop.Reason = "Closed executable fixture witnesses."
		parent, first, second := base, base, base
		parent.ID, parent.Norm.Clause = "N-XP31-CLAUSE-3", "3"
		first.ID, first.Norm.Clause = "N-XP31-CLAUSE-3.1", "3.1"
		second.ID, second.Norm.Clause = "N-XP31-CLAUSE-3.2", "3.2"
		parent.EvidenceFrom = []string{first.ID, second.ID}
		if partial {
			parent.EvidenceFrom = parent.EvidenceFrom[:1]
			parent.EvidenceComposition = "A directly tested parent rule cannot replace the second structural child's separate obligation."
		}
		register.Normative = []normativeRequirement{parent, first, second}
		register.Profiles[0].Matrix[0].Requirements = []string{parent.ID, first.ID, second.ID}
	}
	for _, tc := range []struct {
		name    string
		problem string
		mutate  func(*conformanceRegister)
	}{
		{"published cell", "", func(*conformanceRegister) {}},
		{"complete canonical inheritance", "", func(r *conformanceRegister) { structural(r, false) }},
		{"composition cannot hide structural child", "inheritance omits structural child", func(r *conformanceRegister) { structural(r, true) }},
		{"explicit empty output", "", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive[0].Expected = &wantEmpty }},
		{"omitted published expectation", "missing required description", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive[0].Expected = nil }},

		{"no exact case", "missing required description", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive[0].Check.Case = "" }},
		{"no negative witness", "positive/negative witnesses", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Negative = nil }},
		{"invented oracle", "unknown state", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive[0].Oracle = "self-generated" }},
		{"unpublished expectation", "missing required description", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive[0].Basis = "" }},
		{"unnamed publisher case", "exact catalog case", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive[0].Oracle = "publisher" }},
		{"missing inherited row", "mismatched inherited evidence", func(r *conformanceRegister) { r.Normative[0].EvidenceFrom = []string{"absent"} }},
		{"no positive witness", "positive/negative witnesses", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive = nil }},
		{"documentation inventory on behavioral duty", "limited to the Appendix D", func(r *conformanceRegister) { r.Normative[0].Evidence[0].Positive[0].Oracle = "published-inventory" }},
		{"exact publisher bundle", "", func(r *conformanceRegister) {
			r.Normative[0].Evidence[0].Positive = []normativeProof{{Catalog: &catalogProof{Suite: "qt3", File: "fn/abs.xml", Version: "3.1", XSDVersion: "1.0", Names: []string{"fn-absint1", "fn-absint2"}}}}
		}},
		{"duplicate publisher case", "empty/duplicate", func(r *conformanceRegister) {
			r.Normative[0].Evidence[0].Positive = []normativeProof{{Catalog: &catalogProof{Suite: "qt3", File: "fn/abs.xml", Version: "3.1", XSDVersion: "1.0", Names: []string{"fn-absint1", "fn-absint1"}}}}
		}},
		{"ambiguous publisher bundle", "ambiguous publisher proof bundle", func(r *conformanceRegister) {
			r.Normative[0].Evidence[0].Positive = []normativeProof{{Check: proof.Check, Catalog: &catalogProof{Suite: "qt3", File: "fn/abs.xml", Version: "3.1", XSDVersion: "1.0", Names: []string{"fn-absint1"}}}}
		}},

		{"self inheritance", "cyclic normative evidence", func(r *conformanceRegister) { r.Normative[0].EvidenceFrom = []string{"norm"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var register conformanceRegister
			if err := json.Unmarshal(fixture, &register); err != nil {
				t.Fatal(err)
			}
			p, n := proof, proof
			n.Expected = &wantFalse
			register.Normative[0].Evidence = []normativeEvidence{{Obligation: "Published subtype table", Positive: []normativeProof{p}, Negative: []normativeProof{n}}}
			tc.mutate(&register)
			raw, err := json.Marshal(register)
			if err != nil {
				t.Fatal(err)
			}
			_, problems, err := checkConformanceRegister(root, raw)
			combined := errors.Join(append(problems, err)...)
			if tc.problem == "" && combined != nil || tc.problem != "" && (combined == nil || !strings.Contains(combined.Error(), tc.problem)) {
				t.Fatal(combined)
			}
		})
	}
}

func conformanceFixture(t *testing.T, root string) []byte {
	t.Helper()
	writeFixture(t, root, "fixture/api.go", "package fixture\nfunc Apply() {}\n")
	writeFixture(t, root, "fixture/doc.go", "// Package fixture supplies registry test data.\npackage fixture\n")
	writeFixture(t, root, "fixture_test.go", "package fixture_test\nimport tst \"testing\"\nfunc TestPresent(t *tst.T) {}\n")

	return []byte(`{
		"schema_version":4,"reviewed_on":"2026-10-22","scope":"Test fixture","stage":"experimental","completeness":"Partial normative inventory",
		"documents":[{"id":"standard","title":"Standard","edition":"Published edition","source":"https://example.test/standard","errata":{"sources":[],"review":"reviewed","reviewed_on":"2026-10-22","items":[],"notes":"No published corrections in this fixture."}}],
		"profiles":[{"id":"profile","title":"Selected profile","role":"verifier","modes":["verify"],"claim":"restricted","inventory":"partial","documents":["standard"],"scope_ids":["supported"],"package_docs":["fixture/doc.go"],"gap":"Inventory remains partial.","closure":"Map all applicable clauses.","matrix":[{"document":"standard","modes":["verify"],"requirements":["norm"],"unmapped_clauses":["3.3: additional verifier rules"],"reason":"Selected verifier duties.","closure":"Assess section 3.3."}]}],
		"requirements":[{"id":"supported","title":"Supported capability","status":"implemented","tests":["fixture_test.go"]},{"id":"unimplemented","title":"Open capability","status":"unimplemented","tests":[]}],
		"normative_requirements":[{
			"id":"norm","statement":"Validate the input.","norm":{"document":"standard","clause":"3.2","source":"https://example.test/standard#verify","level":"MUST","errata":[]},
			"applies":{"profile":"profile","role":"verifier","mode":"verify","status":"applicable","reason":"Required for the selected verifier role."},
			"implementation":{"status":"implemented","apis":["fixture.Apply"],"code":["fixture/api.go"]},
			"tests":{"status":"covered","reason":"Exact local fixture cases.","positive":[{"file":"fixture_test.go","name":"TestPresent"}],"negative":[{"file":"fixture_test.go","name":"TestPresent"}]},
			"interop":{"status":"pending","tests":[],"fixtures":[],"reason":"Independent fixture pending."},
			"policy":{"default":{"status":"enabled","reason":"Within the default profile."},"compatibility":{"status":"not-applicable","reason":"No separate compatibility mode."}},
			"gap":"Independent evidence pending.","closure":"Add an independent positive/negative pair."
		}]
	}`)
}

func writeFixture(t *testing.T, root, name, text string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Proof events come from configured go test -json runs. Requiring a matching
// source and register digest prevents a successful old run from closing new work.
type languageProofRun struct {
	SourceSHA256   string               `json:"source_sha256"`
	RegisterSHA256 string               `json:"register_sha256"`
	Events         []languageProofEvent `json:"events"`
	index          map[string]languageProofStatus
}

type languageProofStatus struct {
	passed      bool
	invalid     string
	oracles     map[string]struct{}
	diagnostics map[string]struct{}
	vectors     map[string]struct{}
}

func (r *languageProofRun) passed(check conformanceTest) error {
	if r.index == nil {
		r.index = make(map[string]languageProofStatus)
		for _, event := range r.Events {
			if event.Package != "github.com/skarm/xmlsec" && !strings.HasPrefix(event.Package, "github.com/skarm/xmlsec/") {
				continue
			}
			directory := strings.TrimPrefix(event.Package, "github.com/skarm/xmlsec/")
			if event.Package == "github.com/skarm/xmlsec" {
				directory = "."
			}
			key := directory + "\x00" + event.Test
			switch event.Action {
			case "pass":
				state := r.index[key]
				state.passed = true
				r.index[key] = state
			case "output":
				// An ancestor cannot borrow an unrelated descendant's oracle or vector.
				state := r.index[key]
				state.recordOutput(event.Output)
				r.index[key] = state
			case "skip", "fail":
				// A group with any omitted or failing descendant cannot be cited as passed.
				for name := event.Test; name != ""; {
					key = directory + "\x00" + name
					state := r.index[key]
					state.invalid = event.Action + " at " + event.Test
					r.index[key] = state
					index := strings.LastIndex(name, "/")
					if index < 0 {
						break
					}
					name = name[:index]
				}
			}
		}
	}
	name := check.Name + "/" + check.Case
	key := filepath.ToSlash(filepath.Dir(check.File)) + "\x00" + name
	state := r.index[key]
	if state.invalid != "" {
		return fmt.Errorf("%s has %s", name, state.invalid)
	}
	if !state.passed {
		return fmt.Errorf("no successful execution of %s in %s", name, check.File)
	}
	return nil
}

func (s *languageProofStatus) recordOutput(output string) {
	for _, marker := range []string{"P3_ORACLE ", "P3_DIAGNOSTIC ", "P3_VECTOR "} {
		_, tail, found := strings.Cut(output, marker)
		if !found {
			continue
		}
		if marker == "P3_VECTOR " {
			var expected string
			if err := json.Unmarshal([]byte(strings.TrimSpace(tail)), &expected); err == nil {
				if s.vectors == nil {
					s.vectors = make(map[string]struct{})
				}
				s.vectors[expected] = struct{}{}
			}
			continue
		}
		fields := strings.Fields(tail)
		if len(fields) == 0 {
			continue
		}
		if marker == "P3_ORACLE " {
			if s.oracles == nil {
				s.oracles = make(map[string]struct{})
			}
			s.oracles[fields[0]] = struct{}{}
		} else {
			if s.diagnostics == nil {
				s.diagnostics = make(map[string]struct{})
			}
			s.diagnostics[fields[0]] = struct{}{}
		}
	}
}

func (r *languageProofRun) independent(proof normativeProof) error {
	if err := r.passed(proof.Check); err != nil {
		return err
	}
	key := filepath.ToSlash(filepath.Dir(proof.Check.File)) + "\x00" + proof.Check.Name + "/" + proof.Check.Case
	state := r.index[key]
	if proof.Oracle == "published-vector" || proof.Oracle == "published-inventory" {
		if proof.Expected == nil {
			return fmt.Errorf("%s/%s has no published fixture value", proof.Check.Name, proof.Check.Case)
		}
		if _, exists := state.vectors[*proof.Expected]; !exists {
			return fmt.Errorf("%s/%s does not verify published fixture value %q", proof.Check.Name, proof.Check.Case, *proof.Expected)
		}
		return nil
	}
	if _, exists := state.oracles[proof.Oracle]; !exists {
		return fmt.Errorf("%s/%s has no exact %s agreement; diagnostics cannot close independent evidence", proof.Check.Name, proof.Check.Case, proof.Oracle)
	}
	if _, exists := state.diagnostics[proof.Oracle]; exists {
		return fmt.Errorf("%s/%s has no exact %s agreement; diagnostics cannot close independent evidence", proof.Check.Name, proof.Check.Case, proof.Oracle)
	}
	return nil
}

func languageProofPassed(events []languageProofEvent, check conformanceTest) error {
	run := languageProofRun{Events: events}
	return run.passed(check)
}

func TestLanguageProofEvents(t *testing.T) {
	wantTrue := "true"
	check := conformanceTest{File: "transform/xpath_test.go", Name: "TestXPath", Case: "numeric/overflow"}
	pass := languageProofEvent{Package: "github.com/skarm/xmlsec/transform", Test: "TestXPath/numeric/overflow", Action: "pass"}
	for _, tc := range []struct {
		name   string
		events []languageProofEvent
		valid  bool
	}{
		{"exact pass", []languageProofEvent{pass}, true},
		{"missing", nil, false},
		{"parent only", []languageProofEvent{{Package: pass.Package, Test: "TestXPath/numeric", Action: "pass"}}, false},
		{"different package", []languageProofEvent{{Package: "other/transform/internal/xpath", Test: pass.Test, Action: "pass"}}, false},
		{"skip below passing parent", []languageProofEvent{pass, {Package: pass.Package, Test: pass.Test + "/control", Action: "skip"}}, false},
		{"failed rerun", []languageProofEvent{pass, {Package: pass.Package, Test: pass.Test, Action: "fail"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := languageProofPassed(tc.events, check); (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		name     string
		oracle   string
		output   string
		expected string
		valid    bool
	}{
		{"processor requires actual marker", "saxon-12.10", "", "", false},
		{"exact processor agreement", "saxon-12.10", "P3_ORACLE saxon-12.10", "", true},
		{"wrong processor edition", "saxon-9.4", "P3_ORACLE saxon-12.10", "", false},
		{"diagnostic is not agreement", "saxon-12.10", "P3_ORACLE saxon-12.10\nP3_DIAGNOSTIC saxon-12.10", "", false},
		{"literal published vector", "published-vector", `P3_VECTOR "true"`, "true", true},
		{"wrong published vector", "published-vector", `P3_VECTOR "true"`, "false", false},
		{"unmarked published vector", "published-vector", "", "true", false},
		{"empty published vector", "published-vector", `P3_VECTOR ""`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := languageProofRun{Events: []languageProofEvent{pass, {Package: pass.Package, Test: pass.Test, Action: "output", Output: tc.output}}}
			err := run.independent(normativeProof{Check: check, Oracle: tc.oracle, Expected: &tc.expected})
			if (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
	for _, oracle := range []string{"saxon-12.10", "published-vector"} {
		t.Run("descendant marker cannot close ancestor "+oracle, func(t *testing.T) {
			run := languageProofRun{Events: []languageProofEvent{pass, {Package: pass.Package, Test: pass.Test + "/unrelated", Action: "pass"}, {Package: pass.Package, Test: pass.Test + "/unrelated", Action: "output", Output: `P3_ORACLE saxon-12.10`}, {Package: pass.Package, Test: pass.Test + "/unrelated", Action: "output", Output: `P3_VECTOR "true"`}}}
			if err := run.independent(normativeProof{Check: check, Oracle: oracle, Expected: &wantTrue}); err == nil {
				t.Fatal("borrowed unrelated child marker")
			}
		})
	}
}

func languageEvidenceInputs(t *testing.T) (string, conformanceRegister, languageProofRun) {
	t.Helper()
	ledgerPath := residualRequired(t, "XMLSEC_P3_TEST_EVENTS")
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "conformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var register conformanceRegister
	if err := json.Unmarshal(raw, &register); err != nil {
		t.Fatal(err)
	}
	_, problems, err := checkConformanceRegister(root, raw)
	if err := errors.Join(append(problems, err)...); err != nil {
		t.Fatal(err)
	}
	var artifact languageProofArtifact
	if err := readLanguageProofFile(ledgerPath, &artifact); err != nil {
		t.Fatal(err)
	}
	digest, err := suiteSourceDigest(t.Context(), root)
	stamp := languageProofStamp{SourceSHA256: digest, RegisterSHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	events, artifactErr := artifact.validate(stamp)
	if err != nil || artifactErr != nil {
		t.Fatal("proof events do not belong to completed runs of the current sources and register", err, artifactErr)
	}
	run := languageProofRun{SourceSHA256: stamp.SourceSHA256, RegisterSHA256: stamp.RegisterSHA256, Events: events}
	t.Cleanup(func() {
		current, err := suiteSourceDigest(context.WithoutCancel(t.Context()), root)
		currentRegister, readErr := os.ReadFile(filepath.Join(root, "docs", "conformance.json"))
		if err != nil || readErr != nil || current != digest || run.RegisterSHA256 != fmt.Sprintf("%x", sha256.Sum256(currentRegister)) {
			t.Error("sources or register changed during evidence verification", err, readErr)
		}
	})
	return root, register, run
}

func TestLanguageProofArtifacts(t *testing.T) {
	stamp := languageProofStamp{SourceSHA256: "current-source", RegisterSHA256: "current-register"}
	const module = "github.com/skarm/xmlsec/transform"
	valid := func() languageProofStream {
		return languageProofStream{SchemaVersion: 1, Before: stamp, After: stamp, ExitCode: 0, Arguments: []string{"test", "-json", "-count=1", "./transform"}, Events: []languageProofEvent{
			{Package: module, Action: "start"},
			{Package: module, Test: "TestExact/required", Action: "output", Output: "P3_ORACLE saxon-12.10"},
			{Package: module, Test: "TestExact/required", Action: "pass"},
			{Package: module, Action: "pass"},
		}}
	}
	for _, test := range []struct {
		name   string
		mutate func(*languageProofStream)
	}{
		{"stale source before restamp", func(s *languageProofStream) { s.Before.SourceSHA256 = "old-source" }},
		{"source changed during test", func(s *languageProofStream) { s.After.SourceSHA256 = "different-source" }},
		{"register changed during test", func(s *languageProofStream) { s.After.RegisterSHA256 = "different-register" }},
		{"failed process with partial passes", func(s *languageProofStream) { s.ExitCode = 1 }},
		{"malformed process JSON", func(s *languageProofStream) { s.DecodeError = "invalid character after completed package" }},
		{"truncated process with partial passes", func(s *languageProofStream) { s.Events = s.Events[:len(s.Events)-1] }},
		{"unstarted package", func(s *languageProofStream) { s.Events = s.Events[1:] }},
		{"failed sibling", func(s *languageProofStream) {
			s.Events = append(s.Events, languageProofEvent{Package: module, Test: "TestOther", Action: "fail"})
		}},
		{"failed package", func(s *languageProofStream) { s.Events[len(s.Events)-1].Action = "fail" }},
		{"failed build", func(s *languageProofStream) {
			s.Events = append(s.Events, languageProofEvent{Package: module, Action: "build-fail"})
		}},
		{"missing JSON invocation", func(s *languageProofStream) { s.Arguments[1] = "-v" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := valid()
			test.mutate(&bad)
			// A fresh envelope cannot repair an old or incomplete inner run.
			artifact := languageProofArtifact{SchemaVersion: 1, Stamp: stamp, Streams: []languageProofStream{valid(), bad}}
			if _, err := artifact.validate(stamp); err == nil {
				t.Fatal("invalid captured stream accepted")
			}
		})
	}
	artifact := languageProofArtifact{SchemaVersion: 1, Stamp: stamp, Streams: []languageProofStream{valid()}}
	events, err := artifact.validate(stamp)
	if err != nil || len(events) != len(valid().Events) {
		t.Fatal("complete source-bound capture rejected", events, err)
	}
	file := filepath.Join(t.TempDir(), "old-envelope.json")
	if err := os.WriteFile(file, []byte(`{"source_sha256":"current-source","register_sha256":"current-register","events":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readLanguageProofFile(file, &artifact); err == nil {
		t.Fatal("legacy restampable envelope accepted")
	}
}

func TestLanguageProofCaptureAndMerge(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "go.mod", "module example.test/proof\n\ngo 1.27.0\n")
	writeFixture(t, root, "docs/conformance.json", `{}`)
	writeFixture(t, root, "proof_test.go", "package proof\nimport (\"testing\"; \"os\")\nfunc TestCaptured(t *testing.T) { t.Log(`P3_VECTOR \"fixture\"`) }\nfunc TestRejected(t *testing.T) { t.Fatal(\"deliberate failure\") }\nfunc TestChangesSource(t *testing.T) { if err := os.WriteFile(\"created.go\", []byte(\"package proof\\n\"), 0600); err != nil {t.Fatal(err)} }\n")
	if output, err := exec.CommandContext(t.Context(), "git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	directory := t.TempDir()
	capture, merged := filepath.Join(directory, "capture.json"), filepath.Join(directory, "merged.json")
	var out bytes.Buffer
	if err := runLanguageProof(t.Context(), root, []string{"capture", "-out", capture, "--", "-run=^TestCaptured$", "./..."}, &out, &out); err != nil {
		t.Fatal(out.String(), err)
	}
	if err := runLanguageProof(t.Context(), root, []string{"merge", "-out", merged, capture}, &out, &out); err != nil {
		t.Fatal(out.String(), err)
	}
	var artifact languageProofArtifact
	if err := readLanguageProofFile(merged, &artifact); err != nil || len(artifact.Streams) != 1 {
		t.Fatal(artifact, err)
	}
	original, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "hardlink", "directory-alias"} {
		t.Run(kind, func(t *testing.T) {
			alias := filepath.Join(directory, kind)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(capture, alias)
			case "hardlink":
				err = os.Link(capture, alias)
			case "directory-alias":
				err = os.Symlink(directory, alias)
				alias = filepath.Join(alias, filepath.Base(capture))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := runLanguageProof(t.Context(), root, []string{"merge", "-out", alias, capture}, &out, &out); err == nil || !strings.Contains(err.Error(), "must differ") {
				t.Fatal("aliased capture input accepted as destination", err)
			}
			actual, err := os.ReadFile(capture)
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("aliased destination destroyed capture input", err)
			}
		})
	}
	parent := filepath.Join(directory, "physical")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	physicalInput := filepath.Join(parent, "capture.json")
	if err := os.WriteFile(physicalInput, original, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "parent-link")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	// Keep the raw .. component: filepath.Join would erase the alias being tested.
	rawAlias := link + string(filepath.Separator) + ".." + string(filepath.Separator) + "capture.json"
	identityInput := physicalInput
	rawInfo, err := os.Stat(rawAlias)
	if err != nil {
		t.Fatal(err)
	}
	physicalInfo, err := os.Stat(physicalInput)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(rawInfo, physicalInfo) {
		// Some platforms normalize .. before traversing the link. Validate the
		// actual identity used by their file operations, without skipping it.
		baseInfo, err := os.Stat(capture)
		if err != nil || !os.SameFile(rawInfo, baseInfo) {
			t.Fatal("unexpected symlink/.. resolution", err)
		}
		identityInput = capture
	}
	for _, pair := range [][2]string{{rawAlias, identityInput}, {identityInput, rawAlias}} {
		if err := runLanguageProof(t.Context(), root, []string{"merge", "-out", pair[0], pair[1]}, &out, &out); err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Fatal("symlink/.. alias accepted", err)
		}
		actual, err := os.ReadFile(physicalInput)
		if err != nil || !bytes.Equal(actual, original) {
			t.Fatal("symlink/.. alias destroyed capture input", err)
		}
		actual, err = os.ReadFile(capture)
		if err != nil || !bytes.Equal(actual, original) {
			t.Fatal("symlink/.. alias destroyed base capture", err)
		}
	}
	if err := runLanguageProof(t.Context(), root, []string{"capture", "-out", capture, "--", "-run=^TestRejected$", "./..."}, &out, &out); err == nil {
		t.Fatal("failing Go process accepted as a proof capture")
	}
	if err := runLanguageProof(t.Context(), root, []string{"merge", "-out", merged, capture}, &out, &out); err == nil {
		t.Fatal("failing capture merged as successful evidence")
	}
	writeFixture(t, root, "docs/conformance.json", `{"changed":true}`)
	var old languageProofStream
	if err := readLanguageProofFile(capture, &old); err != nil {
		t.Fatal(err)
	}
	stamp, err := currentLanguageProofStamp(t.Context(), root)
	if err != nil || old.Before.RegisterSHA256 == stamp.RegisterSHA256 {
		t.Fatal("register stamp did not bind actual bytes", old, stamp, err)
	}
	if err := writeLanguageProofFile(capture, artifact.Streams[0]); err != nil {
		t.Fatal(err)
	}
	if err := runLanguageProof(t.Context(), root, []string{"merge", "-out", merged, capture}, &out, &out); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatal("old register capture was restamped during merge", err)
	}
	if err := runLanguageProof(t.Context(), root, []string{"capture", "-out", capture, "--", "-run=^TestChangesSource$", "./..."}, &out, &out); err == nil || !strings.Contains(err.Error(), "changed source") {
		t.Fatal("source mutation during an otherwise passing process accepted", err)
	}
}

func TestResidualFailureConditions(t *testing.T) {
	const selected = "xslt30/2.0/1.0/default/true/false"
	evidence := residualEvidence{Disposition: "fixture", Failures: []residualFailureCondition{{Profile: selected, Kind: "assertion", ErrorCodes: []string{"XTSE0080"}, Cause: "execution-error", Signature: "reserved namespace in template name"}}}
	for _, test := range []struct {
		name    string
		profile string
		kind    string
		code    string
		cause   string
		want    bool
	}{
		{"same proven profile and typed cause", selected, "assertion", "XTSE0080", "execution-error", true},
		{"new failure in passing edition", "xslt30/3.0/1.0/default/true/false", "assertion", "XTSE0080", "execution-error", false},
		{"new panic in known fixture", selected, "panic", "", "assertion-mismatch", false},
		{"new harness failure", selected, "harness", "", "harness-error", false},
		{"different standard error", selected, "assertion", "XTSE0650", "execution-error", false},
		{"different failure phase", selected, "assertion", "XTSE0080", "assertion-error", false},
		{"lost typed error", selected, "assertion", "", "execution-error", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual := suiteOutcome{Status: suiteFailed, Kind: test.kind, ErrorCode: test.code, FailureCause: test.cause, FailureSignature: "reserved namespace in template name"}
			for _, disposition := range []string{"fixture", "environment"} {
				candidate := evidence
				candidate.Disposition = disposition
				if got := residualFailureMatches(candidate, test.profile, actual); got != test.want {
					t.Fatal(disposition, got, test.want)
				}
			}
		})
	}
	for _, disposition := range []string{"fixture", "environment"} {
		candidate := evidence
		candidate.Disposition = disposition
		if residualFailureMatches(candidate, selected, suiteOutcome{Kind: "assertion", ErrorCode: "XTSE0080", FailureCause: "execution-error", FailureSignature: "a different reserved namespace argument"}) {
			t.Fatal(disposition, "same code from a different argument-dependent failure inherited the old cause")
		}
	}
	resource := residualEvidence{Disposition: suiteResourceLimit, Failures: []residualFailureCondition{{Profile: selected, Kind: suiteResourceLimit, ErrorCodes: []string{"", "XPDY0130"}, Cause: "resource-bound"}}}
	for _, code := range []string{"", "XPDY0130"} {
		if !residualFailureMatches(resource, selected, suiteOutcome{Kind: suiteResourceLimit, ErrorCode: code, FailureCause: "resource-bound"}) {
			t.Fatal("deadline and typed implementation limits must not depend on timing", code)
		}
	}
}

// File confinement uses physical roots, including when /tmp or the explicit
// checkout directory is a symlink on the calling platform.
func languageProofDirectory(t *testing.T, variable string) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(residualRequired(t, variable))
	if err == nil {
		directory, err = filepath.Abs(directory)
	}
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestLanguageNormativeEvidence(t *testing.T) {
	root, register, run := languageEvidenceInputs(t)
	pinsData, err := os.ReadFile(filepath.Join(root, "build", "w3c-suites.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins map[string]suitePin
	if err := json.Unmarshal(pinsData, &pins); err != nil {
		t.Fatal(err)
	}
	loaded := make(map[string]suiteCase)
	catalogs := make(map[string]*suiteNode)
	verified := make(map[string]string)
	results := make(map[string]suiteOutcome)
	for _, r := range register.Normative {
		if !languageVerificationDocument(r.Norm.Document) || r.Applies.Status == normNotApplicable {
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			checks := make(map[string]string)
			for _, evidence := range r.Evidence {
				for _, proofs := range [][]normativeProof{evidence.Positive, evidence.Negative} {
					for _, bundled := range proofs {
						for _, proof := range expandNormativeProof(r.ID, bundled) {
							if proof.Catalog == nil {
								if err := run.independent(proof); err != nil {
									t.Error(evidence.Obligation, err)
								}
								continue
							}
							p := *proof.Catalog
							identity := catalogProofIdentity(p)
							if previous, exists := checks[p.Name]; exists {
								if previous != identity {
									t.Fatal("ambiguous publisher witness identity", previous, p)
								}
								continue
							}
							checks[p.Name] = identity
							t.Run(p.Name, func(t *testing.T) {
								directory := verified[p.Suite]
								if directory == "" {
									env := "XMLSEC_QT3_DIR"
									if p.Suite == "xslt30" {
										env = "XMLSEC_XSLT_DIR"
									}
									directory = languageProofDirectory(t, env)
									if err := verifySuiteCheckout(t.Context(), directory, pins[p.Suite]); err != nil {
										t.Fatal(err)
									}
									verified[p.Suite] = directory
									catalog, _, err := readSuiteNode(directory, directory, pins[p.Suite].Catalog)
									if err != nil {
										t.Fatal(err)
									}
									catalogs[p.Suite] = catalog
								}
								outcome, ok := results[identity]
								if !ok {
									key := strings.Join([]string{p.Suite, p.File, p.Name}, "\x00")
									item, exists := loaded[key]
									if !exists {
										for _, candidate := range loadLanguageEvidenceCases(t, directory, pins[p.Suite], p, catalogs[p.Suite]) {
											loaded[strings.Join([]string{p.Suite, p.File, candidate.node.attr("name")}, "\x00")] = candidate
										}
										item, exists = loaded[key]
										if !exists {
											t.Fatal("missing publisher witness", p)
										}
									}
									options := suiteOptions{
										kind: p.Suite, directory: directory, version: p.Version, xsdVersion: p.XSDVersion,
										limitsProfile: "default", xsltAssertions: true, timeout: time.Second,
										currentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), setMatch: regexp.MustCompile(".*"), caseMatch: regexp.MustCompile(".*"),
									}
									outcome = executeSuiteCase(t.Context(), options, item, suiteOutcome{Set: item.set, File: p.File, Name: p.Name})
									results[identity] = outcome
								}
								if outcome.Status != suitePassed {
									t.Fatal("publisher witness did not pass", outcome)
								}
							})
						}
					}
				}
			}
		})
	}
	for kind, directory := range verified {
		if err := verifySuiteCheckout(t.Context(), directory, pins[kind]); err != nil {
			t.Fatal(err)
		}
	}
}

func loadLanguageEvidenceCases(t *testing.T, directory string, pin suitePin, p catalogProof, catalog *suiteNode) []suiteCase {
	t.Helper()
	set, path, err := readSuiteNode(directory, directory, p.File)
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, entry := range catalog.children("test-set") {
		listed = listed || entry.attr("file") == p.File
	}
	if !listed || catalog.XMLName.Space != pin.Namespace || set.XMLName.Space != pin.Namespace {
		t.Fatal("proof file is not in the pinned publisher catalog", p.File)
	}
	environments := suiteEnvironments(set, filepath.Dir(path), suiteEnvironments(catalog, directory, nil))
	cases := make([]suiteCase, 0, len(set.children("test-case")))
	for _, node := range set.children("test-case") {
		cases = append(cases, suiteCase{set: set.attr("name"), file: p.File, base: filepath.Dir(path), setNode: set, node: node, environments: environments})
	}
	return cases
}

// Every visible failure in the thirteen complete profile/control runs must
// resolve to a passing causal check. A new failure cannot inherit a category
// merely because its explanatory text resembles an already reviewed case.
func TestLanguageResidualCoverage(t *testing.T) {
	root, register, run := languageEvidenceInputs(t)
	pinsData, err := os.ReadFile(filepath.Join(root, "build", "w3c-suites.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins map[string]suitePin
	if err := json.Unmarshal(pinsData, &pins); err != nil {
		t.Fatal(err)
	}
	inventories := make(map[string]map[string]struct{})
	for kind, env := range map[string]string{suiteQT3: "XMLSEC_QT3_DIR", suiteXSLT: "XMLSEC_XSLT_DIR"} {
		directory := languageProofDirectory(t, env)
		if err := verifySuiteCheckout(t.Context(), directory, pins[kind]); err != nil {
			t.Fatal(err)
		}
		inventories[kind] = languageCatalogInventory(t, directory, pins[kind])
	}
	reports := filepath.SplitList(residualRequired(t, "XMLSEC_P3_SUITE_REPORTS"))
	entries := make(map[string]residualEvidence)
	for _, evidence := range register.Residual {
		key := evidence.Suite + "/" + evidence.File + "/" + evidence.Name
		entries[key] = evidence
		for _, check := range evidence.Checks {
			if err := run.passed(check); err != nil {
				t.Error(key, err)
			}
		}
	}
	profiles := map[string]struct{}{}
	for _, key := range languageProofProfileKeys() {
		profiles[key] = struct{}{}
	}
	failures := make(map[string]struct{})
	for _, file := range reports {
		raw, err := os.ReadFile(file) // #nosec G304 -- Explicit developer-selected suite report, not a publisher resource URI.
		if err != nil {
			t.Fatal(err)
		}
		var report suiteReport
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		settings := report.Settings
		profile := fmt.Sprintf("%s/%s/%s/%s/%v/%v", report.Suite, report.Language, settings["xsd_version"], settings["limits_profile"], settings["xslt_assertions"], settings["xpath_1_0_compatibility"])
		if _, known := profiles[profile]; !known {
			t.Fatal("unexpected or duplicate profile report", profile)
		}
		delete(profiles, profile)
		if report.SourceSHA256 != run.SourceSHA256 {
			t.Fatal("suite report has stale source evidence", file)
		}
		if report.Pin != pins[report.Suite] {
			t.Fatal("suite report uses a different publisher pin", file)
		}
		inventory := inventories[report.Suite]
		count := len(inventory)
		if len(report.Cases) != count || report.Totals[suiteSkipped] != 0 || settings["case_limit"] != float64(0) || settings["case_timeout"] != "1s" {
			t.Fatal("proof requires the complete pinned catalog without skipped cases", file)
		}
		for setting, want := range map[string]any{
			"current_time": suiteDefaultCurrentTime, "implicit_timezone": "UTC", "default_language": "en", "default_collation": "Unicode codepoint",
			"network": false, "schema_aware": false, "w3c_streaming": false, "allow_single_byte_encodings": true, "set_pattern": ".*", "case_pattern": ".*",
		} {
			if settings[setting] != want {
				t.Fatal("suite report has different proof context", file, setting, settings[setting], want)
			}
		}
		if !languageProofSetting(settings["limits"], suiteLimits(suiteOptions{limitsProfile: fmt.Sprint(settings["limits_profile"])})) {
			t.Fatal("suite report has different resource bounds", file)
		}
		seenCases := make(map[string]struct{})
		totals := map[string]int{suitePassed: 0, suiteFailed: 0, suiteSkipped: 0, suiteNotApplicable: 0}
		for _, item := range report.Cases {
			identity := item.File + "/" + item.Name
			if _, exists := inventory[identity]; !exists {
				t.Fatal("missing, foreign or duplicate publisher case", file, identity)
			}
			if _, exists := seenCases[identity]; exists {
				t.Fatal("missing, foreign or duplicate publisher case", file, identity)
			}
			seenCases[identity] = struct{}{}
			if _, known := totals[item.Status]; !known {
				t.Fatal("unknown case outcome", file, item.Status)
			}
			totals[item.Status]++
			if item.Status != suiteFailed {
				continue
			}
			key := report.Suite + "/" + item.File + "/" + item.Name
			failures[key] = struct{}{}
			evidence, ok := entries[key]
			if !ok || !residualFailureMatches(evidence, profile, item) {
				t.Error("unproved residual failure", profile, key, item.Kind, item.Reason)
			}
		}
		for status, count := range totals {
			if report.Totals[status] != count {
				t.Fatal("suite totals disagree with actual case outcomes", file, status)
			}
		}
		if len(totals) != len(report.Totals) {
			t.Fatal("unknown suite total status", file)
		}
	}
	for key := range profiles {
		t.Error("required complete suite profile is missing", key)
	}
	for key, evidence := range entries {
		if _, exists := failures[key]; !exists && evidence.Disposition != "fixed" {
			t.Error("obsolete retained-failure disposition; verify and record its regression", key)
		}
	}
}

func residualFailureMatches(evidence residualEvidence, profile string, item suiteOutcome) bool {
	if evidence.Disposition == "fixed" || item.Kind == "panic" {
		return false
	}
	return slices.ContainsFunc(evidence.Failures, func(condition residualFailureCondition) bool {
		return condition.Profile == profile && condition.Kind == item.Kind && condition.Cause == item.FailureCause && condition.Signature == item.FailureSignature && slices.Contains(condition.ErrorCodes, item.ErrorCode)
	})
}

func languageProofSetting[T comparable](value any, want T) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	var actual T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&actual) == nil && actual == want
}

func languageCatalogInventory(t *testing.T, directory string, pin suitePin) map[string]struct{} {
	t.Helper()
	catalog, _, err := readSuiteNode(directory, directory, pin.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	inventory := make(map[string]struct{})
	for _, entry := range catalog.children("test-set") {
		set, _, err := readSuiteReferencedNode(directory, directory, entry)
		if err != nil {
			t.Fatal(err)
		}
		for _, node := range set.children("test-case") {
			key := entry.attr("file") + "/" + node.attr("name")
			if _, exists := inventory[key]; exists {
				t.Fatal("duplicate original catalog identity", key)
			}
			inventory[key] = struct{}{}
		}
	}
	return inventory
}

// Appendix D is a documentation duty: another processor need not choose the
// same host defaults. This checklist transcribes its eight REC 2.0 items and
// fourteen REC 3.0/3.1 items; it does not compare incompatible host APIs.
func TestXPathPublishedHostChoiceInventory(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "transforms.md"))
	if err != nil {
		t.Fatal(err)
	}
	choices := []struct {
		name   string
		modern bool
	}{
		{"unicode-version", false},
		{"known-collations", false},
		{"implicit-timezone", false},
		{"warnings", false},
		{"error-transport", false},
		{"xml-names-editions", false},
		{"namespace-axis", false},
		{"static-typing", false},
		{"non-infoset-construction", true},
		{"schema-type-system", true},
		{"extension-signatures", true},
		{"environment-variables", true},
		{"serialization-parameters", true},
		{"external-result-mismatch", true},
	}
	for _, version := range []string{"20", "30", "31"} {
		for _, choice := range choices {
			if version == "20" && choice.modern {
				continue
			}
			t.Run(version+"/"+choice.name, func(t *testing.T) {
				t.Run("documented", func(t *testing.T) {
					declarations := xpathHostChoiceDeclarations(version)
					if declarations[choice.name] == "" {
						t.Fatal("published inventory row omitted", choice.name)
					}
					if err := checkXPathHostChoiceDocumentation(string(raw), version); err != nil {
						t.Fatal(err)
					}
					t.Log(`P3_VECTOR "documented"`)
				})
				t.Run("omission", func(t *testing.T) {
					// Keep every other choice; this item's omission must remain
					// observable rather than inheriting an unrelated declaration.
					declaration := xpathHostChoiceDeclarations(version)[choice.name]
					mutant := strings.ReplaceAll(string(raw), declaration, "")
					if err := checkXPathHostChoiceDocumentation(mutant, version); err == nil || !strings.Contains(err.Error(), choice.name) {
						t.Fatal("omitted published item accepted", choice.name, err)
					}
					t.Log(`P3_VECTOR "omission rejected"`)
				})
			})
		}
	}
}
