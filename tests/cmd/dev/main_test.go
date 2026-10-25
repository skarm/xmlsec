package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		name, want string
		mutate     func(*conformanceRegister)
	}{
		{"duplicate capability", "duplicate capability", func(r *conformanceRegister) { r.Requirements[1].ID = r.Requirements[0].ID }},
		{"duplicate norm", "duplicate normative", func(r *conformanceRegister) { r.Normative = append(r.Normative, r.Normative[0]) }},
		{"duplicate document", "duplicate document", func(r *conformanceRegister) { r.Documents = append(r.Documents, r.Documents[0]) }},
		{"unknown clause source", "document association", func(r *conformanceRegister) { r.Normative[0].Norm.Document = "unknown" }},
		{"invented normative level", "unknown state", func(r *conformanceRegister) { r.Normative[0].Norm.Level = "probably-required" }},
		{"missing clause", "missing required description", func(r *conformanceRegister) { r.Normative[0].Norm.Clause = "" }},
		{"wrong mode", "mode is not part", func(r *conformanceRegister) { r.Normative[0].Applies.Mode = "historical" }},
		{"missing code", "missing/nonportable file", func(r *conformanceRegister) { r.Normative[0].Implementation.Code[0] = "missing.go" }},
		{"directory as evidence", "regular file", func(r *conformanceRegister) { r.Normative[0].Implementation.Code[0] = "fixture" }},
		{"unknown API", "missing exported API", func(r *conformanceRegister) { r.Normative[0].Implementation.APIs[0] = "fixture.Missing" }},
		{"renamed test", "missing test", func(r *conformanceRegister) { r.Normative[0].Tests.Positive[0].Name = "TestMissing" }},
		{"missing negative case", "positive/negative tests", func(r *conformanceRegister) { r.Normative[0].Tests.Negative = nil }},
		{"unsupported policy grant", "policy cannot enable", func(r *conformanceRegister) { r.Normative[0].Implementation.Status = "unimplemented" }},
		{"policy is not implementation", "unknown state", func(r *conformanceRegister) { r.Normative[0].Implementation.Status = "forbidden-by-policy" }},
		{"unsupported mandatory is applicable", "non-applicability requires a different standard role", func(r *conformanceRegister) {
			r.Normative[0].Applies.Status = normNotApplicable
			r.Normative[0].Implementation.Status = normNotApplicable
		}},
		{"unexplained gap", "missing required description", func(r *conformanceRegister) { r.Normative[0].Closure = "" }},
		{"unsupported full claim", "full claim requires a complete inventory", func(r *conformanceRegister) { r.Profiles[0].Claim = conformanceFull }},
		{"unreviewed errata", "full claim requires reviewed errata", func(r *conformanceRegister) {
			r.Profiles[0].Claim, r.Profiles[0].Inventory, r.Profiles[0].Gap = conformanceFull, "complete", ""
			r.Documents[0].Errata.Review = "pending"
		}},
		{"unclosed obligation", "open obligation", func(r *conformanceRegister) {
			r.Profiles[0].Claim, r.Profiles[0].Inventory, r.Profiles[0].Gap = conformanceFull, "complete", ""
		}},
		{"invented interop evidence", "independent fixtures", func(r *conformanceRegister) { r.Normative[0].Interop.Status = "covered" }},
		{"missing schema", "schema 2", func(r *conformanceRegister) { r.SchemaVersion = 0 }},
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

func conformanceFixture(t *testing.T, root string) []byte {
	t.Helper()
	writeFixture(t, root, "fixture/api.go", "package fixture\nfunc Apply() {}\n")
	writeFixture(t, root, "fixture/doc.go", "// Package fixture supplies registry test data.\npackage fixture\n")
	writeFixture(t, root, "fixture_test.go", "package fixture_test\nimport tst \"testing\"\nfunc TestPresent(t *tst.T) {}\n")

	return []byte(`{
		"schema_version":2,"reviewed_on":"2026-10-22","scope":"Test fixture","stage":"experimental","completeness":"Partial normative inventory",
		"documents":[{"id":"standard","title":"Standard","edition":"Published edition","source":"https://example.test/standard","errata":{"sources":[],"review":"reviewed","notes":"No published corrections in this fixture."}}],
		"profiles":[{"id":"profile","title":"Selected profile","role":"verifier","modes":["verify"],"claim":"restricted","inventory":"partial","documents":["standard"],"scope_ids":["supported"],"package_docs":["fixture/doc.go"],"gap":"Inventory remains partial.","closure":"Map all applicable clauses."}],
		"requirements":[{"id":"supported","title":"Supported capability","status":"implemented","tests":["fixture_test.go"]},{"id":"unimplemented","title":"Open capability","status":"unimplemented","tests":[]}],
		"normative_requirements":[{
			"id":"norm","statement":"Validate the input.","norm":{"document":"standard","clause":"3.2","level":"MUST","errata":[]},
			"applies":{"profile":"profile","role":"verifier","mode":"verify","status":"applicable","reason":"Required for the selected verifier role."},
			"implementation":{"status":"implemented","apis":["fixture.Apply"],"code":["fixture/api.go"]},
			"tests":{"positive":[{"file":"fixture_test.go","name":"TestPresent"}],"negative":[{"file":"fixture_test.go","name":"TestPresent"}]},
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
