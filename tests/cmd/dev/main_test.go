package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDocumentationChecks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	writeFixture(t, root, "file with spaces.md", "target\n")
	writeFixture(t, root, "fixture_test.go", "package fixture\n")

	register := `{"requirements":[{"id":"supported","tests":["fixture_test.go"]},{"id":"unimplemented","tests":[]}]}`
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
