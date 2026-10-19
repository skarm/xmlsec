package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// WriteFile writes a fixture into an existing directory and returns its path.
func WriteFile(t testing.TB, dir, name string, contents []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// WriteJSON marshals a fixture and writes it into an existing directory.
func WriteJSON(t testing.TB, dir, name string, value any) string {
	t.Helper()

	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return WriteFile(t, dir, name, contents)
}
