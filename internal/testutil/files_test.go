package testutil_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil"
)

func TestWriteJSONWritesFixture(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := testutil.WriteJSON(t, dir, "data.json", map[string]string{"value": "<é>"})
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"value":"\u003cé\u003e"}` || path != filepath.Join(dir, "data.json") {
		t.Fatalf("JSON fixture at %q = %q, %v", path, raw, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("fixture permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteFileReportsMissingDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "missing")
	err := captureFixtureFatal(t, func(tb testing.TB) {
		testutil.WriteFile(tb, dir, "fixture.txt", []byte("example"))
	})
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || !errors.Is(err, os.ErrNotExist) || pathErr.Path != filepath.Join(dir, "fixture.txt") {
		t.Errorf("WriteFile failed with %v, want missing path %q", err, filepath.Join(dir, "fixture.txt"))
	}
}

func TestWriteJSONReportsUnsupportedFixture(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := captureFixtureFatal(t, func(tb testing.TB) {
		testutil.WriteJSON(tb, dir, "fixture.json", make(chan int))
	})

	var unsupported *json.UnsupportedTypeError
	if !errors.As(err, &unsupported) || unsupported.Type.String() != "chan int" {
		t.Errorf("WriteJSON failed with %v, want an unsupported chan int error", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "fixture.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fixture file stat after failed marshal: %v, want no file", err)
	}
}
