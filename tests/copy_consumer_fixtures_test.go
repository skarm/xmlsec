package tests_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil"
)

func TestCopyConsumerFixtures(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	fixtures := map[string]string{"go.mod": "module example.test/fixture\n", "data.bin": "\x00\x7f\xff"}
	for name, data := range fixtures {
		testutil.WriteFile(t, src, name, []byte(data))
	}
	nested := filepath.Join(src, "ignored")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, nested, "nested.txt", []byte("nested fixture"))

	if err := copyConsumerFixtures(src, dst); err != nil {
		t.Fatalf("copyConsumerFixtures: %v", err)
	}
	for name, want := range fixtures {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil || string(got) != want {
			t.Errorf("copied %s contains %q, error=%v, want %q", name, got, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "ignored")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("nested directory lookup returned %v, want %v", err, fs.ErrNotExist)
	}
}

func TestCopyConsumerFixturesPropagatesWriteFailure(t *testing.T) {
	src := t.TempDir()
	testutil.WriteFile(t, src, "go.mod", []byte("module example.test/fixture\n"))
	dst := filepath.Join(t.TempDir(), "missing")

	var pathErr *fs.PathError
	if err := copyConsumerFixtures(src, dst); !errors.Is(err, fs.ErrNotExist) || !errors.As(err, &pathErr) || pathErr.Path != filepath.Join(dst, "go.mod") {
		t.Errorf("copyConsumerFixtures to missing destination returned %v, want a missing-file error for the destination fixture", err)
	}
}
