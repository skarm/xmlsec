package tests_test

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/skarm/xmlsec/cms"
	_ "github.com/skarm/xmlsec/keyinfo"
	_ "github.com/skarm/xmlsec/keys"
	_ "github.com/skarm/xmlsec/pki"
	_ "github.com/skarm/xmlsec/resource"
	_ "github.com/skarm/xmlsec/saml/idp"
	_ "github.com/skarm/xmlsec/saml/metadata"
	_ "github.com/skarm/xmlsec/saml/replay"
	_ "github.com/skarm/xmlsec/saml/sp"
	_ "github.com/skarm/xmlsec/saml/state"
	_ "github.com/skarm/xmlsec/timestamp"
	_ "github.com/skarm/xmlsec/transform" // Compile the public transformation API in the parent build.
	_ "github.com/skarm/xmlsec/xades"
	_ "github.com/skarm/xmlsec/xmldsig"
	_ "github.com/skarm/xmlsec/xmlenc"
)

// TestExternalConsumer runs a different module outside the repository. It cannot
// import the library's internal packages or accidentally depend on CLI helpers.
func TestExternalConsumer(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	// Subprocess reads are not inputs to the parent test's cache. Record the
	// library sources here as well, so implementation-only changes rerun the
	// external module instead of reusing a stale successful result.
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") || entry.Name() == "go.mod" || entry.Name() == "go.sum" {
			_, err = os.ReadFile(path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	files, err := os.ReadDir(filepath.Join("testdata", "consumer"))
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join("testdata", "consumer", file.Name()))
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, file.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	timeout := 2 * time.Minute
	if consumerRace {
		// Race instrumentation and full collections make memory regressions
		// substantially slower than the ordinary external-module checks.
		timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	testArgs := []string{"test", "-mod=readonly", "-count=1"}
	if consumerRace {
		testArgs = append(testArgs, "-race")
	}

	testArgs = append(testArgs, "./...")
	for _, args := range [][]string{{"mod", "edit", "-replace=github.com/skarm/xmlsec=" + root}, testArgs} {
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = dir

		cmd.Env = append(os.Environ(), "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("external consumer: %v\n%s", err, output)
		}
	}
}
