package testutil

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"regexp"
	"testing"
)

const (
	childSingleRunFlag = "-test.count=1"
	fipsRuntimeOnly    = "fips140=only"
)

const (
	runtimeDebugEnv  = "GODEBUG"
	fipsChildEnv     = "XMLSEC_TEST_FIPS_CHILD"
	fipsChildEnabled = "1"
)

// RunFIPSTest runs the current test in a FIPS-only child when FIPS is disabled.
// It returns true when the caller should execute its FIPS assertions locally;
// false means those assertions already passed in the child process.
func RunFIPSTest(t *testing.T) bool {
	t.Helper()

	if fips140.Enabled() {
		return true
	}

	if os.Getenv(fipsChildEnv) == fipsChildEnabled {
		t.Fatal("FIPS is disabled in the FIPS-only test process")
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	command := exec.CommandContext(t.Context(), executable, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", childSingleRunFlag) // #nosec G204 -- Reruns this test binary and exact test name without a shell.

	command.Env = append(command.Environ(), runtimeDebugEnv+"="+os.Getenv(runtimeDebugEnv)+","+fipsRuntimeOnly, fipsChildEnv+"="+fipsChildEnabled)

	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FIPS-only test failed: %v\n%s", err, output)
	}

	return false
}
