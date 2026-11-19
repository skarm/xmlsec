package testutil_test

import (
	"crypto/fips140"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil"
)

func TestRunFIPSTestExecutesAssertionsWithStrictEnforcement(t *testing.T) {
	const receiptEnv = "XMLSEC_TEST_FIPS_RECEIPT"
	if fips140.Enforced() {
		if !testutil.RunFIPSTest(t) {
			t.Fatal("RunFIPSTest skipped local assertions with strict enforcement")
		}
		if receipt := os.Getenv(receiptEnv); receipt != "" {
			if err := os.WriteFile(receipt, []byte("executed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return
	}

	receipt := filepath.Join(t.TempDir(), "fips-result")
	t.Setenv(receiptEnv, receipt)
	if testutil.RunFIPSTest(t) {
		t.Fatal("RunFIPSTest requested local assertions without strict enforcement")
	}
	got, err := os.ReadFile(receipt)
	if err != nil || string(got) != "executed" {
		t.Fatalf("FIPS child receipt = %q, %v, want %q", got, err, "executed")
	}
}
