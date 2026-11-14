package historical //nolint:testpackage // Exercises internal material reliability checks.

import (
	"crypto"
	"crypto/x509"
	"testing"
)

func TestCMSAlgorithmMapsAuthenticatedSignatureIdentifiers(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		oid  string
		hash crypto.Hash
		want x509.SignatureAlgorithm
	}{
		{"1.2.840.113549.1.1.11", crypto.SHA256, x509.SHA256WithRSA},
		{"1.2.840.113549.1.1.12", crypto.SHA384, x509.SHA384WithRSA},
		{"1.2.840.113549.1.1.13", crypto.SHA512, x509.SHA512WithRSA},
		{"1.2.840.10045.4.3.2", crypto.SHA256, x509.ECDSAWithSHA256},
		{"1.2.840.10045.4.3.3", crypto.SHA384, x509.ECDSAWithSHA384},
		{"1.2.840.10045.4.3.4", crypto.SHA512, x509.ECDSAWithSHA512},
		{"1.2.840.113549.1.1.10", crypto.SHA256, x509.SHA256WithRSAPSS},
		{"1.2.840.113549.1.1.10", crypto.SHA384, x509.SHA384WithRSAPSS},
		{"1.2.840.113549.1.1.10", crypto.SHA512, x509.SHA512WithRSAPSS},
		{"1.2.840.113549.1.1.10", crypto.SHA1, x509.UnknownSignatureAlgorithm},
		{"1.3.101.112", 0, x509.PureEd25519},
		{"1.2.3", crypto.SHA256, x509.UnknownSignatureAlgorithm},
	} {
		if got := cmsAlgorithm(test.oid, test.hash); got != test.want {
			t.Fatalf("CMS algorithm %s/%v = %v; want %v", test.oid, test.hash, got, test.want)
		}
	}
}
