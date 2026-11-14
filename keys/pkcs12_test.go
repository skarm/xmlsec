package keys_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keys"
)

func TestWritePKCS12ReportsBytesAcceptedByDestination(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	identity := keys.PKCS12Identity{PrivateKey: chain.LeafKey, Certificate: chain.Leaf}
	failure := errors.New("destination failed")
	for _, tc := range []struct {
		name       string
		writeError error
		wantError  error
	}{
		{"destination_error", failure, failure},
		{"short_write", nil, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			writer := &pfxPrefixWriter{err: tc.writeError}
			n, err := keys.WritePKCS12(t.Context(), writer, identity, []byte("fixture password"), keys.PKCS12Options{Encryption: protection(crypto.SHA256, 256)}, keys.Limits{})
			if n != 1 || !errors.Is(err, tc.wantError) || writer.Len() != 1 || writer.Bytes()[0] != 0x30 {
				t.Errorf("WritePKCS12 = (%d, %v), emitted %x, want one DER sequence byte and %v", n, err, writer.Bytes(), tc.wantError)
			}
		})
	}
}

type pfxPrefixWriter struct {
	bytes.Buffer
	err error
}

func (w *pfxPrefixWriter) Write(p []byte) (int, error) {
	if w.Len() != 0 || len(p) == 0 {
		return 0, w.err
	}
	_ = w.WriteByte(p[0])
	return 1, w.err
}

func TestMarshalPKCS12RejectsDuplicateAndMismatchedCertificates(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	for _, tc := range []struct {
		name   string
		cert   *x509.Certificate
		extras []*x509.Certificate
	}{
		{"duplicate_leaf", chain.Leaf, []*x509.Certificate{chain.Leaf}},
		{"wrong_leaf", chain.TSA, []*x509.Certificate{chain.Leaf}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			identity := keys.PKCS12Identity{PrivateKey: chain.LeafKey, Certificate: tc.cert, ExtraCertificates: tc.extras}
			result, err := keys.MarshalPKCS12(t.Context(), identity, []byte("fixture password"), keys.PKCS12Options{Encryption: protection(crypto.SHA256, 256)}, keys.Limits{})
			if result != nil || !errors.Is(err, keys.ErrFormat) {
				t.Errorf("MarshalPKCS12 returned %d bytes and %v, want no bytes and ErrFormat", len(result), err)
			}
		})
	}
}

func TestPKCS12PreflightRejectsIncompatibleOptions(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	identity := keys.PKCS12Identity{PrivateKey: chain.LeafKey, Certificate: chain.Leaf}
	password := []byte("fixture password")
	selection := keys.PKCS12ParseOptions{CertificateSHA256: sha256.Sum256(chain.Leaf.Raw)}
	if got, err := keys.ParsePKCS12Identities(t.Context(), nil, password, selection, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrPolicy) {
		t.Errorf("ParsePKCS12Identities with a selector = (%v, %v), want no identities and ErrPolicy", got, err)
	}
	if got, err := keys.ParsePKCS12(t.Context(), nil, []byte{0xff}, keys.Limits{}); got != nil || !errors.Is(err, keys.ErrPolicy) {
		t.Errorf("ParsePKCS12 with non-UTF-8 password = (%v, %v), want no identity and ErrPolicy", got, err)
	}
	var dst *bytes.Buffer
	if n, err := keys.WritePKCS12(t.Context(), dst, identity, password, keys.PKCS12Options{}, keys.Limits{}); n != 0 || !errors.Is(err, keys.ErrPolicy) {
		t.Errorf("WritePKCS12 with typed nil writer = (%d, %v), want zero bytes and ErrPolicy", n, err)
	}
	var output bytes.Buffer
	if n, err := keys.WritePKCS12(t.Context(), &output, identity, nil, keys.PKCS12Options{}, keys.Limits{}); n != 0 || output.Len() != 0 || !errors.Is(err, keys.ErrPolicy) {
		t.Errorf("WritePKCS12 with empty password = (%d, %v), want zero bytes and ErrPolicy", n, err)
	}
}
