package keys_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
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

func TestPKCS12ExportASN1Limits(t *testing.T) {
	t.Parallel()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := testcert.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PFX test certificate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	single := keys.PKCS12Identity{PrivateKey: key, Certificate: testcert.Issue(t, template, template, key.Public(), key)}
	if _, err := keys.ParseCertificate(single.Certificate.Raw, keys.Limits{MaxASN1Nodes: 27}); err != nil {
		t.Fatalf("the certificate itself must fit below the AuthenticatedSafe node limit: %v", err)
	}

	multiple := single
	for serial := int64(2); serial <= 4; serial++ {
		extraKey := testcert.Key(t)
		template.SerialNumber = big.NewInt(serial)
		multiple.ExtraCertificates = append(multiple.ExtraCertificates, testcert.Issue(t, template, template, extraKey.Public(), extraKey))
	}

	password := []byte("bounded storage password")
	for _, tc := range []struct {
		name     string
		identity keys.PKCS12Identity
		limits   keys.Limits
		want     error
	}{
		{"depth_below_authenticated_safe", single, keys.Limits{MaxASN1Depth: 10}, keys.ErrLimit},
		{"nodes_below_authenticated_safe", single, keys.Limits{MaxASN1Nodes: 27}, keys.ErrLimit},
		{"exact_authenticated_safe", single, keys.Limits{MaxASN1Depth: 11, MaxASN1Nodes: 28}, nil},
		{"nodes_below_certificate_safe", multiple, keys.Limits{MaxASN1Nodes: 33}, keys.ErrLimit},
		{"exact_certificate_safe", multiple, keys.Limits{MaxASN1Depth: 11, MaxASN1Nodes: 34}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for _, classic := range []bool{false, true} {
				var output bytes.Buffer
				options := keys.PKCS12Options{ClassicMAC: classic, Encryption: protection(crypto.SHA256, 256)}
				n, err := keys.WritePKCS12(t.Context(), &output, tc.identity, password, options, tc.limits)
				if tc.want != nil {
					if n != 0 || output.Len() != 0 || !errors.Is(err, tc.want) {
						t.Fatalf("export with ClassicMAC=%t = %d bytes, %v; want no output and %v", classic, n, err, tc.want)
					}
					continue
				}
				if n == 0 || n != int64(output.Len()) || err != nil {
					t.Fatalf("export with ClassicMAC=%t = %d bytes, %v; want a complete PFX", classic, n, err)
				}
				parsed, err := keys.ParsePKCS12(t.Context(), output.Bytes(), password, tc.limits)
				if err != nil || parsed == nil || !bytes.Equal(parsed.Certificate.Raw, tc.identity.Certificate.Raw) || len(parsed.ExtraCertificates) != len(tc.identity.ExtraCertificates) {
					t.Fatalf("export with ClassicMAC=%t at exact bounds did not import with matching limits: %v", classic, err)
				}
			}
		})
	}
}

func TestPKCS12DERDefaultIteration(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	identity := keys.PKCS12Identity{PrivateKey: chain.LeafKey, Certificate: chain.Leaf}
	password := []byte("canonical DER fixture password")
	limits := keys.Limits{MinIterations: 1}

	for _, classic := range []bool{true, false} {
		for _, tc := range []struct {
			iterations int
			macFields  int
		}{{iterations: 1, macFields: 2}, {iterations: 2, macFields: 3}} {
			options := keys.PKCS12Options{ClassicMAC: classic, Encryption: keys.EncryptionOptions{Iterations: tc.iterations}}
			raw, err := keys.MarshalPKCS12(t.Context(), identity, password, options, limits)
			if err != nil {
				t.Fatal(err)
			}

			mac := privateFields(t, privateFields(t, raw)[2])
			if len(mac) != tc.macFields {
				t.Errorf("ClassicMAC=%t iterations=%d has %d MacData fields, want %d", classic, tc.iterations, len(mac), tc.macFields)
			} else if len(mac) == 3 && !bytes.Equal(mac[2], der.Int(tc.iterations)) {
				t.Errorf("ClassicMAC=%t iterations=%d encoded a different count: %x", classic, tc.iterations, mac[2])
			}

			decoded, err := keys.ParsePKCS12(t.Context(), raw, password, limits)
			if err != nil || decoded == nil || !bytes.Equal(decoded.Certificate.Raw, chain.Leaf.Raw) {
				t.Errorf("ClassicMAC=%t iterations=%d failed round trip: %v", classic, tc.iterations, err)
			}
		}
	}
}
