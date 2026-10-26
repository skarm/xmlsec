package keyinfo_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
)

const (
	uriSHA256      = "http://www.w3.org/2001/04/xmlenc#sha256"
	subjectIssuer  = "CN=issuer"
	subjectBounded = "CN=bounded"
	nameChanged    = "changed"
	nameEmpty      = "empty"
	uriUnknown     = "urn:unknown"
)

func TestBuildX509DataIndependentFixtures(t *testing.T) {
	data := make([][]byte, 0, 3)

	for _, name := range []string{"pki-leaf.der", "pki-root.der", "pki-fresh.crl.der"} {
		raw, err := os.ReadFile(filepath.Join("..", "testdata", "next", name))
		if err != nil {
			t.Fatal(err)
		}

		data = append(data, raw)
	}

	// Fixed independent cryptography/lxml corpus. Digest and DN/serial values
	// were also checked using the OpenSSL CLI, not the KeyInfo XML serializer.
	digest, err := hex.DecodeString("8c3c5b72546fd0f7ae49d393ee79eb204b5c6577423718c2e7a8435ddd12fca3")
	if err != nil {
		t.Fatal(err)
	}

	group := keyinfo.X509Data{
		Certificates: data[:2], CRLs: data[2:],
		IssuerSerials: []keyinfo.IssuerSerial{{Issuer: "CN=oracle root", Serial: "2"}}, SubjectNames: []string{"CN=oracle leaf"},
		CertificateDigests: []keyinfo.CertificateDigest{{Algorithm: uriSHA256, Value: digest}},
	}

	doc, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: []keyinfo.X509Data{group}})
	if err != nil {
		t.Fatal(err)
	}

	result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
	if err != nil || len(result.Candidates()) != 2 || len(result.X509Groups()) != 1 {
		t.Fatal("independent group did not parse", err)
	}

	got := result.X509Groups()[0]
	if !bytes.Equal(got.CertificatesDER()[0], data[0]) || !bytes.Equal(got.CertificatesDER()[1], data[1]) || !bytes.Equal(got.CRLsDER()[0], data[2]) || !slices.Equal(got.IssuerSerials(), group.IssuerSerials) || !slices.Equal(got.SubjectNames(), group.SubjectNames) || !bytes.Equal(got.CertificateDigests()[0].Value, digest) {
		t.Fatal("independent DER/selector bytes changed")
	}
}

func TestBuildX509DataGroups(t *testing.T) {
	chain := testcert.New(t)
	crl := testcert.CRL(t, chain, chain.Leaf)
	digest := sha256.Sum256(chain.Leaf.Raw)
	issuer := keyinfo.IssuerSerial{Issuer: chain.Leaf.Issuer.String(), Serial: " \t+000" + chain.Leaf.SerialNumber.String() + "\n"}
	subject := `CN=escaped\, subject & <issuer>`
	group := keyinfo.X509Data{
		Certificates: [][]byte{bytes.Clone(chain.Leaf.Raw), bytes.Clone(chain.Root.Raw)}, CRLs: [][]byte{bytes.Clone(crl)},
		IssuerSerials: []keyinfo.IssuerSerial{issuer}, SubjectNames: []string{chain.Leaf.Subject.String()},
		SubjectKeyIdentifiers: [][]byte{bytes.Clone(chain.Leaf.SubjectKeyId)},
		CertificateDigests:    []keyinfo.CertificateDigest{{Algorithm: uriSHA256, Value: bytes.Clone(digest[:])}},
	}

	doc, err := keyinfo.Build(t.Context(), keyinfo.Template{
		X509Data: []keyinfo.X509Data{group, {SubjectNames: []string{subject}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	before := asXML(t, doc)
	group.Certificates[0][0] ^= 255
	group.CRLs[0][0] ^= 255
	group.SubjectKeyIdentifiers[0][0] ^= 255
	group.CertificateDigests[0].Value[0] ^= 255
	group.IssuerSerials[0].Issuer = nameChanged
	group.SubjectNames[0] = nameChanged

	if asXML(t, doc) != before {
		t.Fatal("Build retained mutable X509Data sources")
	}

	result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
	if err != nil {
		t.Fatal(err)
	}

	groups := result.X509Groups()
	if len(groups) != 2 || len(result.Candidates()) != 2 || len(groups[0].CertificatesDER()) != 2 || len(groups[1].CertificatesDER()) != 0 {
		t.Fatal("certificate/selector grouping changed")
	}

	first := groups[0]
	if !bytes.Equal(first.CertificatesDER()[0], chain.Leaf.Raw) || !bytes.Equal(first.CertificatesDER()[1], chain.Root.Raw) || !bytes.Equal(first.CRLsDER()[0], crl) {
		t.Fatal("DER was changed or re-encoded")
	}

	issuer.Serial = chain.Leaf.SerialNumber.String()
	if !slices.Equal(first.IssuerSerials(), []keyinfo.IssuerSerial{issuer}) || !slices.Equal(first.SubjectNames(), []string{chain.Leaf.Subject.String()}) || !bytes.Equal(first.SubjectKeyIdentifiers()[0], chain.Leaf.SubjectKeyId) || !bytes.Equal(first.CertificateDigests()[0].Value, digest[:]) || !slices.Equal(groups[1].SubjectNames(), []string{subject}) {
		t.Fatal("selectors changed or escaped incorrectly")
	}

	first.CRLsDER()[0][0] ^= 255
	if !bytes.Equal(first.CRLsDER()[0], crl) {
		t.Fatal("CRL accessor exposed retained data")
	}

	selectorOnly, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: []keyinfo.X509Data{{SubjectNames: []string{subject}}}})
	if err != nil {
		t.Fatal(err)
	}

	hints, err := keyinfo.Parse(t.Context(), selectorOnly, selectorOnly.Root(), keyinfo.Options{})
	if err != nil || len(hints.Candidates()) != 0 || len(hints.X509Groups()) != 1 {
		t.Fatal("selector-only group invented a key", err)
	}

	legacy, err := keyinfo.Build(t.Context(), keyinfo.Template{Certificates: [][]byte{chain.Leaf.Raw}, X509Data: []keyinfo.X509Data{{SubjectNames: []string{subject}}}})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := keyinfo.Parse(t.Context(), legacy, legacy.Root(), keyinfo.Options{})
	if err != nil || len(parsed.X509Groups()) != 2 || !bytes.Equal(parsed.X509Groups()[0].CertificatesDER()[0], chain.Leaf.Raw) {
		t.Fatal("legacy certificate group was merged", err)
	}
}

func TestBuildX509DataValidationAndLimits(t *testing.T) {
	large := strings.Repeat("x", 1<<20)
	for _, test := range []struct {
		name  string
		group keyinfo.X509Data
		want  error
	}{
		{nameEmpty, keyinfo.X509Data{}, keyinfo.ErrInput},
		{"certificate", keyinfo.X509Data{Certificates: [][]byte{{1, 2, 3}}}, keyinfo.ErrInput},
		{"CRL", keyinfo.X509Data{CRLs: [][]byte{{1, 2, 3}}}, keyinfo.ErrInput},
		{"empty-SKI", keyinfo.X509Data{SubjectKeyIdentifiers: [][]byte{nil}}, keyinfo.ErrInput},
		{"empty-subject", keyinfo.X509Data{SubjectNames: []string{" \t"}}, keyinfo.ErrInput},
		{"empty-issuer", keyinfo.X509Data{IssuerSerials: []keyinfo.IssuerSerial{{Serial: "1"}}}, keyinfo.ErrInput},
		{"negative-serial", keyinfo.X509Data{IssuerSerials: []keyinfo.IssuerSerial{{Issuer: subjectIssuer, Serial: "-1"}}}, keyinfo.ErrInput},
		{"invalid-serial", keyinfo.X509Data{IssuerSerials: []keyinfo.IssuerSerial{{Issuer: subjectIssuer, Serial: "1.0"}}}, keyinfo.ErrInput},
		{"unknown-digest", keyinfo.X509Data{CertificateDigests: []keyinfo.CertificateDigest{{Algorithm: uriUnknown, Value: []byte{1}}}}, keyinfo.ErrUnsupported},
		{"short-digest", keyinfo.X509Data{CertificateDigests: []keyinfo.CertificateDigest{{Algorithm: uriSHA256, Value: []byte{1}}}}, keyinfo.ErrInput},
		{"too-many-items", keyinfo.X509Data{SubjectNames: make([]string, 33)}, keyinfo.ErrLimit},
		{"large-subject", keyinfo.X509Data{SubjectNames: []string{large + "x"}}, keyinfo.ErrLimit},
		{"large-SKI", keyinfo.X509Data{SubjectKeyIdentifiers: [][]byte{make([]byte, (1<<20)+1)}}, keyinfo.ErrLimit},
		{"large-serial", keyinfo.X509Data{IssuerSerials: []keyinfo.IssuerSerial{{Issuer: subjectIssuer, Serial: large + "x"}}}, keyinfo.ErrLimit},
		{"aggregate-before-DER-parse", keyinfo.X509Data{CRLs: [][]byte{{1, 2, 3}}, SubjectNames: []string{large, large, large, large}}, keyinfo.ErrLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: []keyinfo.X509Data{test.group}})
			if doc != nil || !errors.Is(err, test.want) {
				t.Fatalf("got document=%v error=%v, want %v", doc, err, test.want)
			}
		})
	}
}

func TestBuildX509DataBudgetBoundaries(t *testing.T) {
	large := strings.Repeat("x", 1<<20)

	t.Run("processing-budget", func(t *testing.T) {
		groups := []keyinfo.X509Data{
			{SubjectNames: slices.Repeat([]string{subjectBounded}, 32)},
			{SubjectNames: slices.Repeat([]string{subjectBounded}, 32)},
			{SubjectNames: slices.Repeat([]string{subjectBounded}, 32)},
			{SubjectNames: slices.Repeat([]string{subjectBounded}, 29)},
		}

		doc, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: groups})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{}); err != nil {
			t.Fatal("boundary document exceeds parser budget", err)
		}

		groups[3].SubjectNames = append(groups[3].SubjectNames, "CN=over-budget")
		if doc, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: groups}); doc != nil || !errors.Is(err, keyinfo.ErrLimit) {
			t.Fatal("processing budget not enforced", err)
		}
	})

	t.Run("group-limit", func(t *testing.T) {
		groups := slices.Repeat([]keyinfo.X509Data{{SubjectNames: []string{subjectBounded}}}, 32)
		if _, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: groups}); err != nil {
			t.Fatal(err)
		}

		groups = append(groups, groups[0])
		if doc, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: groups}); doc != nil || !errors.Is(err, keyinfo.ErrLimit) {
			t.Fatal("group limit not enforced", err)
		}
	})

	t.Run("candidate-limit", func(t *testing.T) {
		certificate := cert(t, ec(t, elliptic.P256()))
		template := keyinfo.Template{Certificates: slices.Repeat([][]byte{certificate}, 32)}

		doc, err := keyinfo.Build(t.Context(), template)
		if err != nil {
			t.Fatal(err)
		}

		result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
		if err != nil || len(result.Candidates()) != 32 {
			t.Fatal("candidate boundary did not parse", err)
		}

		template.X509Data = []keyinfo.X509Data{{Certificates: [][]byte{certificate}}}
		if doc, err := keyinfo.Build(t.Context(), template); doc != nil || !errors.Is(err, keyinfo.ErrLimit) {
			t.Fatal("combined candidate limit not enforced", err)
		}
	})

	t.Run("aggregate-byte-boundary", func(t *testing.T) {
		template := keyinfo.Template{X509Data: []keyinfo.X509Data{{SubjectNames: []string{large, large, large, large}}}}

		doc, err := keyinfo.Build(t.Context(), template)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{}); err != nil {
			t.Fatal("aggregate byte boundary did not parse", err)
		}

		template.Names = []string{"x"}
		if doc, err := keyinfo.Build(t.Context(), template); doc != nil || !errors.Is(err, keyinfo.ErrLimit) {
			t.Fatal("aggregate byte limit did not include KeyName", err)
		}
	})
}

func TestBuildX509CertificateDigests(t *testing.T) {
	chain := testcert.New(t)

	digest256, digest384, digest512 := sha256.Sum256(chain.Leaf.Raw), sha512.Sum384(chain.Leaf.Raw), sha512.Sum512(chain.Leaf.Raw)
	for _, digest := range []keyinfo.CertificateDigest{
		{Algorithm: uriSHA256, Value: digest256[:]},
		{Algorithm: "http://www.w3.org/2001/04/xmldsig-more#sha384", Value: digest384[:]},
		{Algorithm: "http://www.w3.org/2001/04/xmlenc#sha512", Value: digest512[:]},
		// Describing a legacy digest is separate from allowing SHA-1 signatures.
		{Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1", Value: make([]byte, 20)},
	} {
		doc, err := keyinfo.Build(t.Context(), keyinfo.Template{X509Data: []keyinfo.X509Data{{CertificateDigests: []keyinfo.CertificateDigest{digest}}}})
		if err != nil {
			t.Fatal(err)
		}

		result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
		if err != nil || len(result.Candidates()) != 0 {
			t.Fatal("digest hint invented a key", err)
		}

		got := result.X509Groups()[0].CertificateDigests()[0]
		if got.Algorithm != digest.Algorithm || !bytes.Equal(got.Value, digest.Value) {
			t.Fatal("digest algorithm/value changed")
		}
	}
}

func TestBuildPolicyAndZeroValues(t *testing.T) {
	k := ec(t, elliptic.P256())
	invalidPoint := k.PublicKey
	invalidPoint.Curve = elliptic.P384()
	oversized := make([]reference.Transform, 64)

	source := make([]byte, 64<<10)
	for i := range oversized {
		oversized[i] = reference.Transform{Algorithm: reference.XSLT, Stylesheet: source}
	}

	for _, test := range []struct {
		name string
		spec keyinfo.Template
		want error
	}{
		{nameEmpty, keyinfo.Template{}, keyinfo.ErrInput},
		{"bad-ID", keyinfo.Template{ID: "bad id", Names: []string{"x"}}, keyinfo.ErrInput},
		{"too-many", keyinfo.Template{Names: make([]string, 33)}, keyinfo.ErrLimit},
		{"nil-key", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: (*rsa.PublicKey)(nil)}}}, keyinfo.ErrKey},
		{"incomplete-EC", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &ecdsa.PublicKey{Curve: elliptic.P256()}}}}, keyinfo.ErrKey},
		{"bad-format", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &k.PublicKey, Format: "unexpected"}}}, keyinfo.ErrPolicy},
		{"invalid-cert", keyinfo.Template{Certificates: [][]byte{{1, 2, 3}}}, keyinfo.ErrInput},
		{"invalid-reference", keyinfo.Template{KeyInfoReferences: []string{"bad%escape"}}, keyinfo.ErrInput},
		{"invalid-retrieval-URI", keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: "bad%escape"}}}, keyinfo.ErrInput},
		{"invalid-retrieval-type", keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: uriUrnKey, Type: uriUnknown}}}, keyinfo.ErrUnsupported},
		{"invalid-retrieval-algorithm", keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: uriUrnKey, Transforms: []reference.Transform{{Algorithm: uriUnknown}}}}}, keyinfo.ErrUnsupported},
		{"invalid-retrieval-parameters", keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: uriUrnKey, Transforms: []reference.Transform{{Algorithm: reference.Base64, XPath: []reference.XPathExpression{{Expression: "true()"}}}}}}}, keyinfo.ErrInput},
		{"too-many-retrievals", keyinfo.Template{RetrievalMethods: make([]keyinfo.RetrievalMethod, 33)}, keyinfo.ErrLimit},
		{"retrieval-source-budget-before-XML-parse", keyinfo.Template{RetrievalMethods: []keyinfo.RetrievalMethod{{URI: uriUrnKey, Transforms: oversized}}}, keyinfo.ErrLimit},
		{"invalid-point", keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &invalidPoint}}}, keyinfo.ErrKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, e := keyinfo.Build(t.Context(), test.spec)
			if d != nil || !errors.Is(e, test.want) {
				t.Fatalf("got %v, want %v", e, test.want)
			}
		})
	}

	if _, e := keyinfo.Build(nil, keyinfo.Template{}); !errors.Is(e, keyinfo.ErrInput) {
		t.Fatal(e)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, e := keyinfo.Build(ctx, keyinfo.Template{Names: []string{"x"}}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}

	var candidate keyinfo.Candidate
	if candidate.Valid() || candidate.Kind() != (document.Name{}) || candidate.FingerprintSHA256() != "" {
		t.Fatal("valid zero candidate")
	}

	if _, e := candidate.PublicKey(); !errors.Is(e, keyinfo.ErrKey) {
		t.Fatal(e)
	}

	if _, e := candidate.Certificate(); !errors.Is(e, keyinfo.ErrKey) {
		t.Fatal(e)
	}

	var r *keyinfo.Result
	if r.Candidates() != nil || r.KeyNames() != nil || r.X509Groups() != nil || r.ExternalURIs() != nil {
		t.Fatal("nil result")
	}
}

func BenchmarkBuildCertificateKeyInfo(b *testing.B) {
	key := ec(b, elliptic.P256())
	template := keyinfo.Template{Certificates: [][]byte{cert(b, key)}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := keyinfo.Build(b.Context(), template); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCertificateEncodingConsistency(t *testing.T) {
	chain := testcert.New(t)
	for _, test := range testcert.CertificateEncodings(t, chain) {
		t.Run(test.Name, func(t *testing.T) {
			before := bytes.Clone(test.DER)
			built, err := keyinfo.Build(t.Context(), keyinfo.Template{Certificates: [][]byte{test.DER}})
			if test.Valid {
				if err != nil || built == nil {
					t.Fatal(built, err)
				}
			} else if built != nil || !errors.Is(err, keyinfo.ErrInput) {
				t.Fatal("builder accepted invalid DER", err)
			}
			wire := `<ds:KeyInfo xmlns:ds="` + keyinfo.Namespace + `"><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(test.DER) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
			doc, err := document.Parse(t.Context(), []byte(wire), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
			if !test.Valid {
				if result != nil || !errors.Is(err, keyinfo.ErrInput) {
					t.Fatal("parser accepted invalid DER", err)
				}
				return
			}
			if err != nil || len(result.Candidates()) != 1 {
				t.Fatal(result, err)
			}
			candidate := result.Candidates()[0]
			certificate, err := candidate.Certificate()
			if err != nil || !bytes.Equal(certificate.Raw, test.DER) || certificate.CheckSignatureFrom(chain.Root) != nil {
				t.Fatal("certificate snapshot lost original DER/signature", err)
			}
			certificate.Raw[0] ^= 1
			fresh, err := candidate.Certificate()
			if err != nil || !bytes.Equal(fresh.Raw, test.DER) || !bytes.Equal(test.DER, before) {
				t.Fatal("certificate snapshot aliases caller", err)
			}
		})
	}
}

func TestCertificateSnapshotPreservesConfiguredBlobLimit(t *testing.T) {
	chain := testcert.New(t)
	large := *chain.Leaf
	large.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: bytes.Repeat([]byte{0x42}, 1536<<10)}}
	raw, err := x509.CreateCertificate(rand.Reader, &large, chain.Root, chain.LeafKey.Public(), chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 1<<20 {
		t.Fatal("fixture did not exceed default blob cap")
	}
	wire := `<ds:KeyInfo xmlns:ds="` + keyinfo.Namespace + `"><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
	doc, err := document.Parse(t.Context(), []byte(wire), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{}); result != nil || !errors.Is(err, keyinfo.ErrLimit) {
		t.Fatal("default blob cap was ignored", err)
	}
	result, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: 2 << 20}})
	if err != nil || len(result.Candidates()) != 1 {
		t.Fatal(result, err)
	}
	certificate, err := result.Candidates()[0].Certificate()
	if err != nil || !bytes.Equal(certificate.Raw, raw) {
		t.Fatal("snapshot imposed a smaller byte cap", err)
	}
}
