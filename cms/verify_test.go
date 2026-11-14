package cms_test

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestVerifyReaderRetainsAuthenticatedMetadataWithoutContent(t *testing.T) {
	t.Parallel()

	const message = "detached\x00message"
	chain := testcert.New(t)
	raw, err := cms.Sign(t.Context(), []byte(message), []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw, Hash: crypto.SHA384}}, cms.SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.Parse(t.Context(), raw, cms.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	wantOID := cms.DataOID()
	expected := [][]byte{chain.Leaf.Raw}
	options := cms.VerifyOptions{ExpectedContentType: wantOID, RequireCertificateBinding: true}
	result, err := signed.VerifyReader(t.Context(), iotest.OneByteReader(bytes.NewBufferString(message)), expected, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Content() != nil || result.ContentSize() != int64(len(message)) || !result.ContentType().Equal(wantOID) {
		t.Errorf("verified content = %q, %d bytes, type %v", result.Content(), result.ContentSize(), result.ContentType())
	}
	signers := result.Signers()
	if len(signers) != 1 {
		t.Fatalf("verified %d signers, want 1", len(signers))
	}
	signer := signers[0]
	if !signer.CertificateBound() || signer.SignatureHash() != crypto.SHA384 || signer.SignatureAlgorithmOID() != "1.2.840.10045.4.3.3" {
		t.Errorf("unexpected signer metadata: binding=%t, hash=%v, OID=%s", signer.CertificateBound(), signer.SignatureHash(), signer.SignatureAlgorithmOID())
	}
	clear(result.ContentType())
	signers[0] = cms.SignerResult{}
	if !result.ContentType().Equal(wantOID) || !bytes.Equal(result.Signers()[0].CertificateDER(), chain.Leaf.Raw) {
		t.Error("mutating accessor results changed authenticated metadata")
	}
	attrs := signer.SignedAttributes()
	for _, attr := range attrs {
		if attr.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}) {
			return
		}
	}
	t.Error("authenticated attributes lack the message digest")
}

func TestVerifyReaderPreservesStreamError(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	data := []byte("complete message")
	raw, err := cms.Sign(t.Context(), data, []cms.Signer{{Key: chain.LeafKey, CertificateDER: chain.Leaf.Raw}}, cms.SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.Parse(t.Context(), raw, cms.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("source failed after content")
	source := io.MultiReader(bytes.NewReader(data), iotest.ErrReader(failure))
	result, err := signed.VerifyReader(t.Context(), source, [][]byte{chain.Leaf.Raw}, cms.VerifyOptions{ExpectedContentType: cms.DataOID()})
	if result != nil || !errors.Is(err, failure) {
		t.Errorf("VerifyReader = (%v, %v), want no result and the original read error", result, err)
	}
}
