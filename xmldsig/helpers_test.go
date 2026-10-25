package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	programTrueXPath = "true()"
	nameData         = "#data"
	namePayload      = "#payload"
	nameObject       = "Object"
	nameRoot         = "root"
	uriUrnAttachment = "urn:attachment"
	uriUrnData       = "urn:data"
	nameData2        = "data"
)

func parse(t testing.TB, s string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func ecKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	k, e := ecdsa.GenerateKey(curve, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func rsaKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func xmlString(t testing.TB, d *document.Document) string {
	t.Helper()

	b, e := d.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	return string(b)
}

func sign(t testing.TB, k crypto.Signer, d *document.Document, opt xmldsig.SignOptions) *document.Document {
	t.Helper()

	out, e := xmldsig.SignEnveloped(context.Background(), d, k, opt)
	if e != nil {
		t.Fatal(e)
	}

	return out
}

func digestInput(t testing.TB, ref xmldsig.ReferenceResult) []byte {
	t.Helper()

	var output bytes.Buffer

	n, err := ref.WriteDigestInput(t.Context(), &output)
	if err != nil {
		t.Fatal(err)
	}

	if n != int64(output.Len()) {
		t.Fatal("incorrect byte count", n, output.Len())
	}

	return output.Bytes()
}

func findImportElement(t testing.TB, root document.Element, name document.Name) document.Element {
	t.Helper()

	var find func(document.Element) document.Element

	find = func(e document.Element) document.Element {
		if e.Name() == name {
			return e
		}

		for _, child := range e.Children() {
			if found := find(child); found.Valid() {
				return found
			}
		}

		return document.Element{}
	}
	if found := find(root); found.Valid() {
		return found
	}

	t.Fatalf("element %v missing", name)

	return document.Element{}
}

func assertImportedTree(t testing.TB, got, want document.Element) {
	t.Helper()

	if got.Name() != want.Name() || got.Prefix() != want.Prefix() || got.Text() != want.Text() || !reflect.DeepEqual(got.Attributes(), want.Attributes()) {
		t.Fatalf("imported %v (%s) attrs %v, want %v (%s) attrs %v", got.Name(), got.Prefix(), got.Attributes(), want.Name(), want.Prefix(), want.Attributes())
	}

	gc, wc := got.Children(), want.Children()
	if len(gc) != len(wc) {
		t.Fatalf("child counts %d != %d", len(gc), len(wc))
	}

	for i := range gc {
		assertImportedTree(t, gc[i], wc[i])
	}
}

type coreCountSigner struct {
	crypto.Signer
	calls int
}

func (s *coreCountSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(r, d, o)
}
