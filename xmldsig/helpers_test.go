package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
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
