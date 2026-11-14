package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestVerifyInvoiceRequiresExpectedRoot(t *testing.T) {
	var scalar [32]byte
	scalar[len(scalar)-1] = 1
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		xml     string
		wantErr error
	}{
		{name: "invoice", xml: `<Invoice xmlns="urn:example:invoice" ID="invoice-1"/>`},
		{name: "other namespace", xml: `<Invoice xmlns="urn:example:other" ID="invoice-1"/>`, wantErr: xmldsig.ErrPolicy},
		{name: "other local name", xml: `<Receipt xmlns="urn:example:invoice" ID="invoice-1"/>`, wantErr: xmldsig.ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := document.Parse(t.Context(), []byte(tc.xml), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			signed, err := xmldsig.SignEnveloped(t.Context(), doc, key, xmldsig.SignOptions{})
			if err != nil {
				t.Fatal(err)
			}

			result, err := verifyInvoice(t.Context(), signed, key.Public())
			if tc.wantErr != nil {
				if result != nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("verifyInvoice returned (%v, %v), want (nil, %v)", result, err, tc.wantErr)
				}

				return
			}

			if err != nil || result == nil {
				t.Fatalf("verifyInvoice returned (%v, %v), want a verified invoice", result, err)
			}

			refs := result.References()
			if len(refs) != 1 || refs[0].URI() != "#invoice-1" {
				t.Errorf("references = %+v, want only #invoice-1", refs)
			}
		})
	}
}

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// Verified 1 reference(s), method http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
	// #invoice-1: digest=3ce9b9d07165b4d7a4c24b693ec57334f4e55cd6fbace63132601b06df0b986e, bytes=100
}
