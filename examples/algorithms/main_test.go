package main

import (
	"crypto"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestPSSTemplateUsesExplicitProfile(t *testing.T) {
	const message = "literal <payload>"
	spec := pssTemplate(message)
	if spec.SignatureMethod != xmldsig.RSAPSS {
		t.Errorf("signature method = %q, want %q", spec.SignatureMethod, xmldsig.RSAPSS)
	}

	params := spec.SignatureParameters.PSS
	if params == nil || params.Hash != crypto.SHA384 || params.MGFHash != crypto.SHA384 || params.SaltLength != 24 {
		t.Errorf("PSS parameters = %+v, want SHA-384, MGF1 SHA-384 and a 24-byte salt", params)
	}

	if len(spec.References) != 1 {
		t.Fatalf("reference count = %d, want 1", len(spec.References))
	}

	ref := spec.References[0]
	if ref.URI != "#payload" || len(ref.Transforms) != 1 || ref.Transforms[0].Algorithm != c14n.Exclusive {
		t.Errorf("reference = %+v, want #payload with one exclusive canonicalization transform", ref)
	}

	if len(spec.Objects) != 1 {
		t.Fatalf("object count = %d, want 1", len(spec.Objects))
	}

	obj := spec.Objects[0]
	if obj.ID != "payload" || obj.Text == nil || *obj.Text != message {
		t.Errorf("object = %+v, want ID payload and literal text %q", obj, message)
	}
}

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// RSA-PSS: hash=SHA-384 mgf=SHA-384 salt=24 references=1 container-covered=false
	// HMAC: output-bits=256 references=1 container-covered=false
}
