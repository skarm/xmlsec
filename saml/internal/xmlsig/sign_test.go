package xmlsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestSignCoversOnlySelectedTarget(t *testing.T) {
	key := testcert.Key(t)

	doc, err := document.Parse(t.Context(), []byte(`<Envelope><Request ID="_request"><Issuer>urn:issuer</Issuer><Value>signed</Value></Request><Other ID="_other"/></Envelope>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	target := doc.Root().Children()[0]

	signed, err := xmlsig.Sign(t.Context(), doc, target, xmlsig.SigningKey{Key: key, Method: xmldsig.ECDSASHA256}, false)
	if err != nil {
		t.Fatal(err)
	}

	if len(xmldsig.Signatures(doc)) != 0 {
		t.Fatal("original document mutated")
	}

	result, err := xmlsig.Verify(t.Context(), signed, signed.Root().Children()[0], []crypto.PublicKey{key.Public()}, xmldsig.Policy{})
	if err != nil {
		t.Fatal(err)
	}

	if !result.CoversElement(signed.Root().Children()[0]) || result.CoversElement(signed.Root()) {
		t.Fatal("signature target coverage expanded")
	}

	if _, err := xmlsig.Verify(t.Context(), signed, signed.Root().Children()[0], []crypto.PublicKey{testcert.Key(t).Public()}, xmldsig.Policy{}); err == nil {
		t.Fatal("untrusted key accepted")
	}
}

func TestCloneKeysAndPolicyOwnTheirInputs(t *testing.T) {
	key := testcert.Key(t)

	keys, err := xmlsig.CloneKeys([]crypto.PublicKey{key.Public()})
	if err != nil {
		t.Fatal(err)
	}

	cloned, ok := keys[0].(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected key type %T", keys[0])
	}

	if cloned == &key.PublicKey || !cloned.Equal(key.Public()) {
		t.Fatal("key not copied")
	}

	policy := xmldsig.DefaultPolicy()
	clonedPolicy := xmlsig.ClonePolicy(policy)

	clonedPolicy.AllowedSignatureMethods[0] = "changed"
	if policy.AllowedSignatureMethods[0] == "changed" {
		t.Fatal("policy shares slice storage")
	}

	for _, input := range [][]crypto.PublicKey{nil, {nil}, make([]crypto.PublicKey, 17)} {
		if _, err := xmlsig.CloneKeys(input); !errors.Is(err, xmlsig.ErrSignature) {
			t.Fatalf("invalid key set: %v", err)
		}
	}
}
