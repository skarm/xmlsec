//go:build interop

package interop_test

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

// xmlsec1 computes both signatures, session keys and ciphertext independently.
// Generated templates specify algorithms, never expected digest/cipher values.
func TestXMLSecEncryptedSAML(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	signer := generateKey(t, t.TempDir(), nameRSASHA256)
	recipient := generateKey(t, fixture.work, nameRSASHA256)
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	spec := protocol.Response{
		ID: "_response", Issuer: "https://idp.example/entity", Audience: "https://sp.example/entity", Destination: "https://sp.example/acs", InResponseTo: "_request", IssueInstant: at,
		Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice", NotBefore: at.Add(-time.Minute), NotOnOrAfter: at.Add(time.Minute), AuthnInstant: at.Add(-time.Minute), AuthnContext: "urn:test:password", Attributes: []protocol.Attribute{{Name: "role", Values: []string{"reader"}}}},
	}
	key := protocol.SigningKey{Key: signer.signer}
	for _, data := range []xmlenc.RSAOptions{{DataAlgorithm: xmlenc.AES128GCM}, {DataAlgorithm: xmlenc.AES128CBC, AllowLegacy: true, KeyTransportAlgorithm: xmlenc.RSA15}} {
		verification := xmldsig.Policy{}
		if data.AllowLegacy {
			verification = xmldsig.LegacyVerificationPolicy()
			key.Policy = verification
			key.Policy.AllowLegacySigning = true
			key.SignatureMethod, key.DigestMethod, key.Canonicalization = xmldsig.RSASHA1, xmldsig.SHA1, c14n.Canonical10
		}
		for targets := protocol.EncryptionTargets(1); targets < 8; targets++ {
			t.Run(fmt.Sprintf("%s/%d", data.DataAlgorithm, targets), func(t *testing.T) {
				spec.Encryption = &protocol.EncryptionOptions{Targets: targets, Recipient: recipient.signer.Public().(*rsa.PublicKey), Data: data}
				ours, err := protocol.SignResponse(t.Context(), spec, key)
				if err != nil {
					t.Fatal(err)
				}
				// Native verification authenticates the original ciphertext.
				ourPath := write(t, filepath.Join(fixture.work, "saml-go.xml"), xmlBytes(t, ours))
				native(t, fixture, true, nameVerify, flagPublicKeyPEM, signer.public, flagIDAttrID, "Response", "--node-xpath", "(/*/*[local-name()='Signature'])[1]", ourPath)
				for i, encrypted := range nodes(tree.Root(ours), enc, nameEncryptedData) {
					output := filepath.Join(t.TempDir(), "saml-decrypted.xml")
					selection := fmt.Sprintf("(//*[local-name()='EncryptedData'])[%d]", i+1)
					native(t, fixture, true, "decrypt", "--privkey-pem", recipient.private, "--node-xpath", selection, flagNativeOutput, output, ourPath)
					plain := xmlDoc(t, read(t, output))
					if encrypted.Parent.Name.Local == "EncryptedAssertion" {
						native(t, fixture, true, nameVerify, flagPublicKeyPEM, signer.public, flagIDAttrID, "Assertion", "--node-xpath", "(//*[local-name()='Assertion']/*[local-name()='Signature'])[1]", output)
					} else {
						checkNativeSAMLField(t, ours, plain, encrypted.Parent, spec.Assertion)
					}
				}
				spec.Encryption = nil
				base, err := protocol.SignResponse(t.Context(), spec, key)
				if err != nil {
					t.Fatal(err)
				}
				// Native encryption of inner fields precedes native assertion
				// signing. Assertion encryption follows it; the envelope is last.
				for _, target := range []struct {
					flag          protocol.EncryptionTargets
					name, wrapper string
				}{{protocol.EncryptNameID, "NameID", "EncryptedID"}, {protocol.EncryptAttributes, "Attribute", "EncryptedAttribute"}} {
					if targets&target.flag != 0 {
						base = encryptNativeSAML(t, fixture, base, target.name, target.wrapper, recipient, data)
					}
				}
				path := write(t, filepath.Join(fixture.work, "saml-native-inner-template.xml"), xmlBytes(t, base))
				signed := filepath.Join(fixture.work, "saml-native-inner.xml")
				native(t, fixture, true, nameSign, "--privkey-pem", signer.private, flagIDAttrID, "Assertion", "--node-xpath", "(//*[local-name()='Assertion']/*[local-name()='Signature'])[1]", flagNativeOutput, signed, path)
				base = xmlDoc(t, read(t, signed))
				if targets&protocol.EncryptAssertion != 0 {
					base = encryptNativeSAML(t, fixture, base, "Assertion", "EncryptedAssertion", recipient, data)
				}
				path = write(t, filepath.Join(fixture.work, "saml-native-outer-template.xml"), xmlBytes(t, base))
				native(t, fixture, true, nameSign, "--privkey-pem", signer.private, flagIDAttrID, "Response", "--node-xpath", "(/*/*[local-name()='Signature'])[1]", flagNativeOutput, signed, path)
				base = xmlDoc(t, read(t, signed))
				result, err := protocol.VerifyResponse(t.Context(), base, []crypto.PublicKey{signer.signer.Public()}, protocol.ResponseOptions{Issuer: spec.Issuer, Audience: spec.Audience, Destination: spec.Destination, ExpectedRequestID: spec.InResponseTo, At: at, Policy: verification, Decryption: &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient.signer.(*rsa.PrivateKey)}, Data: data}, RequireEncryption: targets})
				if err != nil || result == nil || result.NameID() != "alice" || result.Attributes()[0].Values[0] != "reader" || result.Encryption() != targets {
					t.Fatalf("independent encrypted SAML: %v", err)
				}
			})
		}
	}
}

func checkNativeSAMLField(t *testing.T, encrypted, plain *document.Document, wrapper *tree.Node, expected protocol.AssertionData) {
	t.Helper()

	// xmlsec1 replaces the selected EncryptedData in place, retaining its
	// SAML wrapper and any other independently encrypted or clear fields.
	children := tree.Children(plain)
	var restoredWrapper *tree.Node
	for _, position := range nodePath(wrapper, encrypted) {
		if position < 1 || position > len(children) {
			t.Fatalf("native decryption lost the selected %v wrapper", wrapper.Name)
		}
		restoredWrapper = children[position-1]
		children = restoredWrapper.Children
	}
	if restoredWrapper == nil || restoredWrapper.Name != wrapper.Name || wrapper.Name.Space != protocol.AssertionNamespace {
		t.Fatalf("native decryption changed the selected %v wrapper", wrapper.Name)
	}
	fields := tree.Wrap(plain, restoredWrapper).Children()
	if len(fields) != 1 {
		t.Fatalf("native decryption returned %d field elements inside %v, want one", len(fields), wrapper.Name)
	}

	field := fields[0]
	switch wrapper.Name.Local {
	case "EncryptedID":
		if field.Name() != (document.Name{Space: protocol.AssertionNamespace, Local: "NameID"}) || field.Text() != expected.NameID {
			t.Fatalf("native decryption restored %v with text %q, want NameID %q", field.Name(), field.Text(), expected.NameID)
		}
	case "EncryptedAttribute":
		want := expected.Attributes[0]
		name, _ := field.Attribute(document.Name{Local: "Name"})
		values := field.Children()
		if field.Name() != (document.Name{Space: protocol.AssertionNamespace, Local: "Attribute"}) || name != want.Name || len(values) != len(want.Values) {
			t.Fatalf("native decryption restored %v with Name %q and %d values, want Attribute %q with %d values", field.Name(), name, len(values), want.Name, len(want.Values))
		}
		for i, value := range values {
			if value.Name() != (document.Name{Space: protocol.AssertionNamespace, Local: "AttributeValue"}) || value.Text() != want.Values[i] {
				t.Fatalf("native decryption restored value %d as %v with text %q, want AttributeValue %q", i, value.Name(), value.Text(), want.Values[i])
			}
		}
	default:
		t.Fatalf("unexpected encrypted SAML field wrapper %v", wrapper.Name)
	}
}

func encryptNativeSAML(t *testing.T, fixture *interopFixture, d *document.Document, local, wrapper string, recipient testKey, options xmlenc.RSAOptions) *document.Document {
	t.Helper()
	for {
		candidates := nodes(tree.Root(d), protocol.AssertionNamespace, local)
		if len(candidates) == 0 {
			break
		}
		selected := candidates[0]
		plain := tree.FromNodes([]*tree.Node{tree.ExtractSubtree(selected)}, document.DefaultLimits())
		pattern, err := xmlenc.EncryptDocument(t.Context(), plain, recipient.signer.Public().(*rsa.PublicKey), options)
		if err != nil {
			t.Fatal(err)
		}
		input := write(t, filepath.Join(fixture.work, "saml-native-plaintext.xml"), xmlBytes(t, plain))
		template := write(t, filepath.Join(fixture.work, "saml-native-encryption-template.xml"), clearCipherValues(t, xmlBytes(t, pattern)))
		output := filepath.Join(fixture.work, "saml-native-encrypted.xml")
		native(t, fixture, true, "encrypt", flagPublicKeyPEM, recipient.public, "--session-key", "aes-128", "--xml-data", input, flagNativeOutput, output, template)
		encrypted := xmlDoc(t, read(t, output))
		container := *selected
		container.Name.Local = wrapper
		container.Attrs, container.Children = nil, nil
		container.Children = []*tree.Node{tree.ImportSubtree(tree.Root(encrypted))}
		draft, err := tree.ReplaceDraft(t.Context(), d, selected, &container)
		if err != nil {
			t.Fatal(err)
		}
		d = xmlDoc(t, xmlBytes(t, draft))
	}
	return d
}
