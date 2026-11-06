package protocol_test

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestHoKCertificateMatchingForm(t *testing.T) {
	c := testcert.New(t)
	valid := `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(c.Leaf.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
	other := strings.Replace(valid, base64.StdEncoding.EncodeToString(c.Leaf.Raw), base64.StdEncoding.EncodeToString(c.TSA.Raw), 1)
	for _, test := range []struct {
		name, content string
		accept        bool
	}{
		{"exact", valid, true},
		{"alternative KeyInfo", other + valid, true},
		{"different certificate", other, false},
		{"no certificate", `<ds:KeyInfo><ds:X509Data><ds:X509SKI>AQID</ds:X509SKI></ds:X509Data></ds:KeyInfo>`, false},
		{"CRL forbidden", strings.Replace(valid, `</ds:X509Data>`, `<ds:X509CRL>AQID</ds:X509CRL></ds:X509Data>`, 1), false},
		{"multiple X509Data forbidden", strings.Replace(valid, `</ds:KeyInfo>`, `<ds:X509Data/></ds:KeyInfo>`, 1), false},
		{"bare key forbidden", `<ds:KeyInfo><ds:KeyValue/></ds:KeyInfo>`, false},
		{"unknown extension with certificate", strings.Replace(valid, `</ds:X509Data>`, `<ext:Optional xmlns:ext="urn:test"/></ds:X509Data>`, 1), true},
		{"XML base64 whitespace", strings.Replace(valid, base64.StdEncoding.EncodeToString(c.Leaf.Raw), "\n "+base64.StdEncoding.EncodeToString(c.Leaf.Raw)+"\t\r", 1), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, err := document.Parse(t.Context(), []byte(`<saml:SubjectConfirmationData xmlns:saml="`+protocol.AssertionNamespace+`" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+test.content+`</saml:SubjectConfirmationData>`), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if err := protocol.MatchConfirmationCertificate(d.Root(), c.Leaf.Raw); (err == nil) != test.accept {
				t.Fatalf("match=%v, want=%v", err, test.accept)
			}
		})
	}
}

// Re-sign malformed semantic controls, so rejection cannot be attributed to a
// broken cryptographic signature or to using our producer as the only parser.
func TestHoKConfirmationConditions(t *testing.T) {
	c := testcert.New(t)
	spec := responseSpec()
	spec.Assertion.HolderOfKeyCertificate = c.TSA.Raw
	d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*tree.Node)
		accept bool
	}{
		{"valid", func(*tree.Node) {}, true},
		{"alternative confirmation", func(root *tree.Node) {
			conf := find(root, "SubjectConfirmation")
			// Import from the unchanged source; descendants are borrowed
			// read-only until resign reparses the private draft.
			alternative := tree.ImportSubtree(find(tree.Root(d), "SubjectConfirmation"))
			alternative.Parent = conf.Parent
			conf.Parent.Children = append(conf.Parent.Children, alternative)
			set(find(conf, "SubjectConfirmationData"), "Recipient", "https://other.test/acs")
		}, true},
		{"recipient", func(root *tree.Node) {
			set(find(root, "SubjectConfirmationData"), "Recipient", "https://attacker.test/acs")
		}, false},
		{"request", func(root *tree.Node) { set(find(root, "SubjectConfirmationData"), "InResponseTo", "_wrong") }, false},
		{"expired", func(root *tree.Node) {
			set(find(root, "SubjectConfirmationData"), "NotOnOrAfter", spec.IssueInstant.Add(-time.Second).Format(time.RFC3339Nano))
		}, false},
		{"future", func(root *tree.Node) {
			set(find(root, "SubjectConfirmationData"), "NotBefore", spec.IssueInstant.Add(time.Minute).Format(time.RFC3339Nano))
		}, false},
		{"address mismatch", func(root *tree.Node) { set(find(root, "SubjectConfirmationData"), "Address", "192.0.2.8") }, false},
		{"address match", func(root *tree.Node) { set(find(root, "SubjectConfirmationData"), "Address", "192.0.2.9") }, true},
		{"wrong xsi type", func(root *tree.Node) {
			data := find(root, "SubjectConfirmationData")
			for i := range data.Attrs {
				if data.Attrs[i].Name.Local == "type" {
					data.Attrs[i].Value = "saml:SubjectConfirmationDataType"
				}
			}
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := resign(t, d, c, test.mutate)
			envelope, err := binding.WrapSOAP(t.Context(), changed)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := proof.SignCS01CompatXML(t.Context(), envelope, proof.Signing{Key: c.TSAKey, Certificate: c.TSA.Raw})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := signed.XML(t.Context())
			p, err := proof.VerifyCS01CompatXML(t.Context(), raw, proof.Options{})
			if err != nil {
				t.Fatal(err)
			}
			body, err := p.Payload(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			o := options()
			o.Proof = p
			o.RequireHolderOfKey = true
			o.ExpectedAddress = "192.0.2.9"
			result, err := protocol.VerifyResponse(t.Context(), body, []crypto.PublicKey{c.LeafKey.Public()}, o)
			if (err == nil) != test.accept {
				t.Fatalf("verify=%v, want=%v", err, test.accept)
			}
			if test.accept && !bytes.Equal(result.HolderOfKeyCertificate(), c.TSA.Raw) {
				t.Fatal("wrong certificate")
			}
			if _, err := protocol.VerifyResponse(t.Context(), changed, []crypto.PublicKey{c.LeafKey.Public()}, o); err == nil {
				t.Fatal("proof transferred to another payload snapshot")
			}
		})
	}
	if _, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, options()); err == nil {
		t.Fatal("HoK accepted without proof")
	}
	bearerSpec := responseSpec()
	bearer, err := protocol.SignResponse(t.Context(), bearerSpec, protocol.SigningKey{Key: c.LeafKey})
	if err != nil {
		t.Fatal(err)
	}
	o := options()
	o.RequireHolderOfKey = true
	if _, err := protocol.VerifyResponse(t.Context(), bearer, []crypto.PublicKey{c.LeafKey.Public()}, o); err == nil {
		t.Fatal("bearer downgrade accepted")
	}
}
