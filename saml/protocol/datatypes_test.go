package protocol_test

import (
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestAuthnRequestBooleanLexicalValues(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	for _, attribute := range []string{"ForceAuthn", "IsPassive", "AllowCreate"} {
		for _, test := range []struct {
			name, value string
			valid, want bool
		}{
			{"true literal", "true", true, true},
			{"one with XML whitespace", " &#x9;1&#xD;&#xA; ", true, true},
			{"false with spaces", " false ", true, false},
			{"zero literal", "0", true, false},
			{"empty", "", false, false},
			{"whitespace only", " ", false, false},
			{"uppercase", "TRUE", false, false},
			{"internal whitespace", "tr ue", false, false},
			{"non XML whitespace", "&#xA0;true", false, false},
		} {
			t.Run(attribute+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				attrs := ` ` + attribute + `="` + test.value + `"`
				child := ""
				if attribute == "AllowCreate" {
					child, attrs = `<samlp:NameIDPolicy`+attrs+`/>`, ""
				}
				doc := parseLexicalAuthnRequest(t, attrs, child)
				for _, transport := range []string{"POST", "Redirect"} {
					t.Run(transport, func(t *testing.T) {
						t.Parallel()

						options := protocol.RequestOptions{Issuer: sp, Destination: sso, At: testcert.Now(), ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: acs}}}
						var result *protocol.VerifiedRequest
						var err error
						if transport == "POST" {
							signed, signErr := xmlsig.Sign(t.Context(), doc, doc.Root(), xmlsig.SigningKey{Key: key, Method: xmldsig.ECDSASHA256}, true)
							if signErr != nil {
								t.Fatal(signErr)
							}
							result, err = protocol.VerifyAuthnRequest(t.Context(), signed, []crypto.PublicKey{key.Public()}, options)
						} else {
							query, signErr := binding.SignRedirect(t.Context(), doc, binding.Request, nil, key, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
							if signErr != nil {
								t.Fatal(signErr)
							}
							result, err = protocol.VerifyRedirectRequest(t.Context(), query, []crypto.PublicKey{key.Public()}, options, binding.Options{})
						}
						if !test.valid {
							if err == nil || result != nil {
								t.Fatal("invalid signed boolean accepted")
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						got := map[string]bool{"ForceAuthn": result.ForceAuthn(), "IsPassive": result.IsPassive(), "AllowCreate": result.AllowCreateNameID()}[attribute]
						if got != test.want {
							t.Fatalf("got %v, want %v", got, test.want)
						}
					})
				}
			})
		}
	}
}

func TestAuthnRequestIndexLexicalValues(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	for _, test := range []struct {
		name, value string
		valid       bool
		index       uint16
	}{
		{"minimum", "0", true, 0},
		{"leading zeros", "0000", true, 0},
		{"XML whitespace", " 0000&#x9; ", true, 0},
		{"maximum", "65535", true, 65535},
		{"empty", "", false, 0},
		{"whitespace only", " ", false, 0},
		{"negative", "-1", false, 0},
		{"overflow", "65536", false, 0},
		{"hexadecimal", "0x0", false, 0},
		{"numeric separator", "0_0", false, 0},
		{"fraction", "0.0", false, 0},
		{"non XML whitespace", "&#xA0;0", false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			doc := parseLexicalAuthnRequest(t, ` AssertionConsumerServiceIndex="`+test.value+`"`, "")
			// The explicit default has a different index from either valid case;
			// ignoring the requested index must not select the expected endpoint.
			options := protocol.RequestOptions{Issuer: sp, Destination: sso, At: testcert.Now(), ACS: []metadata.Endpoint{
				{Binding: metadata.HTTPPost, Location: "https://sp.example.test/default-acs", Index: 1, Default: true, DefaultSet: true},
				{Binding: metadata.HTTPPost, Location: acs, Index: test.index},
			}}
			want := ""
			if test.valid {
				want = acs
			}
			for _, transport := range []string{"POST", "Redirect"} {
				t.Run(transport, func(t *testing.T) {
					t.Parallel()

					checkACSSelection(t, t.Context(), doc, key, options, transport, want)
				})
			}
		})
	}
}

func parseLexicalAuthnRequest(t *testing.T, attrs, child string) *document.Document {
	t.Helper()
	raw := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" ID="_request" Version="2.0" IssueInstant="%s" Destination="%s"%s><saml:Issuer>%s</saml:Issuer>%s</samlp:AuthnRequest>`, protocol.ProtocolNamespace, protocol.AssertionNamespace, testcert.Now().Format(time.RFC3339), sso, attrs, sp, child)
	doc, err := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
