package metadata_test

import (
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
)

// SAML Metadata 2.0 sections 2.2.3 and 2.4.4 use xs:boolean, whose
// whiteSpace facet is fixed to collapse (XSD 1.0 Part 2 sections 3.2.2, 4.3.6).
func TestMetadataBooleanLexicalValues(t *testing.T) {
	t.Parallel()

	c := testcert.New(t)
	doc, err := metadata.Build(t.Context(), metadata.EntityDescriptor{
		EntityID: "urn:test:sp", ValidUntil: testcert.Now().Add(time.Hour),
		IDP: &metadata.RoleDescriptor{
			WantAuthnRequestsSigned: true,
			Keys:                    []metadata.KeyDescriptor{{CertificateDER: c.Leaf.Raw}},
			Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {
				{Binding: metadata.HTTPRedirect, Location: "https://idp.example.test/sso"},
			}},
		},
		SP: &metadata.RoleDescriptor{
			AuthnRequestsSigned: true, WantAssertionsSigned: true,
			Keys: []metadata.KeyDescriptor{{CertificateDER: c.Leaf.Raw}},
			Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {
				{Binding: metadata.HTTPPost, Location: "https://sp.example.test/acs", Default: true},
			}},
		},
	}, testcert.Now(), metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"AuthnRequestsSigned", "WantAssertionsSigned", "WantAuthnRequestsSigned", "isDefault"} {
		original := " " + attribute + `="true"`
		if count := strings.Count(string(raw), original); count != 1 {
			t.Fatalf("fixture must contain exactly one %s attribute; got %d", attribute, count)
		}
		for _, test := range []struct {
			name, value string
			valid, want bool
		}{
			{"true literal", "true", true, true},
			{"one literal", "1", true, true},
			{"XML whitespace around true", " &#x9;true&#xD;&#xA; ", true, true},
			{"false literal", "false", true, false},
			{"zero literal", "0", true, false},
			{"XML whitespace around false", " &#x9;false&#xD;&#xA; ", true, false},
			{"empty", "", false, false},
			{"whitespace only", " ", false, false},
			{"uppercase", "TRUE", false, false},
			{"internal whitespace", "tr ue", false, false},
			{"non XML whitespace", "&#xA0;true", false, false},
		} {
			t.Run(attribute+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				input := strings.Replace(string(raw), original, " "+attribute+`="`+test.value+`"`, 1)
				set, err := metadata.ParseTrusted(t.Context(), []byte(input), testcert.Now(), metadata.Options{})
				if !test.valid {
					if err == nil || set != nil {
						t.Fatal("invalid boolean accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				entity, err := set.Find("urn:test:sp", testcert.Now())
				if err != nil {
					t.Fatal(err)
				}
				role, err := entity.Role(metadata.ServiceProvider, testcert.Now())
				if err != nil {
					t.Fatal(err)
				}
				endpoint, err := role.ACS(metadata.HTTPPost, nil)
				if err != nil || !endpoint.DefaultSet {
					t.Fatalf("endpoint boolean changed: %v", err)
				}
				idp, err := entity.Role(metadata.IdentityProvider, testcert.Now())
				if err != nil {
					t.Fatalf("IdP boolean changed: %v", err)
				}
				values := map[string]bool{
					"AuthnRequestsSigned": role.AuthnRequestsSigned(), "WantAssertionsSigned": role.WantAssertionsSigned(),
					"WantAuthnRequestsSigned": idp.WantAuthnRequestsSigned(), "isDefault": endpoint.Default,
				}
				for name, value := range values {
					want := name != attribute || test.want
					if value != want {
						t.Fatalf("%s = %v; want %v", name, value, want)
					}
				}
			})
		}
	}
}
