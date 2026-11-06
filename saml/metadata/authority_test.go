package metadata_test

import (
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
)

func TestAuthorityMetadataRoles(t *testing.T) {
	c := testcert.New(t)
	at := testcert.Now()
	for _, test := range []struct {
		role     metadata.RoleType
		endpoint string
	}{{metadata.AuthenticationAuthority, metadata.AuthnQueryService}, {metadata.AttributeAuthority, metadata.AttributeService}, {metadata.PolicyDecisionPoint, metadata.AuthzService}} {
		t.Run(string(test.role), func(t *testing.T) {
			role := &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{test.endpoint: {{Binding: metadata.SOAP, Location: "https://authority.test/soap"}}, metadata.AssertionIDRequestService: {{Binding: metadata.URI, Location: "https://authority.test/assertion"}}}}
			spec := metadata.EntityDescriptor{EntityID: "https://authority.test/entity", ValidUntil: at.Add(time.Hour)}
			switch test.role {
			case metadata.AuthenticationAuthority:
				spec.AuthnAuthority = role
			case metadata.AttributeAuthority:
				spec.AttributeAuthority = role
			case metadata.PolicyDecisionPoint:
				spec.PDP = role
			}
			d, err := metadata.Build(t.Context(), spec, at, metadata.Options{})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := d.XML(t.Context())
			snapshot, err := metadata.ParseTrusted(t.Context(), raw, at, metadata.Options{})
			if err != nil {
				t.Fatal(err)
			}
			entity, err := snapshot.Find(spec.EntityID, at)
			if err != nil {
				t.Fatal(err)
			}
			got, err := entity.Role(test.role, at)
			if err != nil || len(got.Endpoints(test.endpoint)) != 1 || len(got.SigningKeys()) != 1 {
				t.Fatalf("authority role: %v", err)
			}
			role.Endpoints = map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.SOAP, Location: "https://authority.test/soap"}}}
			if _, err = metadata.Build(t.Context(), spec, at, metadata.Options{}); err == nil {
				t.Fatal("authority without its required endpoint accepted")
			}
		})
	}
}

func TestNameIDMappingMetadataResponseLocation(t *testing.T) {
	at := testcert.Now()
	spec := metadata.EntityDescriptor{EntityID: "https://authority.test/entity", ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.SOAP, Location: "https://authority.test/soap"}}, metadata.NameIDMappingService: {{Binding: metadata.SOAP, Location: "https://authority.test/mapping", ResponseLocation: "https://other.test/response"}}}}}
	if _, err := metadata.Build(t.Context(), spec, at, metadata.Options{}); err == nil {
		t.Fatal("forbidden NameIDMappingService ResponseLocation accepted")
	}
}
