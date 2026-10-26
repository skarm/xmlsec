package metadata_test

import (
	"fmt"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
)

func TestMetadataIndexLexicalValues(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, value string
		valid       bool
		want        uint16
	}{
		{"minimum", "0", true, 0},
		{"leading zeros", "00001", true, 1},
		{"spaces", " 0 ", true, 0},
		{"maximum with XML whitespace", " &#x9;65535&#xD;&#xA; ", true, 65535},
		{"empty", "", false, 0},
		{"negative", "-1", false, 0},
		{"overflow", "65536", false, 0},
		{"internal whitespace", "1 0", false, 0},
		{"hexadecimal", "0x10", false, 0},
		{"numeric separator", "1_0", false, 0},
		{"non XML whitespace", "&#xA0;1", false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := fmt.Sprintf(`<md:EntityDescriptor xmlns:md="%s" entityID="urn:test:sp"><md:SPSSODescriptor protocolSupportEnumeration="%s"><md:AssertionConsumerService Binding="%s" Location="https://sp.example.test/acs" index="%s"/></md:SPSSODescriptor></md:EntityDescriptor>`, metadata.Namespace, metadata.Protocol, metadata.HTTPPost, test.value)
			set, err := metadata.ParseTrusted(t.Context(), []byte(input), testcert.Now(), metadata.Options{})
			if !test.valid {
				if err == nil || set != nil {
					t.Fatal("invalid endpoint index accepted")
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
			endpoint, err := role.ACS(metadata.HTTPPost, &test.want)
			if err != nil || endpoint.Index != test.want {
				t.Fatalf("index=%d error=%v; want %d", endpoint.Index, err, test.want)
			}
		})
	}
}
