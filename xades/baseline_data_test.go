package xades //nolint:testpackage // Tests the private parser for XAdES data object properties.

import (
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/document"
)

func TestParseObjectIdentifierValidatesQualifierAndDocumentation(t *testing.T) {
	t.Parallel()

	const validIdentifier = `<Identifier Qualifier="OIDAsURN">urn:oid:2.999.3</Identifier>`
	for _, tc := range []struct {
		name, body string
		want       ObjectIdentifier
		wantErr    error
	}{
		{
			name: "urn_with_metadata",
			body: validIdentifier + `<Description>Catalog item</Description><DocumentationReferences><DocumentationReference>https://example.test/spec</DocumentationReference><DocumentationReference>guide.xml</DocumentationReference></DocumentationReferences>`,
			want: ObjectIdentifier{Identifier: "urn:oid:2.999.3", Qualifier: "OIDAsURN", Description: "Catalog item", Documentation: []string{"https://example.test/spec", "guide.xml"}},
		},
		{
			name: "uri_qualified",
			body: `<Identifier Qualifier="OIDAsURI">https://example.test/id</Identifier>`,
			want: ObjectIdentifier{Identifier: "https://example.test/id", Qualifier: "OIDAsURI"},
		},
		{name: "missing_identifier", body: "<Description>Catalog item</Description>", wantErr: ErrProfile},
		{name: "oid_urn_requires_qualifier", body: "<Identifier>urn:oid:2.999.3</Identifier>", wantErr: ErrProfile},
		{name: "second_arc_outside_first_arc_range", body: `<Identifier Qualifier="OIDAsURN">urn:oid:1.40.3</Identifier>`, wantErr: ErrProfile},
		{name: "oid_arc_with_leading_zero", body: `<Identifier Qualifier="OIDAsURN">urn:oid:2.01.3</Identifier>`, wantErr: ErrProfile},
		{name: "oid_arc_with_non_digit", body: `<Identifier Qualifier="OIDAsURN">urn:oid:2.abc</Identifier>`, wantErr: ErrProfile},
		{name: "uri_qualifier_requires_absolute_uri", body: `<Identifier Qualifier="OIDAsURI">relative.xml</Identifier>`, wantErr: ErrProfile},
		{name: "unknown_qualifier", body: `<Identifier Qualifier="Other">https://example.test/id</Identifier>`, wantErr: ErrProfile},
		{name: "empty_documentation", body: validIdentifier + "<DocumentationReferences/>", wantErr: ErrProfile},
		{name: "unexpected_documentation_child", body: validIdentifier + "<DocumentationReferences><Description>text</Description></DocumentationReferences>", wantErr: ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := `<ObjectIdentifier xmlns="` + Namespace + `">` + tc.body + "</ObjectIdentifier>"
			doc, err := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
			if err != nil {
				t.Fatalf("parse XML fixture: %v", err)
			}
			got, err := parseObjectIdentifier(doc.Root())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("parseObjectIdentifier error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseObjectIdentifier = %+v, want %+v", got, tc.want)
			}
		})
	}
}
