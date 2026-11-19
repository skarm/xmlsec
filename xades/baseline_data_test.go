package xades //nolint:testpackage // Tests the private parser for XAdES data object properties.

import (
	"errors"
	"reflect"
	"testing"

	"github.com/skarm/xmlsec/document"
)

func TestParseDataObjectFormatMediaType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body, want string
		wantErr          error
	}{
		{name: "omitted"},
		{name: "type and subtype with parameters", body: `<MimeType>application/json; charset=utf-8</MimeType>`, want: "application/json; charset=utf-8"},
		{name: "disposition", body: `<MimeType>attachment</MimeType>`, wantErr: ErrProfile},
		{name: "empty", body: `<MimeType/>`, wantErr: ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := `<DataObjectFormat xmlns="` + Namespace + `" ObjectReference="#data"><Description>Catalog item</Description>` + tc.body + "</DataObjectFormat>"
			doc, err := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseDataObjectFormat(doc.Root())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("parseDataObjectFormat error = %v, want %v", err, tc.wantErr)
			}
			if err == nil && (got.ObjectReference != "#data" || got.Description != "Catalog item" || got.MIMEType != tc.want) {
				t.Errorf("parseDataObjectFormat = %+v, want description, object reference, MIME type %q", got, tc.want)
			}
		})
	}
}

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
