package xpath //nolint:testpackage // Checks the parser and validation of serialization-parameter documents.

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

const serializationParameterRootOpen = `<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"
	xmlns:e="urn:extension" xmlns:p="urn:items"`

const serializationParameterRootClose = `</o:serialization-parameters>`

func TestReadSerializationParametersEditionRules(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		attributes string
		children   string
		want30     *SerializationParameters
		want31     *SerializationParameters
	}{
		{
			name: "string_and_token_whitespace",
			children: `<o:media-type value="  text/plain  "/><o:version value="  1.1  "/><o:item-separator value="  |  "/>
				<o:doctype-public value=" -//Test   DTD//EN "/><o:doctype-system value="data.dtd"/><o:standalone value=" no "/>`,
			want30: &SerializationParameters{Strings: map[string]string{
				"media-type": "  text/plain  ", "version": "  1.1  ", "item-separator": "  |  ",
				"doctype-public": " -//Test   DTD//EN ", "doctype-system": "data.dtd", "standalone": "no",
			}},
			want31: &SerializationParameters{Strings: map[string]string{
				"media-type": "text/plain", "version": "1.1", "item-separator": "  |  ",
				"doctype-public": "-//Test DTD//EN", "doctype-system": "data.dtd", "standalone": "no",
			}},
		},
		{
			name: "typed_boolean_and_rendering_parameters",
			children: `<o:indent xsi:type="o:yes-no-param-type" value="yes"/><o:escape-uri-attributes value="no"/>
				<o:include-content-type value="yes"/><o:undeclare-prefixes value="no"/><o:byte-order-mark value="yes"/>
				<o:html-version value="+4.01"/><o:encoding value="UTF-8"/><o:normalization-form value="NFD"/>`,
			want30: &SerializationParameters{
				Booleans: map[string]bool{"indent": true, "escape-uri-attributes": false, "include-content-type": true, "undeclare-prefixes": false, "byte-order-mark": true},
				Strings:  map[string]string{"html-version": "+4.01", "encoding": "UTF-8", "normalization-form": "NFD"},
			},
			want31: &SerializationParameters{
				Booleans: map[string]bool{"indent": true, "escape-uri-attributes": false, "include-content-type": true, "undeclare-prefixes": false, "byte-order-mark": true},
				Strings:  map[string]string{"html-version": "+4.01", "encoding": "UTF-8", "normalization-form": "NFD"},
			},
		},
		{
			name:     "xsd_boolean_lexicals",
			children: `<o:indent value=" true "/><o:byte-order-mark value="1"/><o:standalone value="0"/>`,
			want31:   &SerializationParameters{Booleans: map[string]bool{"indent": true, "byte-order-mark": true}, Strings: map[string]string{"standalone": "no"}},
		},
		{
			name:     "standalone_uses_edition_specific_boolean_space",
			children: `<o:standalone value="false"/>`,
			want31:   &SerializationParameters{Strings: map[string]string{"standalone": "no"}},
		},
		{
			name:     "json_and_json_node_output_method",
			children: `<o:method value="json"/><o:json-node-output-method value="Q{}text"/><o:allow-duplicate-names value="no"/>`,
			want31:   &SerializationParameters{Strings: map[string]string{"method": "json", "json-node-output-method": "text"}, Booleans: map[string]bool{"allow-duplicate-names": false}},
		},
		{
			name:     "json_parameters_unavailable_in_3_0",
			children: `<o:json-node-output-method value="text"/>`,
			want31:   &SerializationParameters{Strings: map[string]string{"json-node-output-method": "text"}},
		},
		{
			name:     "expanded_names_and_duplicate_cdata_names",
			children: `<o:cdata-section-elements xmlns="urn:default" value="item p:item Q{urn:items}item"/>`,
			want31:   &SerializationParameters{Names: map[string][]string{"cdata-section-elements": {"{urn:default}item", "{urn:items}item"}}},
		},
		{
			name:     "extension_method_with_bound_prefix",
			children: `<o:method value="e:custom"/>`,
			want30:   &SerializationParameters{Strings: map[string]string{"method": "e:custom"}},
			want31:   &SerializationParameters{Strings: map[string]string{"method": "e:custom"}},
		},
		{
			name:       "comments_processing_instructions_and_schema_location",
			attributes: ` xsi:noNamespaceSchemaLocation="local.xsd"`,
			children:   ` <!-- notes --> <?config local?> <o:method value="text"/>`,
			want30:     &SerializationParameters{Strings: map[string]string{"method": "text"}},
			want31:     &SerializationParameters{Strings: map[string]string{"method": "text"}},
		},
		{
			name:     "unknown_parameter",
			children: `<o:unknown value="ignored"/><o:method value="text"/>`,
			want31:   &SerializationParameters{Strings: map[string]string{"method": "text"}},
		},
		{
			name:     "foreign_parameter",
			children: `<e:indent><e:note/></e:indent><o:indent value="no"/>`,
			want31:   &SerializationParameters{Booleans: map[string]bool{"indent": false}},
		},
		{
			name:     "unqualified_parameter",
			children: `<indent value="yes"/><o:indent value="no"/>`,
			want31:   &SerializationParameters{Booleans: map[string]bool{"indent": false}},
		},
		{
			name:       "root_attribute",
			attributes: ` e:note="comment"`,
			children:   `<o:method value="text"/>`,
			want31:     &SerializationParameters{Strings: map[string]string{"method": "text"}},
		},
		{
			name:     "non_whitespace_in_root",
			children: `text<o:method value="text"/>`,
			want31:   &SerializationParameters{Strings: map[string]string{"method": "text"}},
		},
	} {
		for _, edition := range []struct {
			version int
			want    *SerializationParameters
		}{{30, tc.want30}, {31, tc.want31}} {
			t.Run(fmt.Sprintf("%s/serialization_%d", tc.name, edition.version), func(t *testing.T) {
				t.Parallel()
				input := serializationParameterRootOpen + tc.attributes + ">" + tc.children + serializationParameterRootClose
				got, err := readSerializationParametersFromXML(t, input, edition.version)
				if edition.want == nil {
					requireSerializationParameterError(t, got, err, "SEPM0017")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := edition.want
				if !maps.Equal(got.Strings, want.Strings) || !maps.Equal(got.Booleans, want.Booleans) ||
					!maps.EqualFunc(got.Names, want.Names, slices.Equal[[]string]) || got.CharactersSet || len(got.Reset) != 0 {
					t.Errorf("parameters = %+v; want supplied parameters %+v", got, want)
				}
			})
		}
	}
}

func TestReadSerializationParametersRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input, code string
	}{
		{"wrong_root_name", `<o:options xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization"/>`, "XPTY0004"},
		{"wrong_root_namespace", `<serialization-parameters/>`, "XPTY0004"},
		{"declared_type_must_match_parameter", `<o:indent xsi:type="o:string-param-type" value="yes"/>`, "SEPM0017"},
		{"type_name_must_be_lexical_qname", `<o:indent xsi:type="Q{http://www.w3.org/2010/xslt-xquery-serialization}yes-no-param-type" value="yes"/>`, "SEPM0017"},
		{"type_name_rejects_unbound_prefix", `<o:indent xsi:type="u:yes-no-param-type" value="yes"/>`, "SEPM0017"},
		{"nil_is_forbidden_even_when_false", `<o:indent xsi:nil="false" value="yes"/>`, "SEPM0017"},
		{"missing_value_attribute", `<o:item-separator e:value="|"/>`, "SEPM0017"},
		{"qualified_value_attribute", `<o:item-separator o:value="|"/>`, "SEPM0017"},
		{"non_xml_whitespace_is_significant", `<o:item-separator value="x">&#160;</o:item-separator>`, "SEPM0017"},
		{"value_cannot_contain_an_element", `<o:encoding value="UTF-8"><e:child/></o:encoding>`, "SEPM0017"},
		{"malformed_html_version", `<o:html-version value="5.0.1"/>`, "SEPM0017"},
		{"unsupported_boolean_spelling", `<o:indent value="True"/>`, "SEPM0017"},
		{"standalone_out_of_domain", `<o:standalone value="maybe"/>`, "SEPM0017"},
		{"encoding_name_out_of_domain", `<o:encoding value="8-bit"/>`, "SEPM0017"},
		{"public_identifier_out_of_domain", `<o:doctype-public value="café"/>`, "SEPM0017"},
		{"system_identifier_has_both_delimiters", `<o:doctype-system value="a&quot;b'c"/>`, "SEPM0017"},
		{"normalization_form_is_nmtoken", `<o:normalization-form value="NF D"/>`, "SEPM0017"},
		{"json_node_method_excludes_adaptive", `<o:json-node-output-method value="adaptive"/>`, "SEPM0017"},
		{"unbound_extension_method", `<o:method value="u:custom"/>`, "SEPM0017"},
		{"duplicate_foreign_parameters", `<e:other/><e:other/>`, "SEPM0019"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := tc.input
			if tc.code != "XPTY0004" {
				input = serializationParameterRootOpen + ">" + input + serializationParameterRootClose
			}
			got, err := readSerializationParametersFromXML(t, input, 31)
			requireSerializationParameterError(t, got, err, tc.code)
		})
	}
}

func readSerializationParametersFromXML(t *testing.T, input string, edition int) (SerializationParameters, error) {
	t.Helper()
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), input)
	if err != nil {
		t.Fatalf("parse parameter fixture: %v", err)
	}
	return ReadSerializationParameters(t.Context(), doc.DocumentElement(), edition)
}

func requireSerializationParameterError(t *testing.T, got SerializationParameters, err error, code string) {
	t.Helper()
	if !errors.Is(err, &xdm.Error{Code: code}) || got.Strings != nil || got.Booleans != nil || got.Names != nil || got.CharactersSet || got.Characters != nil || got.Reset != nil {
		t.Errorf("parameters = %+v, error = %v; want no supplied values and %s", got, err, code)
	}
}
