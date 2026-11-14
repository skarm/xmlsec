package xpath //nolint:testpackage // Tests validation of active character maps and their lax schema content.

import (
	"maps"
	"testing"
)

func TestResolveSerializeCharacterMapsElement(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input, code string
	}{
		{"ignores_nonentries_and_keeps_exact_replacement", `<!--note--><?config keep?><o:character-map e:note="ignore" character="🙂" map-string=" face "/><o:character-map character="x"/><o:character-map map-string="unused"/>`, ""},
		{"rejects_character_with_two_scalars", `<o:character-map character="e&#x301;"/>`, "SEPM0017"},
		{"rejects_entry_unknown_attribute", `<o:character-map character="x" other="ignore"/>`, "SEPM0017"},
		{"rejects_qualified_entry_attribute", `<o:character-map o:character="x"/>`, "SEPM0017"},
		{"rejects_entry_child_content", `<o:character-map character="x"><e:entry/></o:character-map>`, "SEPM0017"},
		{"rejects_significant_map_text", `<![CDATA[letters]]>`, "SEPM0017"},
		{"rejects_two_foreign_children", `<e:other/><e:next/>`, "SEPM0017"},
		{"rejects_entry_after_foreign_child", `<e:other/><o:character-map character="x"/>`, "SEPM0017"},
		{"rejects_duplicate_non_bmp_entries", `<o:character-map character="🙂" map-string="first"/><o:character-map character="🙂" map-string="second"/>`, "SEPM0018"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := serializationParameterRootOpen + ">" + `<o:use-character-maps e:note="ignore">` + tc.input + `</o:use-character-maps>` + serializationParameterRootClose
			got, err := readSerializationParametersFromXML(t, input, 31)
			if tc.code != "" {
				requireSerializationParameterError(t, got, err, tc.code)
				return
			}

			want := map[rune]string{'🙂': " face ", 'x': ""}
			if err != nil || !got.CharactersSet || !maps.Equal(got.Characters, want) {
				t.Errorf("active character map = %v, supplied = %t, error = %v; want %v", got.Characters, got.CharactersSet, err, want)
			}
		})
	}
}

func TestResolveSerializeCharacterMapsElementLaxTypes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input string
		want30      bool
		want31      bool
	}{
		{"base_type_accepts_only_foreign_attributes_and_no_value", `<e:node xsi:type="o:base-param-type" e:note="local"/>`, true, true},
		{"base_type_rejects_local_attributes", `<e:node xsi:type="o:base-param-type" value="not allowed"/>`, false, false},
		{"base_type_rejects_element_content", `<e:node xsi:type="o:base-param-type"><e:other/></e:node>`, false, false},
		{"typed_nested_map_validates_without_extracting", `<e:node xsi:type="o:use-character-maps-param-type"><o:character-map character="a" map-string="first"/><o:character-map character="a" map-string="second"/></e:node>`, true, true},
		{"qualified_eqname_only_exists_in_3_1", `<e:node xsi:type="o:Qualified-EQName">Q{urn:items}item</e:node>`, false, true},
		{"qualified_eqname_requires_nonempty_namespace", `<e:node xsi:type="o:Qualified-EQName">Q{}item</e:node>`, false, false},
		{"prefixed_qname_only_accepts_bound_prefix", `<e:node xsi:type="o:Prefixed-QName">p:item</e:node>`, false, true},
		{"prefixed_qname_rejects_eqname", `<e:node xsi:type="o:Prefixed-QName">Q{urn:items}item</e:node>`, false, false},
		{"tokenized_string_parameter_only_exists_in_3_1", `<e:node xsi:type="o:tokenized-string-param-type" value="  text/plain  "/>`, false, true},
		{"json_node_output_method_only_exists_in_3_1", `<e:node xsi:type="o:json-node-output-method-param-type" value="text"/>`, false, true},
		{"char_type_counts_unicode_scalars", `<e:node xsi:type="o:char-type">🙂</e:node>`, true, true},
		{"char_type_rejects_multiple_scalars", `<e:node xsi:type="o:char-type">e&#x301;</e:node>`, false, false},
		{"simple_type_rejects_undeclared_local_attribute", `<e:node xsi:type="xs:integer" unit="kg">12</e:node>`, false, false},
		{"simple_type_rejects_nested_element", `<e:node xsi:type="xs:integer">1<e:digit/>2</e:node>`, false, false},
		{"built_in_list_type_checks_each_member", `<e:node xsi:type="xs:NMTOKENS">one two-2</e:node>`, true, true},
		{"built_in_integer_respects_range", `<e:node xsi:type="xs:byte">128</e:node>`, false, false},
		{"xsd_11_type_is_not_declared", `<e:node xsi:type="xs:dateTimeStamp">2024-02-01T01:02:03Z</e:node>`, false, false},
		{"any_simple_type_accepts_text", `<e:node xsi:type="xs:anySimpleType">a value</e:node>`, true, true},
		{"notation_requires_declaration", `<e:node xsi:type="xs:NOTATION">p:item</e:node>`, false, false},
		{"entity_requires_declaration", `<e:node xsi:type="xs:ENTITY">asset</e:node>`, false, false},
		{"abstract_parameter_cannot_be_instantiated", `<o:serialization-parameter-element/>`, false, false},
		{"generic_wrapper_checks_declared_descendants", `<e:node><o:html-version value="1e2"/></e:node>`, false, false},
		{"nested_container_rejects_attributes", `<e:node><o:serialization-parameters e:note="local"/></e:node>`, false, false},
		{"nested_container_has_foreign_wildcard_in_3_1", `<e:wrapper><o:serialization-parameters><e:node xsi:type="xs:integer">24</e:node></o:serialization-parameters></e:wrapper>`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const mapOpen = `<o:use-character-maps><o:character-map character="a" map-string="A"/>`
			const mapClose = `</o:use-character-maps>`
			input := serializationParameterRootOpen + ">" + mapOpen + tc.input + mapClose + serializationParameterRootClose
			for _, edition := range []struct {
				name    string
				version int
				valid   bool
			}{{"serialization_30", 30, tc.want30}, {"serialization_31", 31, tc.want31}} {
				t.Run(edition.name, func(t *testing.T) {
					t.Parallel()
					got, err := readSerializationParametersFromXML(t, input, edition.version)
					if !edition.valid {
						requireSerializationParameterError(t, got, err, "SEPM0017")
						return
					}

					want := map[rune]string{'a': "A"}
					if err != nil || !got.CharactersSet || !maps.Equal(got.Characters, want) {
						t.Errorf("active character map = %v, supplied = %t, error = %v; want only %v", got.Characters, got.CharactersSet, err, want)
					}
				})
			}
		})
	}
}
