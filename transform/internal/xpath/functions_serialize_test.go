package xpath //nolint:testpackage // Runs serialization functions through both internal evaluation paths.

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestReadSerializationParametersPreservesSuppliedValues(t *testing.T) {
	t.Parallel()
	const input = `<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization" xmlns:p="urn:p">
		<o:method value="xml"/>
		<o:byte-order-mark value="no"/>
		<o:omit-xml-declaration value="yes"/>
		<o:standalone value="omit"/>
		<o:item-separator value=""/>
		<o:cdata-section-elements value="p:b a p:b"/>
		<o:suppress-indentation value="p:c"/>
		<o:use-character-maps><o:character-map character="é" map-string="E"/><o:character-map character="x"/></o:use-character-maps>
	</o:serialization-parameters>`
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadSerializationParameters(t.Context(), doc.DocumentElement(), 31)
	if err != nil {
		t.Fatal(err)
	}
	if want := (map[string]string{"method": "xml", "standalone": "omit", "item-separator": ""}); !maps.Equal(got.Strings, want) {
		t.Errorf("string parameters = %v, want %v", got.Strings, want)
	}
	if want := (map[string]bool{"byte-order-mark": false, "omit-xml-declaration": true}); !maps.Equal(got.Booleans, want) {
		t.Errorf("boolean parameters = %v, want %v", got.Booleans, want)
	}
	if want := (map[string][]string{"cdata-section-elements": {"{urn:p}b", "{}a"}, "suppress-indentation": {"{urn:p}c"}}); !maps.EqualFunc(got.Names, want, slices.Equal[[]string]) {
		t.Errorf("name parameters = %v, want %v", got.Names, want)
	}
	if want := (map[rune]string{'é': "E", 'x': ""}); !got.CharactersSet || !maps.Equal(got.Characters, want) || len(got.Reset) != 0 {
		t.Errorf("character map = %v, supplied=%v, resets=%v; want %v, true, no resets", got.Characters, got.CharactersSet, got.Reset, want)
	}
}

func TestReadSerializationParameterMapDistinguishesEmptyValues(t *testing.T) {
	t.Parallel()
	seq, err := evaluateFunctionExpression(t, `map{'method':'text','byte-order-mark':true(),'indent':false(),'standalone':false(),'item-separator':(),'suppress-indentation':QName('urn:p','p:body'),'use-character-maps':map{}, QName('urn:ext','ext:indent'):true(),'unknown':17}`, "VM")
	if err != nil || xdm.SequenceLen(seq) != 1 {
		t.Fatalf("build options map: %v, %v", seq, err)
	}
	options, ok := seq.Get(0).(xdm.MapItem)
	if !ok {
		t.Fatalf("options = %T, want a map", seq.Get(0))
	}
	got, err := ReadSerializationParameterMap(t.Context(), options, 31)
	if err != nil {
		t.Fatal(err)
	}
	if want := (map[string]string{"method": "text", "standalone": "no"}); !maps.Equal(got.Strings, want) {
		t.Errorf("string options = %v, want %v", got.Strings, want)
	}
	if want := (map[string]bool{"byte-order-mark": true, "indent": false}); !maps.Equal(got.Booleans, want) {
		t.Errorf("boolean options = %v, want %v", got.Booleans, want)
	}
	if want := (map[string][]string{"suppress-indentation": {"{urn:p}body"}}); !maps.EqualFunc(got.Names, want, slices.Equal[[]string]) {
		t.Errorf("name options = %v, want %v", got.Names, want)
	}
	if !got.CharactersSet || len(got.Characters) != 0 || !slices.Equal(got.Reset, []string{"item-separator"}) {
		t.Errorf("character map = %v, supplied=%v, resets=%v; want supplied empty map and item-separator reset", got.Characters, got.CharactersSet, got.Reset)
	}
	if _, err := ReadSerializationParameterMap(t.Context(), options, 30); !errors.Is(err, &xdm.Error{Code: "XPTY0004"}) {
		t.Errorf("serialization 3.0 map returned %v, want XPTY0004", err)
	}
}

func TestSerializeHTMLAndXHTMLDocumentsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"html5_adds_doctype_and_preserves_void_elements", `serialize(parse-xml('<html><body><br/><p>a&amp;b</p></body></html>'),map{'method':'html','include-content-type':false()})`, "<!DOCTYPE html>\n<html><body><br><p>a&amp;b</p></body></html>"},
		{"leading_text_suppresses_automatic_doctype", `serialize(('intro',parse-xml('<html><body/></html>')/*),map{'method':'html','item-separator':' ','include-content-type':false()})`, `intro <html><body></body></html>`},
		{"html4_escapes_characters_outside_the_repertoire", `serialize(parse-xml('<p>café</p>'),map{'method':'html','html-version':4.01,'encoding':'US-ASCII','include-content-type':false()})`, `<p>caf&#xE9;</p>`},
		{"html5_default_doctype_is_not_repeated", `let $h:=parse-xml('<html/>')/* return serialize(($h,$h),map{'method':'html','include-content-type':false()})`, "<!DOCTYPE html>\n<html></html><html></html>"},
		{"explicit_doctype_uses_html_name", `serialize(parse-xml('<HtMl><br/></HtMl>'),map{'method':'html','doctype-system':'sample.dtd','doctype-public':'-//EXAMPLE//DTD HTML//EN','include-content-type':false()})`, "<!DOCTYPE html PUBLIC \"-//EXAMPLE//DTD HTML//EN\" \"sample.dtd\">\n<HtMl><br></HtMl>"},
		{"xhtml_uses_namespace_and_compatibility_spacing", `serialize(parse-xml('<p xmlns="http://www.w3.org/1999/xhtml"><br/><span/></p>'),map{'method':'xhtml','html-version':4.01,'include-content-type':false()})`, `<p xmlns="http://www.w3.org/1999/xhtml"><br /><span></span></p>`},
		{"xhtml5_uses_automatic_doctype", `serialize(parse-xml('<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>'),map{'method':'xhtml','html-version':5,'include-content-type':false()})`, `<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><body></body></html>`},
		{"serialize_selected_element_retains_in_scope_namespaces", `serialize(parse-xml('<r xmlns:p="urn:p"><a><p:b/></a></r>')/r/a,map{'method':'xml'})`, `<a xmlns:p="urn:p"><p:b/></a>`},
	})
}

func TestSerializeCharacterMapValidatesTypedExtensionWithoutApplyingIt(t *testing.T) {
	t.Parallel()
	const prefix = `<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization" xmlns:e="urn:extension" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:p="urn:p"><o:use-character-maps><o:character-map character="a" map-string="A"/><e:wrapper>`
	const suffix = `</e:wrapper></o:use-character-maps></o:serialization-parameters>`
	for _, tc := range []struct {
		name, element string
		valid         bool
	}{
		{"decimal_parameter_accepts_fraction", `<e:decimal xsi:type="o:decimal-param-type" value="-.25"/>`, true},
		{"decimal_parameter_disallows_exponent", `<e:decimal xsi:type="o:decimal-param-type" value="1e2"/>`, false},
		{"standalone_domain_accepts_omit", `<e:standalone xsi:type="o:yes-no-omit-param-type" value="omit"/>`, true},
		{"encoding_domain_requires_lexical_name", `<e:encoding xsi:type="o:encoding-param-type" value="invalid name"/>`, false},
		{"method_domain_accepts_qualified_extension", `<e:method xsi:type="o:method-param-type" value="p:custom"/>`, true},
		{"qnames_resolve_both_notations", `<e:qnames xsi:type="o:QNames-param-type" value="p:one Q{urn:p}two"/>`, true},
		{"qnames_reject_unbound_prefix", `<e:qnames xsi:type="o:QNames-param-type" value="missing:one"/>`, false},
		{"xsd_qname_uses_in_scope_prefix", `<e:name xsi:type="xs:QName"> p:value </e:name>`, true},
		{"xsd_qname_rejects_eqname", `<e:name xsi:type="xs:QName">Q{urn:p}value</e:name>`, false},
		{"xsd_any_type_still_checks_declared_descendants", `<e:box xsi:type="xs:anyType"><o:indent value="perhaps"/></e:box>`, false},
		{"nested_map_does_not_override_active_map", `<o:use-character-maps><o:character-map character="a" map-string="B"/></o:use-character-maps>`, true},
		{"nested_parameter_container_validates_children", `<o:serialization-parameters><o:indent value="yes"/></o:serialization-parameters>`, true},
		{"nested_parameter_container_rejects_undeclared_parameter", `<o:serialization-parameters><o:unknown/></o:serialization-parameters>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), prefix+tc.element+suffix)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadSerializationParameters(t.Context(), doc.DocumentElement(), 31)
			if !tc.valid {
				if !errors.Is(err, &xdm.Error{Code: "SEPM0017"}) || got.CharactersSet {
					t.Fatalf("parameters = %+v, error=%v; want SEPM0017 without an active map", got, err)
				}
				return
			}
			if want := (map[rune]string{'a': "A"}); err != nil || !got.CharactersSet || !maps.Equal(got.Characters, want) {
				t.Fatalf("parameters = %+v, error=%v; want only active character map %v", got, err, want)
			}
		})
	}
}

func TestSerializeJSONMapUsesStringNamesASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"empty_value_becomes_null", `serialize(map{7:()},map{'method':'json','indent':false()})`, `{"7":null}`},
		{"explicit_duplicate_names_are_kept", `let $s := serialize(map{7:1,'7':2},map{'method':'json','allow-duplicate-names':true(),'indent':false()}) return ($s = ('{"7":1,"7":2}','{"7":2,"7":1}'))`, `true`},
		{"nested_map_in_array", `serialize([map{'first':true()},map{}],map{'method':'json','indent':false()})`, `[{"first":true},{}]`},
	})
}

func TestSerializeOutputRestrictionsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, expression, code string }{
		{"markup_rejects_attribute_items", `serialize(parse-xml('<r id="1"/>')/r/@id,map{'method':'html'})`, "SENR0001"},
		{"markup_rejects_map_items", `serialize(map{'a':1},map{'method':'xml'})`, "SENR0001"},
		{"markup_rejects_function_items", `serialize(string#1,map{'method':'text'})`, "SENR0001"},
		{"html4_rejects_control_characters", `serialize(codepoints-to-string(127),map{'method':'html','html-version':4.01})`, "SERE0014"},
		{"html_rejects_processing_instruction_with_gt", `serialize(parse-xml('<?sample a>b?><p/>'),map{'method':'html'})`, "SERE0015"},
		{"json_rejects_non_finite_numbers", `serialize(xs:double('INF'),map{'method':'json'})`, "SERE0020"},
		{"json_rejects_keys_with_same_string_name", `serialize(map{7:1,'7':2},map{'method':'json'})`, "SERE0022"},
		{"json_rejects_multi_item_map_value", `serialize(map{'a':(1,2)},map{'method':'json'})`, "SERE0023"},
		{"json_rejects_function_item", `serialize(string#1,map{'method':'json'})`, "SERE0021"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, tc.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Fatalf("%s returned %v, %v; want no output and %s", tc.expression, seq, err, tc.code)
				}
			})
		}
	}
}

func TestFnSerializeErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"JSON rejects sequence longer than one item", `serialize((1,2),map{'method':'json'})`, "SERE0023"},
		{"duplicate serialization parameters", `serialize('x',parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><indent value="yes"/><indent value="no"/></serialization-parameters>')/*)`, "SEPM0019"},
		{"duplicate entries in character map", `serialize('a',parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><use-character-maps><character-map character="a" map-string="x"/><character-map character="a" map-string="y"/></use-character-maps></serialization-parameters>')/*)`, "SEPM0018"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, test.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: test.code}) {
					t.Fatalf("%s = %v, %v; want no result and %s", test.expression, seq, err, test.code)
				}
			})
		}
	}
}

func TestSerializationMethodsASTAndVM(t *testing.T) {
	t.Parallel()
	assertFunctionResults(t, []functionResultCase{
		{"XML escapes a custom item separator", `serialize(('a','b'),map{'method':'xml','item-separator':'&'})`, "a&amp;b"},
		{"XML declaration emitted once across documents", `serialize((parse-xml('<a/>'),parse-xml('<b/>')),map{'method':'xml','omit-xml-declaration':false(),'indent':false()})`, `<?xml version="1.0" encoding="UTF-8"?><a/><b/>`},
		{"XML normalizes across a text boundary", `serialize((parse-xml('<r>e</r>')/r/text(),codepoints-to-string(769)),map{'method':'xml','normalization-form':'NFC'})`, "é"},
		{"text excludes comments and processing instructions", `serialize(parse-xml-fragment('<!--c--><?p v?><r>text</r>')/node(),map{'method':'text'})`, "text"},
		{"parameter document sets method and separator", `serialize((1,2),parse-xml('<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><method value="text"/><item-separator value="/"/></serialization-parameters>')/*)`, "1/2"},
		{"XML CDATA applies only to named elements", `serialize(parse-xml('<r><a>&lt;x&gt;</a><b>&lt;y&gt;</b></r>'),map{'method':'xml','cdata-section-elements':QName('','a')})`, `<r><a><![CDATA[<x>]]></a><b>&lt;y&gt;</b></r>`},
		{"adaptive format preserves nested sequence members", `serialize([(1,2),(),map{'k':(3,4)}],map{'method':'adaptive'})`, `[(1,2),(),map{"k":(3,4)}]`},
		{"adaptive distinguishes function names and arities", `serialize((string#1,function($x){$x},QName('urn:q','q:n')),map{'method':'adaptive','item-separator':'/'})`, `fn:string#1/(anonymous-function)#1/Q{urn:q}n`},
		{"adaptive includes standalone attribute and namespace nodes", `let $r := parse-xml('<r xmlns:q="urn:q" a="&amp;&quot;"/>')/r return serialize(($r/@a,$r/namespace::q),map{'method':'adaptive','item-separator':' '})`, `a="&amp;&quot;" xmlns:q="urn:q"`},
		{"JSON null and nested arrays", `serialize([true(),(),['x',3]],map{'method':'json','indent':false()})`, `[true,null,["x",3]]`},
		{"JSON renders nodes using selected method", `serialize(parse-xml('<r>x&amp;y</r>')/r,map{'method':'json','json-node-output-method':'text'})`, `"x&y"`},
		{"text character map replaces the configured character", `serialize('café',map{'method':'text','use-character-maps':map{'é':'[e]'}})`, `caf[e]`},
	})
}

func TestFnSerializeParameterDocuments(t *testing.T) {
	t.Parallel()

	const element = `<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization">`
	const closeElement = `</o:serialization-parameters>`
	assertFunctionResults(t, []functionResultCase{
		{
			"xml_parameter_document_controls_declaration",
			`serialize(parse-xml('<r/>'), parse-xml('` + element + `<o:version value="1.1"/><o:encoding value="UTF-8"/><o:omit-xml-declaration value="0"/><o:standalone value="true"/>` + closeElement + `')/*)`,
			`<?xml version="1.1" encoding="UTF-8" standalone="yes"?><r/>`,
		},
		{
			"json_node_method_is_independent_of_top_level_method",
			`serialize(parse-xml('<r>é&amp;x</r>')/*, parse-xml('` + element + `<o:method value="Q{}json"/><o:json-node-output-method value="Q{}text"/>` + closeElement + `')/*)`,
			`"é&x"`,
		},
		{
			"html_metadata_uses_supplied_media_type_and_encoding",
			`serialize(parse-xml('<html><head/><body>é🙂</body></html>'), parse-xml('` + element + `<o:method value="html"/><o:html-version value="5"/><o:media-type value=" text/example "/><o:encoding value="ISO-8859-1"/>` + closeElement + `')/*)`,
			"<!DOCTYPE html>\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/example; charset=ISO-8859-1\"></head><body>é&#x1F642;</body></html>",
		},
		{
			"xhtml_metadata_uses_supplied_media_type_and_encoding",
			`serialize(parse-xml('<html xmlns="http://www.w3.org/1999/xhtml"><head/><body/></html>'), parse-xml('` + element + `<o:method value="xhtml"/><o:html-version value="5"/><o:media-type value="application/xhtml+xml"/><o:encoding value="UTF-8"/>` + closeElement + `')/*)`,
			`<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="application/xhtml+xml; charset=UTF-8" /></head><body></body></html>`,
		},
		{
			"text_nfd_decomposes_without_altering_item_separator",
			`serialize(('é','Å'), parse-xml('` + element + `<o:method value="text"/><o:item-separator value=" + "/><o:normalization-form value="NFD"/>` + closeElement + `')/*)`,
			"e\u0301 + A\u030a",
		},
		{
			"text_nfkc_applies_compatibility_mappings",
			`serialize('ﬃ①', parse-xml('` + element + `<o:method value="text"/><o:normalization-form value="NFKC"/>` + closeElement + `')/*)`,
			"ffi1",
		},
		{
			"text_nfkd_decomposes_compatibility_mappings",
			`serialize('ǆ', parse-xml('` + element + `<o:method value="text"/><o:normalization-form value="NFKD"/>` + closeElement + `')/*)`,
			"dz\u030c",
		},
	})
}

func TestFnSerializeParameterDocumentErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, expression, code string }{
		{"rejects_parameter_document_node", `serialize('sample',parse-xml('<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization"/>'))`, "XPTY0004"},
		{"rejects_atomic_parameter_argument", `serialize('sample','text')`, "XPTY0004"},
		{"rejects_multiple_parameter_items", `let $p:=parse-xml('<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization"/>')/* return serialize('sample',($p,$p))`, "XPTY0004"},
		{"extension_method_valid_but_unsupported", `serialize('sample',parse-xml('<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization" xmlns:p="urn:items"><o:method value="p:custom"/></o:serialization-parameters>')/*)`, "SEPM0016"},
		{"omit_declaration_conflicts_with_standalone", `serialize(parse-xml('<r/>'),parse-xml('<o:serialization-parameters xmlns:o="http://www.w3.org/2010/xslt-xquery-serialization"><o:standalone value="false"/></o:serialization-parameters>')/*)`, "SEPM0009"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				result, err := evaluateFunctionExpression(t, tc.expression, mode)
				if xdm.SequenceLen(result) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("serialize result = %v, error = %v; want empty result and %s", result, err, tc.code)
				}
			})
		}
	}
}

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

func TestValidateSerializeOptions(t *testing.T) {
	t.Parallel()
	const document = `let $d := parse-xml('<r/>') return `
	assertFunctionResults(t, []functionResultCase{
		{"XML 1.1 permits undeclaring prefixes", document + `serialize($d, map{'method':'xml','version':'1.1','omit-xml-declaration':false(),'undeclare-prefixes':true()})`, `<?xml version="1.1" encoding="UTF-8"?><r/>`},
		{"text method ignores XML prefix undeclarations", `serialize('text', map{'method':'text','undeclare-prefixes':true()})`, "text"},
		{"XML 1.0 permits a doctype without a declaration", document + `serialize($d, map{'method':'xml','version':'1.0','doctype-system':'catalog.dtd'})`, `<!DOCTYPE r SYSTEM "catalog.dtd"><r/>`},
	})

	for _, tc := range []struct{ name, options, code string }{
		{"XML version rejected with declaration omitted", `map{'method':'xml','version':'1.2'}`, "SESU0013"},
		{"HTML version rejected", `map{'method':'html','html-version':8}`, "SESU0013"},
		{"XML 1.0 prefix undeclarations rejected", `map{'method':'xml','undeclare-prefixes':true()}`, "SEPM0010"},
		{"XML 1.1 doctype requires the declaration", `map{'method':'xml','version':'1.1','doctype-system':'catalog.dtd'}`, "SEPM0009"},
		{"unsupported normalization rejected on an empty element", `map{'method':'xml','normalization-form':'fully-normalized'}`, "SESU0011"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				source := document + `serialize($d, ` + tc.options + `)`
				seq, err := evaluateFunctionExpression(t, source, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Fatalf("%s = %v, %v; want no result and %s", source, seq, err, tc.code)
				}
			})
		}
	}
}
