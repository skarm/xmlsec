package xpath //nolint:testpackage // Runs serialization functions through both internal evaluation paths.

import (
	"errors"
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
