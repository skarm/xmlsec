package xpath //nolint:testpackage // Exercises serializing values with XML-supplied parameters.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

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
