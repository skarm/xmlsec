package tree_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestParseDTDTextPreservesTypedAttributeDefaults(t *testing.T) {
	t.Parallel()

	const input = `<!DOCTYPE catalog [
		<!ELEMENT catalog (#PCDATA|entry)*>
		<!ELEMENT entry EMPTY>
		<!NOTATION png SYSTEM "image/png">
		<!NOTATION svg PUBLIC "  -//Example   SVG//EN  ">
		<!ENTITY logo SYSTEM "logo.svg" NDATA svg>
		<!ATTLIST catalog id ID #REQUIRED
			primary IDREF #IMPLIED related IDREFS #IMPLIED
			mode ( full | summary ) 'full'
			format NOTATION ( png | svg ) #FIXED 'svg'
			raw CDATA ' a  b ' note CDATA #IMPLIED>
		<!ATTLIST catalog mode ( full | summary ) 'summary'>
	]><catalog id=" item " primary=" first " related=" first  second " note="quote: &quot;&apos;" />`
	const base = "urn:catalog:example"
	options := treepkg.ParseOptions{Limits: treepkg.DefaultLimits(), AllowDTD: true, BaseURI: base}

	doc, err := options.ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	root := treepkg.Root(doc)
	attrs := make(map[string]string, len(root.Attrs))
	for _, attr := range root.Attrs {
		attrs[attr.Name.Local] = attr.Value
	}
	want := map[string]string{
		"id": "item", "primary": "first", "related": "first second",
		"mode": "full", "format": "svg", "raw": " a  b ", "note": "quote: \"'",
	}
	if !maps.Equal(attrs, want) {
		t.Errorf("catalog attributes = %q, want %q", attrs, want)
	}
	for name, kind := range map[string]treepkg.DTDAttributeType{
		"id": treepkg.DTDID, "primary": treepkg.DTDIDRef, "related": treepkg.DTDIDRefs,
		"mode": treepkg.DTDNoType, "format": treepkg.DTDNoType,
	} {
		if got := treepkg.AttributeDTDType(doc, root, treepkg.Name{Local: name}); got != kind {
			t.Errorf("DTD type of %s = %v, want %v", name, got, kind)
		}
	}
	dtd, ok := doc.DTD()
	if !ok || dtd.Name != "catalog" {
		t.Fatalf("document type = %+v, %v, want catalog", dtd, ok)
	}
	wantNotations := map[string]treepkg.Notation{
		"png": {SystemID: "image/png", BaseURI: base},
		"svg": {PublicID: "-//Example SVG//EN", BaseURI: base},
	}
	if !maps.Equal(dtd.Notations, wantNotations) {
		t.Errorf("notations = %+v, want %+v", dtd.Notations, wantNotations)
	}
	wantEntities := map[string]treepkg.UnparsedEntity{
		"logo": {SystemID: "logo.svg", BaseURI: base, Notation: "svg"},
	}
	if !maps.Equal(dtd.UnparsedEntities, wantEntities) {
		t.Errorf("unparsed entities = %+v, want %+v", dtd.UnparsedEntities, wantEntities)
	}
}

func TestParseDTDTextPreservesDocumentAndDeclarationNodes(t *testing.T) {
	t.Parallel()

	const input = "\uFEFF<?xml version='1.7' standalone='yes'?>\r\n" +
		"<?before ready ?>\r<!DOCTYPE r [<?directory catalog ?>]><r>" +
		"<!--note\r\ncontinued--><![CDATA[a & <]]>&#13;<?within done ?></r><?after finish ?>"
	const base = "urn:xml:input"
	options := treepkg.ParseOptions{Limits: treepkg.DefaultLimits(), AllowDTD: true, BaseURI: base}

	doc, err := options.ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	type nodeValue struct {
		kind treepkg.Kind
		name string
		text string
	}
	values := func(nodes []*treepkg.Node) []nodeValue {
		list := make([]nodeValue, 0, len(nodes))
		for _, node := range nodes {
			list = append(list, nodeValue{node.Kind, node.Name.Local, node.Data})
		}
		return list
	}
	wantTop := []nodeValue{
		{treepkg.PINode, "before", "ready "},
		{treepkg.ElementNode, "r", ""},
		{treepkg.PINode, "after", "finish "},
	}
	if got := values(treepkg.Children(doc)); !slices.Equal(got, wantTop) {
		t.Errorf("document children = %#v, want %#v", got, wantTop)
	}
	wantChildren := []nodeValue{
		{treepkg.CommentNode, "", "note\ncontinued"},
		{treepkg.TextNode, "", "a & <\r"},
		{treepkg.PINode, "within", "done "},
	}
	if got := values(treepkg.Root(doc).Children); !slices.Equal(got, wantChildren) {
		t.Errorf("root children = %#v, want %#v", got, wantChildren)
	}
	dtd, ok := doc.DTD()
	wantInstructions := []treepkg.ProcessingInstruction{{Target: "directory", Data: "catalog ", BaseURI: base}}
	if !ok || !slices.Equal(dtd.ProcessingInstructions, wantInstructions) {
		t.Errorf("DTD instructions = %+v, %v, want %+v", dtd.ProcessingInstructions, ok, wantInstructions)
	}
}

func TestParseDTDTextRejectsMalformedDeclarations(t *testing.T) {
	t.Parallel()

	options := treepkg.ParseOptions{Limits: treepkg.DefaultLimits(), AllowDTD: true}
	for _, tc := range []struct{ name, input string }{
		{"empty-enumeration", `<!DOCTYPE r [<!ATTLIST r mode () #IMPLIED>]><r/>`},
		{"missing-enumeration-token", `<!DOCTYPE r [<!ATTLIST r mode (full|) #IMPLIED>]><r/>`},
		{"qualified-notation-token", `<!DOCTYPE r [<!ATTLIST r format NOTATION (image:png) #IMPLIED>]><r/>`},
		{"missing-public-system-separator", `<!DOCTYPE r PUBLIC "example""fixture.dtd"><r/>`},
		{"literal-less-than-in-attribute", `<!DOCTYPE r><r value="a<b"/>`},
		{"duplicate-attribute", `<!DOCTYPE r><r value="a" value="b"/>`},
		{"cdata-before-root", `<!DOCTYPE r><![CDATA[leading]]><r/>`},
		{"cdata-after-root", `<!DOCTYPE r><r/><![CDATA[trailing]]>`},
		{"unterminated-cdata", `<!DOCTYPE r><r><![CDATA[text</r>`},
		{"unsupported-version-number", `<?xml version="1.x"?><!DOCTYPE r><r/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := options.ParseText(t.Context(), tc.input)
			if doc != nil || !errors.Is(err, treepkg.ErrMalformed) {
				t.Fatalf("ParseText(%q) = %v, %v, want nil document and ErrMalformed", tc.input, doc, err)
			}
		})
	}
}

func TestParseDTDTextLimitAndCancellation(t *testing.T) {
	t.Parallel()

	const input = `<!DOCTYPE r [<!ATTLIST r name CDATA "a" label CDATA "b">]><r/>`
	limits := treepkg.DefaultLimits()
	limits.MaxAttributesPerElement = 1
	options := treepkg.ParseOptions{Limits: limits, AllowDTD: true}
	if doc, err := options.ParseText(t.Context(), input); doc != nil || !errors.Is(err, treepkg.ErrLimit) {
		t.Errorf("attribute limit = %v, %v, want nil document and ErrLimit", doc, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	options.Limits = treepkg.DefaultLimits()
	if doc, err := options.ParseText(ctx, input); doc != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled parse = %v, %v, want nil document and context.Canceled", doc, err)
	}
	options.Limits.MaxBytes = len(input) - 1
	if doc, err := options.ParseText(t.Context(), input); doc != nil || !errors.Is(err, treepkg.ErrLimit) {
		t.Errorf("input limit = %v, %v, want nil document and ErrLimit", doc, err)
	}
}

func TestParseDTDTextExplicitAttributeOverridesDefault(t *testing.T) {
	t.Parallel()

	const input = `<!DOCTYPE r [<!ATTLIST r a CDATA 'first' b CDATA 'default'>
		<!ATTLIST r a CDATA 'second'>]><r b="explicit"/>`
	options := treepkg.ParseOptions{Limits: treepkg.DefaultLimits(), AllowDTD: true}
	doc, err := options.ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if attrs := treepkg.Root(doc).Attrs; len(attrs) != 2 {
		t.Fatalf("root attributes = %+v, want one a and one b", attrs)
	}
	for name, want := range map[string]string{"a": "first", "b": "explicit"} {
		if got, ok := doc.Root().Attribute(treepkg.Name{Local: name}); !ok || got != want {
			t.Errorf("attribute %s = %q, %v, want %q", name, got, ok, want)
		}
	}
}
