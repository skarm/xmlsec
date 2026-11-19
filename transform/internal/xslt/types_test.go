package xslt //nolint:testpackage // Tests cardinality after atomization and XSLT function conversion directly.

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestSequenceTypeCardinality(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		typeName     string
		acceptsCount [3]bool // Expected acceptance for zero, one and two items.
	}{
		{"default item sequence", "", [3]bool{true, true, true}},
		{"empty sequence", "empty-sequence()", [3]bool{true, false, false}},
		{"optional", "xs:integer?", [3]bool{true, true, false}},
		{"zero or more", "xs:integer*", [3]bool{true, true, true}},
		{"exactly one", "xs:integer", [3]bool{false, true, false}},
		{"one or more", "xs:integer+", [3]bool{false, true, true}},
		{"nested comments before occurrence", "xs:integer (: outer (: inner :) :) ?", [3]bool{true, true, false}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := allowsEmptySequence(test.typeName); got != test.acceptsCount[0] {
				t.Fatalf("allows empty %q = %v", test.typeName, got)
			}
			for size := 0; size <= 2; size++ {
				seq := make(xdm.ItemSlice, size)
				for i := range seq {
					seq[i] = xdm.AtomicValue{TypeName: "xs:integer", Value: int64(i)}
				}
				sequenceType := parseSequenceType(test.typeName)
				got, err := checkSequenceType(t.Context(), seq, sequenceType, "XTTE0570", "test variable")
				if test.acceptsCount[size] {
					if err != nil || xdm.SequenceLen(got) != size {
						t.Fatalf("%q size %d = %v, %v", test.typeName, size, got, err)
					}
				} else {
					var detail *XSLTError
					if got != nil || !errors.As(err, &detail) || detail.Code != "XTTE0570" {
						t.Fatalf("%q size %d = %v, %v; want XTTE0570", test.typeName, size, got, err)
					}
				}
			}
		})
	}
}

func TestSequenceTypeAtomizationBeforeCardinality(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		seq      xdm.Sequence
		typeName string
		want     []string
		wantErr  bool
	}{
		{"array expands", xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{stringItem("a"), stringItem("b")}})}, "xs:string+", []string{"a", "b"}, false},
		{"expanded cardinality checked", xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{xdm.ItemSlice{stringItem("a"), stringItem("b")}})}, "xs:string", nil, true},
		{"empty array atomizes to empty", xdm.ItemSlice{xdm.NewArray(nil)}, "xs:string*", nil, false},
		{"empty member atomizes to empty", xdm.ItemSlice{xdm.NewArray([]xdm.Sequence{nil})}, "xs:string?", nil, false},
		{"empty-sequence test does not atomize array", xdm.ItemSlice{xdm.NewArray(nil)}, "empty-sequence()", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := checkSequenceType(t.Context(), test.seq, parseSequenceType(test.typeName), "XTTE0570", "test variable")
			if test.wantErr {
				var detail *XSLTError
				if got != nil || !errors.As(err, &detail) || detail.Code != "XTTE0570" {
					t.Fatalf("converted = %v, %v; want XTTE0570", got, err)
				}
				return
			}
			if err != nil || xdm.SequenceLen(got) != len(test.want) {
				t.Fatalf("converted = %v, %v; want %d items", got, err, len(test.want))
			}
			for i, want := range test.want {
				atom, ok := got.Get(i).(xdm.AtomicValue)
				if !ok || atom.TypeName != "xs:string" || atom.Value != want {
					t.Fatalf("atom %d = %+v; want xs:string %q", i, got.Get(i), want)
				}
			}
		})
	}
}

func TestSequenceTypePreservesNodeIdentity(t *testing.T) {
	t.Parallel()
	original := xdm.NewDefaultDocument().CreateText("a")
	got, err := checkSequenceType(t.Context(), xdm.ItemSlice{xdm.NodeItem{Node: original}}, parseSequenceType("text()"), "XTTE0570", "test variable")
	if err != nil || xdm.SequenceLen(got) != 1 {
		t.Fatalf("node type check = %v, %v", got, err)
	}
	node, ok := got.Get(0).(xdm.NodeItem)
	if !ok || node.Node != original {
		t.Fatal("node identity changed during type checking")
	}
}

func TestFunctionWildcardAcceptsArrayValue(t *testing.T) {
	t.Parallel()

	for _, itemType := range []string{"function(*)", "(function(*))", "((function(*)))"} {
		t.Run(itemType, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", `<xsl:variable name="colors" as="`+itemType+`" select="['red', 'blue']"/>
				<xsl:value-of select="$colors(2)"/>`)
			got, err := ss.Transform(parseTestDocument(t, "<r/>")).Serialize(t.Context())
			requireSerialization(t, got, err, "blue", "")
		})
	}
}

func TestSequenceTypeAtomicConversions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input xdm.AtomicValue
		as    string
		kind  string
		value string
	}{
		{xdm.AtomicValue{TypeName: "xs:untypedAtomic", Value: "42"}, "xs:integer", "xs:integer", "42"},
		{xdm.AtomicValue{TypeName: "xs:integer", Value: int64(42)}, "xs:double", "xs:double", "42"},
		{xdm.AtomicValue{TypeName: "xs:integer", Value: int64(42)}, "xs:decimal", "xs:integer", "42"},
		{xdm.AtomicValue{TypeName: "xs:anyURI", Value: "https://example.test/"}, "xs:string", "xs:string", "https://example.test/"},
	} {
		got, err := checkSequenceType(t.Context(), xdm.SingleAtomic(test.input), parseSequenceType(test.as), "XTTE0790", "function argument")
		if err != nil || xdm.SequenceLen(got) != 1 {
			t.Fatalf("convert %+v to %s = %v, %v", test.input, test.as, got, err)
		}
		atom, ok := got.Get(0).(xdm.AtomicValue)
		if !ok {
			t.Fatalf("converted to non-atomic %T", got.Get(0))
		}
		value, err := xpath.AtomicToString(atom)
		if err != nil || atom.TypeName != test.kind || value != test.value {
			t.Fatalf("convert %+v to %s = %+v (%q), %v", test.input, test.as, atom, value, err)
		}
	}
	got, err := checkSequenceType(t.Context(), xdm.ItemSlice{stringItem("valid"), xdm.AtomicValue{TypeName: "xs:integer", Value: int64(1)}}, parseSequenceType("xs:string+"), "XTTE0790", "function argument")
	var detail *XSLTError
	if got != nil || !errors.As(err, &detail) || detail.Code != "XTTE0790" {
		t.Fatalf("partial type failure = %v, %v", got, err)
	}
}

func TestVariableURIPromotion(t *testing.T) {
	t.Parallel()
	for _, profile := range []struct {
		version   string
		processor int
	}{
		{"2.0", processorXSLT20},
		{"3.0", processorXSLT30},
	} {
		t.Run(profile.version, func(t *testing.T) {
			t.Parallel()
			for _, tc := range []struct{ name, declared, supplied, want, code string }{
				{"string is not a URI", "xs:anyURI", "'urn:sample'", "", errCodeXTTE0570},
				{"explicit URI constructor", "xs:anyURI", "xs:anyURI('urn:sample')", "true", ""},
				{"untyped becomes URI", "xs:anyURI", "xs:untypedAtomic('urn:sample')", "true", ""},
				{"URI promotes to string", "xs:string", "xs:anyURI('urn:sample')", "true", ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="` + profile.version + `">
						<xsl:output method="text"/>
						<xsl:template name="start">
							<xsl:variable name="value" as="` + tc.declared + `" select="` + tc.supplied + `"/>
							<xsl:value-of select="$value instance of ` + tc.declared + ` and string($value) eq 'urn:sample'"/>
						</xsl:template>
					</xsl:stylesheet>`
					compiled, err := NewCompiler().ProcessorVersion(profile.processor).Compile(t.Context(), parseTestDocument(t, source))
					if err != nil {
						t.Fatal(err)
					}

					got, err := compiled.CallTemplate("start").Serialize(t.Context())
					requireSerialization(t, got, err, tc.want, tc.code)
				})
			}
		})
	}
}

func TestCanonicalNameTestExplicitNamespace(t *testing.T) {
	for _, tc := range []struct{ source, want string }{{"Q{}n", "Q{}n"}, {"Q{urn:other}n", "Q{urn:other}n"}, {"n", "Q{urn:default}n"}} {
		t.Run(tc.source, func(t *testing.T) {
			ast, err := xpath.Parse(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			var path xpath.LocationPath
			switch v := ast.(type) {
			case xpath.LocationPath:
				path = v
			case *xpath.LocationPath:
				path = *v
			default:
				t.Fatalf("path=%#v", ast)
			}
			if len(path.Steps) != 1 {
				t.Fatalf("steps=%#v", path)
			}
			var b strings.Builder
			w := canonicalTypeWriter{b: &b, defaultElemNS: "urn:default", hasDefaultElemNS: true}
			w.nodeTest(path.Steps[0].NodeTest)
			if b.String() != tc.want {
				t.Errorf("actual %q; expected %q", b.String(), tc.want)
			}
		})
	}
}

func TestSequenceTypeElementNameWithCommaInNamespace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, declared, selection, source, want, code string }{
		{"qualified element", "element(Q{urn:example,a}n)", "/*", `<n xmlns="urn:example,a"/>`, "n", ""},
		{"qualified element with annotation", "element(Q{urn:example,(a)}n, xs:anyType)", "/*", `<n xmlns="urn:example,(a)"/>`, "n", ""},
		{"qualified document root", "document-node(element(Q{urn:example,a}n))", "/", `<n xmlns="urn:example,a"/>`, "n", ""},
		{"different namespace", "element(Q{urn:example,a}n)", "/*", `<n xmlns="urn:example,b"/>`, "", errCodeXTTE0570},
		{"explicit no namespace", "element(Q{}n)", "/*", `<n/>`, "n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ss := compileTestStylesheet(t, "", `<xsl:variable name="value" as="`+tc.declared+`" select="`+tc.selection+`"/>`+
				`<xsl:value-of select="local-name(($value/descendant-or-self::*)[1])"/>`)
			got, err := ss.Transform(parseTestDocument(t, tc.source)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestSequenceTypeDocumentChildConstraints(t *testing.T) {
	t.Parallel()

	const typedDocument = "document-node(element(r))"
	for _, tc := range []struct{ name, declared, fragment, want, code string }{
		{"element only", typedDocument, `&lt;r/>`, "1", ""},
		{"comment and processing instruction", typedDocument, `&lt;!--before-->&lt;r/>&lt;?keep value?>`, "1", ""},
		{"no element", typedDocument, `&lt;!--only a comment-->`, "", errCodeXTTE0570},
		{"second element", typedDocument, `&lt;r/>&lt;s/>`, "", errCodeXTTE0570},
		{"text sibling", typedDocument, `text&lt;r/>`, "", errCodeXTTE0570},
		{"CDATA sibling", typedDocument, `&lt;r/>&lt;![CDATA[text]]&gt;`, "", errCodeXTTE0570},
		{"document node without an element test", "document-node()", `text&lt;r/>&lt;s/>`, "2", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ss := compileTestStylesheet(t, "", `<xsl:variable name="value" as="`+tc.declared+`" select="parse-xml-fragment('`+tc.fragment+`')"/>
			<xsl:value-of select="count($value/*)"/>`)
			got, err := ss.Transform(parseTestDocument(t, `<source/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, tc.code)
		})
	}
}

func TestReviewDerivedIntegerConversionRejectsUnrelatedType(t *testing.T) {
	for _, tc := range []struct{ name, as, selectValue string }{
		{"base to derived", "xs:positiveInteger", "-1"},
		{"sibling derived", "xs:nonNegativeInteger", "xs:negativeInteger('-1')"},
		{"narrow integer", "xs:byte", "256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ss := compileTestStylesheet(t, "", `<xsl:variable name="value" as="`+tc.as+`" select="`+tc.selectValue+`"/><xsl:value-of select="$value"/>`)
			got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
			requireSerialization(t, got, err, "", "XTTE0570")
		})
	}
}

func TestReviewExpandedAtomicTypeName(t *testing.T) {
	ss := compileTestStylesheet(t, "", `<xsl:variable name="value" as="Q{http://www.w3.org/2001/XMLSchema}integer" select="1"/><xsl:value-of select="$value"/>`)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "1", "")
}
