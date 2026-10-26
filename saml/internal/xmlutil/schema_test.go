package xmlutil_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

func TestAttributeSchemaPresenceAndNamespaces(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, xml string
		valid     bool
	}{
		{"required and optional", `<r id="a" optional="b"/>`, true},
		{"present empty", `<r id=""/>`, true},
		{"namespace declaration", `<r xmlns:p="urn:p" id="a"/>`, true},
		{"missing required", `<r optional="b"/>`, false},
		{"undeclared attribute", `<r id="a" extra="b"/>`, false},
		{"qualified lookalike", `<r xmlns:p="urn:p" p:id="a"/>`, false},
		{"qualified optional", `<r xmlns:p="urn:p" id="a" p:optional="b"/>`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := xmlutil.Attrs(parseSchemaElement(t, test.xml), []string{"id"}, []string{"optional"})
			if test.valid && err != nil || !test.valid && !errors.Is(err, profile.ErrSchema) {
				t.Fatalf("Attrs = %v; want valid=%v", err, test.valid)
			}
		})
	}
}

func TestBooleanAttributeAbsenceAndLexicalValue(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, xml string
		want      bool
		valid     bool
	}{
		{"absent", `<r/>`, false, true},
		{"true", `<r flag="true"/>`, true, true},
		{"whitespace and character references", `<r flag=" &#x9;1&#xD;&#xA; "/>`, true, true},
		{"false", `<r flag=" false "/>`, false, true},
		{"zero", `<r flag="0"/>`, false, true},
		{"foreign attribute is not the unqualified attribute", `<r xmlns:p="urn:p" p:flag="true"/>`, false, true},
		{"present empty", `<r flag=""/>`, false, false},
		{"whitespace only", `<r flag=" &#x9; "/>`, false, false},
		{"case sensitive", `<r flag="True"/>`, false, false},
		{"non XML whitespace", `<r flag="&#xA0;true"/>`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := xmlutil.BoolAttr(parseSchemaElement(t, test.xml), "flag")
			if test.valid {
				if err != nil || got != test.want {
					t.Fatalf("BoolAttr = %v, %v; want %v", got, err, test.want)
				}
			} else if !errors.Is(err, profile.ErrSchema) {
				t.Fatalf("BoolAttr accepted invalid value: %v, %v", got, err)
			}
		})
	}
}

func TestDirectChildRequiresOneExpandedName(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, xml string
		valid     bool
	}{
		{"one direct child", `<r xmlns:p="urn:expected"><p:item>chosen</p:item></r>`, true},
		{"foreign and nested names do not collide", `<r xmlns:p="urn:expected" xmlns:q="urn:other"><q:item/><p:item>chosen</p:item><wrapper><p:item/></wrapper></r>`, true},
		{"same expanded name with different prefixes", `<r xmlns:p="urn:expected" xmlns:q="urn:expected"><p:item/><q:item/></r>`, false},
		{"only foreign child", `<r xmlns:q="urn:other"><q:item/></r>`, false},
		{"only descendant", `<r xmlns:p="urn:expected"><wrapper><p:item/></wrapper></r>`, false},
		{"no children", `<r/>`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := xmlutil.Direct(parseSchemaElement(t, test.xml), xmlutil.Name("urn:expected", "item"))
			if !test.valid {
				if !errors.Is(err, profile.ErrSchema) || got.Valid() {
					t.Fatalf("Direct = %v, %v; want invalid element and ErrSchema", got.Name(), err)
				}
				return
			}
			if err != nil || got.Name() != (document.Name{Space: "urn:expected", Local: "item"}) {
				t.Fatalf("Direct selected %v: %v", got.Name(), err)
			}
			if text, err := xmlutil.Simple(got, 6); err != nil || text != "chosen" {
				t.Fatalf("Direct selected wrong content: %q, %v", text, err)
			}
		})
	}
}

func TestChildrenRejectMixedContent(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, xml string
		valid     bool
	}{
		{"whitespace comments and PI", "<r> \t<!--ignored--><?ignored ok?><a/><b/>\n</r>", true},
		{"CDATA whitespace", `<r><![CDATA[  ]]><a/><b/></r>`, true},
		{"text before child", `<r>text<a/><b/></r>`, false},
		{"text after child", `<r><a/><b/>text</r>`, false},
		{"non XML whitespace", `<r>&#xA0;<a/><b/></r>`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			children, err := xmlutil.Children(parseSchemaElement(t, test.xml))
			if !test.valid {
				if !errors.Is(err, profile.ErrSchema) || children != nil {
					t.Fatalf("mixed content returned %d children, %v", len(children), err)
				}
				return
			}
			var names []string
			for _, child := range children {
				names = append(names, child.Name().Local)
			}
			if err != nil || !slices.Equal(names, []string{"a", "b"}) {
				t.Fatalf("Children = %v, %v; want [a b]", names, err)
			}
		})
	}
}

func TestXMLLimitsFillDefaultsWithoutWeakeningBudgets(t *testing.T) { //nolint:tparallel // Subtests read limits before the parent changes the byte limit.
	t.Parallel()

	want := document.DefaultLimits()
	want.MaxBytes = 10
	if got := xmlutil.XMLLimits(document.Limits{}, 10); got != want {
		t.Fatalf("default limits = %+v; want %+v", got, want)
	}
	limits := document.Limits{MaxBytes: 7, MaxDepth: 3, MaxNodes: 11, MaxAttributesPerElement: 2, MaxInScopeNamespaces: 4, MaxNodeSetNodes: 5}
	if got := xmlutil.XMLLimits(limits, 10); got != limits {
		t.Fatalf("explicit smaller limits changed: %+v; want %+v", got, limits)
	}
	defaults := document.DefaultLimits()
	for _, test := range []struct {
		name   string
		change func(input, expected *document.Limits)
	}{
		{"bytes", func(input, expected *document.Limits) { input.MaxBytes, expected.MaxBytes = 0, 10 }},
		{"depth", func(input, expected *document.Limits) { input.MaxDepth, expected.MaxDepth = 0, defaults.MaxDepth }},
		{"nodes", func(input, expected *document.Limits) { input.MaxNodes, expected.MaxNodes = 0, defaults.MaxNodes }},
		{"attributes", func(input, expected *document.Limits) {
			input.MaxAttributesPerElement, expected.MaxAttributesPerElement = 0, defaults.MaxAttributesPerElement
		}},
		{"namespaces", func(input, expected *document.Limits) {
			input.MaxInScopeNamespaces, expected.MaxInScopeNamespaces = 0, defaults.MaxInScopeNamespaces
		}},
		{"node sets", func(input, expected *document.Limits) {
			input.MaxNodeSetNodes, expected.MaxNodeSetNodes = 0, defaults.MaxNodeSetNodes
		}},
	} {
		t.Run("independently unset/"+test.name, func(t *testing.T) {
			input, expected := limits, limits
			test.change(&input, &expected)
			if got := xmlutil.XMLLimits(input, 10); got != expected {
				t.Fatalf("independent default = %+v; want %+v", got, expected)
			}
		})
	}
	limits.MaxBytes = 11
	want = limits
	want.MaxBytes = 10
	if got := xmlutil.XMLLimits(limits, 10); got != want || limits.MaxBytes != 11 {
		t.Fatalf("capacity clamp = %+v; want %+v; input=%+v", got, want, limits)
	}
}

func TestDocumentPublishesAnIndependentEscapedSnapshot(t *testing.T) {
	t.Parallel()

	root := xmlutil.Node("s", "urn:s", "Root")
	root.NS = []tree.Namespace{{Prefix: "s", URI: "urn:s"}}
	xmlutil.Set(root, "ID", "request")
	child := xmlutil.Node("s", "urn:s", "Value")
	xmlutil.Text(child, "<&")
	xmlutil.Add(root, child)
	doc, err := xmlutil.Document(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	root.Attrs[0].Value = "changed"
	child.Children[0].Data = "changed"
	if got := xmlutil.Attr(doc.Root(), "ID"); got != "request" {
		t.Fatal("draft mutation changed the published attribute", got)
	}
	value, err := xmlutil.Direct(doc.Root(), document.Name{Space: "urn:s", Local: "Value"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := xmlutil.Simple(value, 2); err != nil || got != "<&" {
		t.Fatal("draft mutation changed published text", got, err)
	}
	raw, err := doc.XML(t.Context())
	if err != nil || !strings.Contains(string(raw), "&lt;&amp;") || strings.Contains(string(raw), "changed") {
		t.Fatalf("snapshot was not independently escaped: %s, %v", raw, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := xmlutil.Document(ctx, root); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled publication succeeded", got, err)
	}
}

func TestInvalidElementsAndSimpleContentGuards(t *testing.T) {
	t.Parallel()

	var invalid document.Element
	if got, err := xmlutil.Children(invalid); got != nil || !errors.Is(err, profile.ErrSchema) {
		t.Fatal("invalid children", got, err)
	}
	if got, err := xmlutil.SimpleText(invalid, 1); got != "" || !errors.Is(err, profile.ErrSchema) {
		t.Fatal("invalid simple content", got, err)
	}
	if xmlutil.EmptyContent(invalid) {
		t.Fatal("invalid element treated as empty content")
	}
	for _, test := range []struct {
		xml    string
		budget int
	}{{`<r/>`, -1}, {`<r><child/></r>`, 10}, {`<r a="value"/>`, 10}} {
		if got, err := xmlutil.Simple(parseSchemaElement(t, test.xml), test.budget); got != "" || !errors.Is(err, profile.ErrSchema) {
			t.Fatalf("invalid simple content %q: %q, %v", test.xml, got, err)
		}
	}
}

func parseSchemaElement(t *testing.T, xml string) document.Element {
	t.Helper()
	doc, err := document.Parse(t.Context(), []byte(xml), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return doc.Root()
}
