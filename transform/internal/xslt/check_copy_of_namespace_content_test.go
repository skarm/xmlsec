package xslt //nolint:testpackage // Exercises copy instruction contracts within the executor.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestCheckCopyOfNamespaceContent(t *testing.T) {
	t.Parallel()

	doc := parseTestDocument(t, `<root xmlns:q="urn:value"><child ref="q:value">q:value</child></root>`)
	root := doc.DocumentElement()
	child, ok := xdm.AsNode[*xdm.Element](root.FirstChild())
	if !ok {
		t.Fatal("source child is not an element")
	}
	attribute := child.Attributes()[0]

	for _, tc := range []struct {
		name        string
		node        xdm.Node
		annotated   xdm.Node
		annotation  string
		keepBinding bool
		wantCode    string
	}{
		{"element_can_keep_qname_content_with_bindings", root, child, xdm.TypeQName, true, ""},
		{"stripping_cannot_remove_qname_binding_from_descendant", root, child, xdm.TypeQName, false, "XTTE0950"},
		{"stripping_cannot_remove_notation_binding_from_attribute", root, attribute, xdm.TypeNOTATION, false, "XTTE0950"},
		{"standalone_qname_attribute_cannot_keep_binding", attribute, attribute, xdm.TypeQName, true, "XTTE0950"},
		{"prefixed_string_is_not_a_namespace_sensitive_value", root, child, xdm.TypeString, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ec := &execContext{typeAnnotations: map[xdm.Node]string{tc.annotated: tc.annotation}}
			err := ec.checkCopyOfNamespaceContent(tc.node, tc.keepBinding)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("namespace check: %v", err)
				}
				return
			}
			var detail *XSLTError
			if !errors.As(err, &detail) || detail.Code != tc.wantCode {
				t.Fatalf("namespace check error = %v; want %s", err, tc.wantCode)
			}
		})
	}
}
