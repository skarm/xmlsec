package xpath //nolint:testpackage // Exercise QName casts in explicit namespace contexts.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestCastToQName(t *testing.T) {
	t.Parallel()

	namespaces := map[string]string{"": "urn:default", "p": "urn:prefix", "fn": ""}
	xpathContext := &evalContext{namespaces: namespaces}
	xsdContext := &evalContext{namespaces: namespaces, qnameValueNoDefaultNS: true}
	existing := xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:original"}

	cases := []struct {
		name     string
		value    xdm.AtomicValue
		context  *evalContext
		want     xdm.QNameValue
		wantCode string
	}{
		{"typed_qname_retains_expanded_name", xdm.AtomicValue{TypeName: xdm.TypeQName, Value: existing}, xpathContext, existing, ""},
		{"notation_retains_expanded_name", xdm.AtomicValue{TypeName: xdm.TypeNOTATION, Value: existing}, xpathContext, existing, ""},
		{"explicit_prefix_on_string_subtype", xdm.AtomicValue{TypeName: xdm.TypeToken, Value: "p:name"}, xpathContext, xdm.QNameValue{Prefix: "p", Local: "name", URI: "urn:prefix"}, ""},
		{"default_namespace_applies_in_xpath", xdm.AtomicValue{TypeName: xdm.TypeUntypedAtomic, Value: "name"}, xpathContext, xdm.QNameValue{Local: "name", URI: "urn:default"}, ""},
		{"xsd_value_ignores_xpath_default", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "name"}, xsdContext, xdm.QNameValue{Local: "name"}, ""},
		{"predeclared_prefix_is_resolved", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "xs:string"}, nil, xdm.QNameValue{Prefix: "xs", Local: "string", URI: NSXS}, ""},
		{"explicit_empty_binding_hides_predeclared_prefix", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "fn:name"}, xpathContext, xdm.QNameValue{}, "FONS0004"},
		{"undeclared_prefix", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "unknown:name"}, xpathContext, xdm.QNameValue{}, "FONS0004"},
		{"invalid_lexical_name", xdm.AtomicValue{TypeName: xdm.TypeString, Value: "p:1name"}, xpathContext, xdm.QNameValue{}, "FORG0001"},
		{"incompatible_source_type", xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: true}, xpathContext, xdm.QNameValue{}, "XPTY0004"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := castToQName(tc.value, tc.context)
			if tc.wantCode != "" {
				if !errors.Is(err, &xdm.Error{Code: tc.wantCode}) {
					t.Errorf("castToQName(%#v): %v, want %s", tc.value, err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("castToQName(%#v): %v", tc.value, err)
			}
			if want := (xdm.AtomicValue{TypeName: xdm.TypeQName, Value: tc.want}); got != want {
				t.Errorf("castToQName(%#v) = %#v, want %#v", tc.value, got, want)
			}
		})
	}
}
