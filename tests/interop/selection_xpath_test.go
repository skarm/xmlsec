//go:build interop

package interop_test

import "testing"

func TestSelectionXPathForOracle(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request canonicalRequest
		markers bool
		want    string
	}{
		{name: "omitted_selection", want: "-"},
		{name: "explicit_empty_selection", request: canonicalRequest{Select: &[]selector{}}, want: "/*[false()]"},
		{
			name:    "subtree_includes_attributes_and_namespaces",
			request: canonicalRequest{Subtree: []int{2}},
			want:    "/node()[2]/descendant-or-self::node() | /node()[2]/descendant-or-self::*/@* | /node()[2]/descendant-or-self::*/namespace::*",
		},
		{
			name: "attribute_uses_namespace_and_local_name",
			request: canonicalRequest{Select: &[]selector{
				{Kind: "attribute", Path: []int{1, 2}, Local: "name", Space: "urn:example"},
			}},
			want: "/node()[1]/node()[2]/@*[local-name()='name' and namespace-uri()='urn:example']",
		},
		{
			name:    "element_with_empty_default_namespace_marker",
			request: canonicalRequest{Select: &[]selector{{Kind: "element", Path: []int{1}}}},
			markers: true,
			want:    "/node()[1] | /node()[1]/namespace::*[name()='' and string()='']",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectionXPath(tc.request, tc.markers); got != tc.want {
				t.Errorf("selectionXPath returned %q, want %q", got, tc.want)
			}
		})
	}
}
