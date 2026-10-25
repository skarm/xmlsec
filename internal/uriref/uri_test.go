package uriref_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/uriref"
)

func TestValidate(t *testing.T) {
	for _, value := range []string{"", "#", "../data%2f.xml?x=1#part", "https://example.test/é", "urn:example:item"} {
		if err := uriref.Validate(value); err != nil {
			t.Errorf("Validate(%q): %v", value, err)
		}
	}

	for _, value := range []string{"a\\b", "a%", "%0g", "a#b#c", "a b", "a\u00a0b", "a\x00b", "\xff", ":bad", "https://[invalid/"} {
		if err := uriref.Validate(value); !errors.Is(err, uriref.Err) {
			t.Errorf("Validate(%q) = %v, want URI error", value, err)
		}
	}
}

func TestBase(t *testing.T) {
	base, err := uriref.Base("")
	if err != nil || base != nil {
		t.Fatalf("empty base = %v, %v", base, err)
	}

	base, err = uriref.Base("https://example.test/a%2fb/?x=1")
	if err != nil || base.String() != "https://example.test/a%2fb/?x=1" {
		t.Fatalf("absolute base = %v, %v", base, err)
	}

	for _, value := range []string{"../relative", "urn:opaque", "https://example.test/a#", "https://example.test/a#part"} {
		if _, err := uriref.Base(value); !errors.Is(err, uriref.Err) {
			t.Errorf("Base(%q) = %v", value, err)
		}
	}
}

func TestResolve(t *testing.T) {
	base, err := uriref.Base("https://example.test/base/document.xml")
	if err != nil {
		t.Fatal(err)
	}

	root := &tree.Node{Attrs: []tree.Attribute{{Name: document.Name{Space: document.XMLNamespace, Local: "base"}, Value: "dir/"}}}
	child := &tree.Node{Parent: root, Attrs: []tree.Attribute{{Name: document.Name{Space: document.XMLNamespace, Local: "base"}, Value: "../leaf/"}}}
	for _, tc := range []struct {
		name     string
		value    string
		base     *url.URL
		resource string
		source   *tree.Node
		want     string
	}{
		{"literal without base", "../a%2fb#", nil, "", child, "../a%2fb#"},
		{"absolute unchanged", "https://other.test/a%2fb#", base, "bad%", child, "https://other.test/a%2fb#"},
		{"document base", "item.xml", base, "", nil, "https://example.test/base/item.xml"},
		{"retrieval and ancestors", "item%2f.xml?#", base, "https://example.test/retrieved/document.xml", child, "https://example.test/retrieved/leaf/item%2f.xml?#"},
		{"inherited base", "item.xml", base, "", child, "https://example.test/base/leaf/item.xml"},
		{"unqualified base ignored", "item.xml", base, "", &tree.Node{Attrs: []tree.Attribute{{Name: document.Name{Local: "base"}, Value: "bad%"}}}, "https://example.test/base/item.xml"},
		{"foreign base ignored", "item.xml", base, "", &tree.Node{Attrs: []tree.Attribute{{Name: document.Name{Space: "urn:foreign", Local: "base"}, Value: "bad%"}}}, "https://example.test/base/item.xml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := uriref.Resolve(tc.value, tc.base, tc.resource, tc.source)
			if err != nil || got != tc.want {
				t.Fatalf("Resolve = %q, %v; want %q", got, err, tc.want)
			}
		})
	}

	if base.String() != "https://example.test/base/document.xml" || root.Attrs[0].Value != "dir/" {
		t.Fatal("resolution changed caller-owned context")
	}

	for _, tc := range []struct {
		value    string
		resource string
		source   *tree.Node
	}{
		{"bad%", "", nil},
		{"item", "bad%", nil},
		{"item", "relative/document.xml", nil},
		{"item", "", &tree.Node{Attrs: []tree.Attribute{{Name: document.Name{Space: document.XMLNamespace, Local: "base"}, Value: "bad%"}}}},
		{"item", "", &tree.Node{Attrs: []tree.Attribute{{Name: document.Name{Space: document.XMLNamespace, Local: "base"}, Value: "urn:opaque"}}}},
	} {
		if _, err := uriref.Resolve(tc.value, base, tc.resource, tc.source); !errors.Is(err, uriref.Err) {
			t.Errorf("invalid context accepted: %+v, %v", tc, err)
		}
	}
}

func BenchmarkURIContext(b *testing.B) {
	const rawBase = "https://example.test/path/document.xml"
	base, err := uriref.Base(rawBase)
	if err != nil {
		b.Fatal(err)
	}

	source := &tree.Node{Attrs: []tree.Attribute{{Name: document.Name{Space: document.XMLNamespace, Local: "base"}, Value: "../assets/"}}}
	b.Run("Validate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := uriref.Validate(rawBase); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Base", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := uriref.Base(rawBase); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Resolve", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := uriref.Resolve("data%2f.xml#part", base, "", source); err != nil {
				b.Fatal(err)
			}
		}
	})
}
