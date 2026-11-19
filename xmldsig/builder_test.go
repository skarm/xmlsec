package xmldsig_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestBuildTemplateKeepsObjectVariantsInOrder(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const raw = `<p:payload xmlns:p="urn:sample"><p:item/></p:payload>`
	xml := parse(t, raw)
	binary := []byte{0, 1, 255}
	empty := ""
	spec := xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256,
		References:      []xmldsig.ReferenceTemplate{{URI: "#xml"}, {URI: "#binary"}, {URI: "#empty"}},
		Objects: []xmldsig.ObjectTemplate{
			{ID: "xml", XML: xml},
			{ID: "binary", MIMEType: "application/octet-stream", Binary: binary},
			{ID: "empty", Text: &empty},
		},
	}
	result, selected, err := xmldsig.BuildTemplate(ctx, nil, document.Element{}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !selected.Same(result.Root()) {
		t.Fatal("standalone signature handle does not identify returned document root")
	}
	clear(binary)
	children := selected.Children()
	if len(children) != 5 {
		t.Fatalf("signature children = %d, want SignedInfo, SignatureValue and three objects", len(children))
	}
	for i, want := range []string{"xml", "binary", "empty"} {
		child := children[i+2]
		id, ok := child.Attribute(document.Name{Local: "Id"})
		if child.Name() != (document.Name{Space: xmldsig.Namespace, Local: "Object"}) || !ok || id != want {
			t.Errorf("child %d = %v with Id %q, want Object with Id %q", i+2, child.Name(), id, want)
		}
	}
	payload := children[2].Children()
	if len(payload) != 1 || payload[0].Name() != (document.Name{Space: "urn:sample", Local: "payload"}) ||
		len(payload[0].Children()) != 1 || payload[0].Children()[0].Name() != (document.Name{Space: "urn:sample", Local: "item"}) {
		t.Errorf("XML object lost its namespace or subtree: %v", payload)
	}
	if mime, ok := children[3].Attribute(document.Name{Local: "MimeType"}); !ok || mime != "application/octet-stream" || children[3].Text() != "AAH/" {
		t.Errorf("binary object = %q with media type %q, want AAH/ and application/octet-stream", children[3].Text(), mime)
	}
	if children[4].Text() != "" || len(children[4].Children()) != 0 {
		t.Error("explicit empty object has content")
	}
	if got := xmlString(t, xml); got != `<p:payload xmlns:p="urn:sample"><p:item></p:item></p:payload>` {
		t.Errorf("source XML changed: %s", got)
	}
}

func TestBuildTemplateRejectsInvalidPlacementAndRecipes(t *testing.T) {
	t.Parallel()

	original := parse(t, `<r ID="r"><item/></r>`)
	before := xmlString(t, original)
	variant := "text"
	for _, tc := range []struct {
		name  string
		doc   *document.Document
		at    document.Element
		alter func(*xmldsig.SignatureTemplate)
		want  error
	}{
		{"parent without document", nil, original.Root(), nil, xmldsig.ErrPolicy},
		{"parent from another snapshot", original, parse(t, before).Root(), nil, xmldsig.ErrPolicy},
		{"override existing XML limits", original, original.Root(), func(s *xmldsig.SignatureTemplate) { s.XMLLimits = document.DefaultLimits() }, xmldsig.ErrPolicy},
		{"missing signature method", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) { s.SignatureMethod = "" }, xmldsig.ErrAlgorithm},
		{"canonicalization must canonicalize", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) { s.Canonicalization.Algorithm = reference.Base64 }, xmldsig.ErrAlgorithm},
		{"no references", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) { s.References = nil }, xmldsig.ErrPolicy},
		{"bad reference ID", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) { s.References[0].ID = "1wrong" }, xmldsig.ErrReference},
		{"bad reference digest", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) { s.References[0].DigestMethod = "urn:unknown:digest" }, xmldsig.ErrAlgorithm},
		{"object without content", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) { s.Objects = []xmldsig.ObjectTemplate{{ID: "r"}} }, xmldsig.ErrStructure},
		{"object with two variants", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) {
			s.Objects = []xmldsig.ObjectTemplate{{ID: "r", Binary: []byte{}, Text: &variant}}
		}, xmldsig.ErrStructure},
		{"empty XML document variant", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) {
			s.Objects = []xmldsig.ObjectTemplate{{ID: "r", XML: &document.Document{}}}
		}, xmldsig.ErrStructure},
		{"manifest requires references", nil, document.Element{}, func(s *xmldsig.SignatureTemplate) {
			s.Objects = []xmldsig.ObjectTemplate{{Manifest: &xmldsig.ManifestTemplate{ID: "r"}}}
		}, xmldsig.ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spec := xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#r"}}}
			if tc.alter != nil {
				tc.alter(&spec)
			}
			result, selected, err := xmldsig.BuildTemplate(t.Context(), tc.doc, tc.at, spec)
			if result != nil || selected.Valid() || !errors.Is(err, tc.want) {
				t.Errorf("build = (%v, valid=%t, %v), want no draft and %v", result, selected.Valid(), err, tc.want)
			}
			if got := xmlString(t, original); got != before {
				t.Errorf("source changed from %s to %s after rejected build", before, got)
			}
		})
	}
}

func TestBuildTemplateRejectsOversizedEncodedObjectsAndCancellation(t *testing.T) {
	t.Parallel()

	spec := xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256,
		References:      []xmldsig.ReferenceTemplate{{URI: "#a"}, {URI: "#b"}},
		Objects:         []xmldsig.ObjectTemplate{{ID: "a", Binary: bytes.Repeat([]byte{'a'}, 24)}, {ID: "b", Binary: bytes.Repeat([]byte{'b'}, 24)}},
		XMLLimits:       document.DefaultLimits(),
	}
	spec.XMLLimits.MaxBytes = 63 // Each object needs 32 Base64 bytes before XML markup.
	result, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, spec)
	if result != nil || selected.Valid() || !errors.Is(err, xmldsig.ErrPolicy) || !errors.Is(err, document.ErrLimit) {
		t.Errorf("build above aggregate blob budget = (%v, valid=%t, %v), want policy and document limit error", result, selected.Valid(), err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, selected, err = xmldsig.BuildTemplate(ctx, nil, document.Element{}, spec)
	if result != nil || selected.Valid() || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled build = (%v, valid=%t, %v), want no draft and cancellation", result, selected.Valid(), err)
	}
}

func TestBuildTemplateTransformLimit(t *testing.T) {
	t.Parallel()

	const maximum = 64
	payload := "payload"
	transforms := slices.Repeat([]reference.Transform{{Algorithm: c14n.Exclusive}}, maximum+1)
	spec := xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256,
		References:      []xmldsig.ReferenceTemplate{{URI: "#data", Transforms: transforms}},
		Objects:         []xmldsig.ObjectTemplate{{ID: "data", Text: &payload}},
	}

	t.Run("above hard limit", func(t *testing.T) {
		t.Parallel()

		draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, spec)
		if draft != nil || selected.Valid() || !errors.Is(err, xmldsig.ErrPolicy) {
			t.Fatalf("build above hard transform limit = (%t, %t, %v)", draft != nil, selected.Valid(), err)
		}
	})
	t.Run("configured at hard limit", func(t *testing.T) {
		t.Parallel()

		atLimit := spec
		atLimit.References = []xmldsig.ReferenceTemplate{{URI: "#data", Transforms: transforms[:maximum]}}
		draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, atLimit)
		if err != nil {
			t.Fatal(err)
		}

		key := coreEC(t)
		if _, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{
			Validation: xmldsig.SignatureOptions{Processing: reference.Options{MaxTransforms: maximum}},
		}); err != nil {
			t.Fatal(err)
		}
	})
}
