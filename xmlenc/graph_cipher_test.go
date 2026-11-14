package xmlenc //nolint:testpackage // Exercises cipher planning and byte accounting independently of encryption.

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

func TestGraphCipherPlansLocalReferencesAndInclusivePrefixes(t *testing.T) {
	t.Parallel()

	const start = `<r xmlns:x="` + Namespace + `" xmlns:ds="` + SignatureNamespace + `" xmlns:ec="` + c14n.Exclusive + `" xmlns:p="urn:prefix"><payload xml:id="cipher">YQBi</payload><x:CipherData>`
	const end = `</x:CipherData></r>`
	const referenceStart = `<x:CipherReference URI="#cipher"><x:Transforms>`
	const referenceEnd = `</x:Transforms></x:CipherReference>`
	for _, tc := range []struct {
		name, cipher string
		allowed      []string
		want         []byte
		wantErr      error
	}{
		{
			name:   "base64_with_nul",
			cipher: referenceStart + `<ds:Transform Algorithm="` + reference.Base64 + `"/>` + referenceEnd,
			want:   []byte{'a', 0, 'b'},
		},
		{
			name:    "exclusive_canonicalization_keeps_prefix",
			cipher:  referenceStart + `<ds:Transform Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces PrefixList="p"/></ds:Transform>` + referenceEnd,
			allowed: []string{c14n.Exclusive},
			want:    []byte(`<payload xmlns:p="urn:prefix" xml:id="cipher">YQBi</payload>`),
		},
		{
			name:    "empty_transform_list",
			cipher:  referenceStart + referenceEnd,
			wantErr: ErrFormat,
		},
		{
			name:    "missing_local_target",
			cipher:  `<x:CipherReference URI="#missing"/>`,
			wantErr: ErrFormat,
		},
		{
			name:    "known_transform_disabled_by_policy",
			cipher:  referenceStart + `<ds:Transform Algorithm="` + reference.Base64 + `"/>` + referenceEnd,
			allowed: []string{c14n.Exclusive},
			wantErr: ErrPolicy,
		},
		{
			name:    "cipher_value_cannot_have_elements",
			cipher:  `<x:CipherValue><payload/></x:CipherValue>`,
			wantErr: ErrFormat,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := document.Parse(t.Context(), []byte(start+tc.cipher+end), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			graph, source, err := newKeyGraph(t.Context(), doc, KeyGraphOptions{CipherTransforms: tc.allowed})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(graph.close)
			plan, err := graph.cipherPlan(source, doc.Root().Children()[1], 1024)
			if tc.wantErr != nil {
				if plan != nil || !errors.Is(err, tc.wantErr) {
					t.Errorf("cipherPlan = (%v, %v), want (%v, %v)", plan, err, nil, tc.wantErr)
				}
				return
			}
			if err != nil || plan == nil || !plan.local {
				t.Fatalf("local cipherPlan = (%v, %v)", plan, err)
			}
			if len(tc.allowed) != 0 && (len(plan.transforms) != 1 || !slices.Equal(plan.transforms[0].InclusivePrefixes, []string{"p"})) {
				t.Errorf("transforms = %v, want exclusive canonicalization with prefix p", plan.transforms)
			}
			got, err := graph.readCipher(plan)
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Errorf("readCipher = (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
}

func TestGraphCipherChargesInlineBytesOnce(t *testing.T) {
	t.Parallel()

	doc, err := document.Parse(t.Context(), []byte(`<x:CipherData xmlns:x="`+Namespace+`"><x:CipherValue>YWJj</x:CipherValue></x:CipherData>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	graph, source, err := newKeyGraph(t.Context(), doc, KeyGraphOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(graph.close)
	plan, err := graph.cipherPlan(source, doc.Root(), 3)
	if err != nil {
		t.Fatal(err)
	}
	graph.remaining.MaxBytes = 3
	if got, err := graph.readCipher(plan); err != nil || string(got) != "abc" || graph.remaining.MaxBytes != 0 {
		t.Fatalf("readCipher at the limit = (%q, %v), remaining bytes = %d", got, err, graph.remaining.MaxBytes)
	}
	if got, err := graph.readCipher(plan); got != nil || !errors.Is(err, document.ErrLimit) {
		t.Errorf("readCipher with exhausted budget = (%q, %v), want no bytes and ErrLimit", got, err)
	}
}
