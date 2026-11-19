package xmlenc //nolint:testpackage // Tests key method selection independently of a cipher.

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/document"
)

func TestGraphKeyMethodSelectionRespectsNamesAndExplicitMethods(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		names    []string
		bindings []graphBinding
		methods  []string
		want     string
		wantErr  error
	}{
		{
			name:     "exact_name_selects_method",
			names:    []string{"a"},
			bindings: []graphBinding{{"a", AES128KeyWrap}, {"a ", AES256KeyWrap}},
			methods:  []string{AES128KeyWrap, AES256KeyWrap},
			want:     AES128KeyWrap,
		},
		{
			name:     "name_with_two_methods_is_ambiguous",
			names:    []string{"a"},
			bindings: []graphBinding{{"a", AES128KeyWrap}, {"a", AES256KeyWrap}},
			methods:  []string{AES128KeyWrap, AES256KeyWrap},
			wantErr:  ErrPolicy,
		},
		{
			name:     "two_names_can_select_same_method",
			names:    []string{"a", "b"},
			bindings: []graphBinding{{"a", AES128KeyWrap}, {"b", AES128KeyWrap}},
			methods:  []string{AES128KeyWrap, AES256KeyWrap},
			want:     AES128KeyWrap,
		},
		{
			name:    "one_explicit_method_without_named_binding",
			names:   []string{"no match"},
			methods: []string{ConcatKDF, AES192KeyWrap},
			want:    AES192KeyWrap,
		},
		{
			name:    "fallback_rejects_ambiguous_methods",
			methods: []string{AES128KeyWrap, AES256KeyWrap},
			wantErr: ErrPolicy,
		},
		{
			name:     "derivation_is_not_an_encryption_method",
			names:    []string{"master"},
			bindings: []graphBinding{{"master", ConcatKDF}},
			methods:  []string{ConcatKDF},
			wantErr:  errGraphKeyUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			graph := keyGraph{bindings: make(map[graphBinding]KeyGraphKey), methods: make(map[string]struct{})}
			for _, binding := range tc.bindings {
				graph.bindings[binding] = KeyGraphKey{Name: binding.name, Algorithm: binding.algorithm}
			}
			for _, method := range tc.methods {
				graph.methods[method] = struct{}{}
			}
			got, err := graph.algorithmForNames(tc.names)
			if got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Errorf("algorithmForNames(%q) = (%q, %v), want (%q, %v)", tc.names, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestGraphCachedPlanChecksDependencyDepth(t *testing.T) {
	t.Parallel()

	identity := graphPlanID{algorithm: AES256GCM, keyBytes: 32}
	cached := &graphKeyPlan{dependencyDepth: 1}
	graph := keyGraph{limits: KeyGraphLimits{MaxDepth: 3}, plans: map[graphPlanID]*graphKeyPlan{identity: cached}}
	if got, err := graph.keyPlan(graphNode{}, identity.algorithm, identity.keyBytes, 2); got != cached || err != nil {
		t.Fatalf("cached plan at depth limit = %p, %v, want %p, nil", got, err, cached)
	}
	if got, err := graph.keyPlan(graphNode{}, identity.algorithm, identity.keyBytes, 3); got != nil || !errors.Is(err, document.ErrLimit) {
		t.Errorf("cached plan over depth limit = %p, %v, want nil, ErrLimit", got, err)
	}
}

func TestGraphRetrievalRequiresURIAttribute(t *testing.T) {
	t.Parallel()

	const start = `<x:EncryptedKey xmlns:x="` + Namespace + `" xmlns:ds="` + SignatureNamespace + `"><ds:KeyInfo><ds:RetrievalMethod`
	const end = `/></ds:KeyInfo><x:CipherData><x:CipherValue/></x:CipherData></x:EncryptedKey>`
	for _, attribute := range []string{` URI=""`, ""} {
		doc, err := document.Parse(t.Context(), []byte(start+attribute+end), document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		graph, source, err := newKeyGraph(t.Context(), doc, KeyGraphOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(graph.close)
		retrieval := doc.Root().Children()[0].Children()[0]
		got, err := graph.retrievedKey(source, retrieval)
		if attribute != "" {
			if err != nil || !got.element().Same(doc.Root()) {
				t.Errorf("explicit empty URI = %v, %v, want the document element", got, err)
			}
		} else if got != (graphNode{}) || !errors.Is(err, ErrFormat) {
			t.Errorf("missing URI = %v, %v, want no target and ErrFormat", got, err)
		}
	}
}
