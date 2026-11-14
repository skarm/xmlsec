package xmlenc //nolint:testpackage // Tests key method selection independently of a cipher.

import (
	"errors"
	"testing"
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
