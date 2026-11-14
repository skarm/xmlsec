package xmlenc //nolint:testpackage // Checks configuration ownership and graph budget boundaries.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

func TestKeyGraphOwnsConfiguredSecretsAndIDRules(t *testing.T) {
	t.Parallel()

	secret := bytes.Repeat([]byte{7}, 32)
	ids := []document.Name{{Local: "item"}}
	limits := document.DefaultLimits()
	doc, err := document.Parse(t.Context(), []byte(`<r><item marker="selected"/><other marker="ignored"/></r>`), limits)
	if err != nil {
		t.Fatal(err)
	}
	graph, source, err := newKeyGraph(t.Context(), doc, KeyGraphOptions{
		Keys:    []KeyGraphKey{{Name: "recipient", Algorithm: AES256GCM, Secret: secret}},
		IDRules: []reference.IDAttributeRule{{Attribute: document.Name{Local: "marker"}, Elements: ids}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(graph.close)
	wantSecret := bytes.Repeat([]byte{7}, 32)
	stored := graph.bindings[graphBinding{"recipient", AES256GCM}].Secret
	if !bytes.Equal(stored, wantSecret) || &stored[0] == &secret[0] {
		t.Fatal("graph did not take ownership of a copy of the configured key")
	}
	ids[0] = document.Name{Local: "other"}
	if got := graph.options.IDRules[0].Elements[0]; got.Local != "item" {
		t.Errorf("graph ID rule changed to %v after caller mutation", got)
	}
	target, err := graph.localTarget(source, "#selected")
	if err != nil || !target.element().Same(doc.Root().Children()[0]) {
		t.Errorf("local ID target = (%v, %v), want the selected item", target, err)
	}
	if _, err := graph.localTarget(source, "#ignored"); !errors.Is(err, ErrFormat) {
		t.Errorf("target outside the configured element scope returned %v, want ErrFormat", err)
	}
	graph.close()
	if !bytes.Equal(stored, make([]byte, len(stored))) || !bytes.Equal(secret, wantSecret) {
		t.Error("graph close did not clear its own copy or changed caller key")
	}
}

func TestKeyGraphConfigurationRejectsInvalidOptionsBeforeResourceIO(t *testing.T) {
	t.Parallel()

	doc, err := document.Parse(t.Context(), []byte("<r/>"), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		options KeyGraphOptions
	}{
		{"depth_below_minimum", KeyGraphOptions{Limits: KeyGraphLimits{MaxDepth: -1}}},
		{"unsupported_master_key_size", KeyGraphOptions{MasterKeyBytes: 20}},
		{"unknown_cipher_transform", KeyGraphOptions{CipherTransforms: []string{"urn:unsupported"}}},
		{"duplicate_key_method", KeyGraphOptions{KeyAlgorithms: []string{AES256GCM, AES256GCM}}},
		{"wrong_wrapping_key_size", KeyGraphOptions{Keys: []KeyGraphKey{{Name: "recipient", Algorithm: AES192KeyWrap, Secret: make([]byte, 16)}}}},
		{"empty_secret", KeyGraphOptions{Keys: []KeyGraphKey{{Name: "recipient", Algorithm: AES128GCM}}}},
		{"malformed_kdf_field", KeyGraphOptions{ConcatKDF: &ConcatKDFParameters{PartyUInfo: []byte{8, 0}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := tc.options
			options.External = &KeyGraphResources{AllowedURIs: []string{"https://example.test/key.xml"}, Resolver: CipherResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				t.Error("configuration failure invoked the resource resolver")
				return nil, ErrResource
			})}
			graph, principal, err := newKeyGraph(t.Context(), doc, options)
			if graph != nil || principal != nil || !errors.Is(err, ErrPolicy) {
				t.Errorf("newKeyGraph = (graph present: %t, document present: %t, %v), want ErrPolicy and no graph", graph != nil, principal != nil, err)
			}
		})
	}
}
