package protocol //nolint:testpackage // Exercises the internal channel container codec and advice comparison.

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

func TestValidateChannelBindingsLimitsAndUniqueTypes(t *testing.T) {
	t.Parallel()

	const dataLimit = 4096
	exact := make([]ChannelBinding, 8)
	for i := range exact {
		exact[i] = ChannelBinding{Type: fmt.Sprintf("urn:test:channel:%d", i), Data: []byte{1}}
	}

	for _, tc := range []struct {
		name       string
		bindings   []ChannelBinding
		allowEmpty bool
		wantErr    error
	}{
		{"maximum_alternatives", exact, false, nil},
		{"too_many_alternatives", append(exact, ChannelBinding{Type: "urn:test:extra", Data: []byte{1}}), false, ErrProfile},
		{"maximum_type_and_data", []ChannelBinding{{Type: strings.Repeat("a", 256), Data: make([]byte, dataLimit)}}, false, nil},
		{"too_much_data", []ChannelBinding{{Data: make([]byte, dataLimit+1)}}, false, ErrProfile},
		{"type_too_long", []ChannelBinding{{Type: strings.Repeat("a", 257), Data: []byte{1}}}, false, ErrProfile},
		{"duplicate_type", []ChannelBinding{{Type: "urn:test:same", Data: []byte{1}}, {Type: "urn:test:same", Data: []byte{2}}}, false, ErrProfile},
		{"duplicate_untyped", []ChannelBinding{{Data: []byte{1}}, {Data: []byte{2}}}, false, ErrProfile},
		{"whitespace_in_type", []ChannelBinding{{Type: "urn:test: a", Data: []byte{1}}}, false, ErrProfile},
		{"empty_advice_signal", []ChannelBinding{{Type: "urn:test:one"}}, true, nil},
		{"empty_request_data", []ChannelBinding{{Type: "urn:test:one"}}, false, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateChannelBindings(tc.bindings, tc.allowEmpty); !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateChannelBindings(%d alternatives) = %v, want %v", len(tc.bindings), err, tc.wantErr)
			}
		})
	}
}

func TestChannelContainerPreservesTypeDataAndNamespace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		local, namespace, prefix string
		allowEmpty               bool
		data                     []byte
	}{
		{xmlNameAdvice, AssertionNamespace, prefixAssertion, true, []byte{}},
		{"Extensions", ProtocolNamespace, prefixProtocol, false, []byte{0, 255, 1}},
	} {
		t.Run(tc.local, func(t *testing.T) {
			t.Parallel()

			want := []ChannelBinding{{Type: "urn:test:one", Data: tc.data}, {Data: []byte{4, 5}}}
			parent := xmlutil.Node(tc.prefix, tc.namespace, "Parent")
			parent.NS = []tree.Namespace{{Prefix: tc.prefix, URI: tc.namespace}}
			if err := appendChannelContainer(parent, tc.local, nil, tc.allowEmpty); err != nil || len(parent.Children) != 0 {
				t.Fatalf("append empty bindings = %v, children = %d, want success and no children", err, len(parent.Children))
			}
			if err := appendChannelContainer(parent, tc.local, want, tc.allowEmpty); err != nil {
				t.Fatalf("appendChannelContainer: %v", err)
			}
			if len(parent.Children) != 1 {
				t.Fatalf("parent has %d children, want one", len(parent.Children))
			}
			d, err := xmlutil.Document(t.Context(), parent)
			if err != nil {
				t.Fatalf("serialize channel container: %v", err)
			}
			root := d.Root().Children()[0]
			if wantName := (document.Name{Space: tc.namespace, Local: tc.local}); root.Name() != wantName {
				t.Errorf("container name = %+v, want %+v", root.Name(), wantName)
			}
			if got, err := readChannelContainer(root, tc.allowEmpty); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("readChannelContainer = %+v, %v, want %+v", got, err, want)
			}
		})
	}
}

func TestReadChannelContainerChecksDecodedPayload(t *testing.T) {
	t.Parallel()

	const start = `<s:Extensions xmlns:s="` + ProtocolNamespace + `" xmlns:cb="` + ChannelBindingNamespace + `">`
	const bindingStart = `<cb:ChannelBindings Type="urn:test:one">`
	const bindingEnd = "</cb:ChannelBindings>"
	const end = "</s:Extensions>"
	atLimit := bytes.Repeat([]byte{0xab}, 4096)

	for _, tc := range []struct {
		name, content string
		want          []byte
		wantErr       error
	}{
		{"xml_whitespace", bindingStart + " \taG\r\nk= " + bindingEnd, []byte("hi"), nil},
		{"noncanonical_base64_padding", bindingStart + "aGl=" + bindingEnd, nil, ErrProfile},
		{"maximum_decoded_size", bindingStart + base64.StdEncoding.EncodeToString(atLimit) + bindingEnd, atLimit, nil},
		{"above_decoded_size", bindingStart + base64.StdEncoding.EncodeToString(append(bytes.Clone(atLimit), 0)) + bindingEnd, nil, ErrProfile},
		{"no_binding", "", nil, ErrProfile},
		{"unexpected_child", `<s:ChannelBindings/>`, nil, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d, err := document.Parse(t.Context(), []byte(start+tc.content+end), document.DefaultLimits())
			if err != nil {
				t.Fatalf("parse XML fixture: %v", err)
			}
			got, err := readChannelContainer(d.Root(), false)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("readChannelContainer = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil && len(got) != 0 {
				t.Errorf("rejected binding exposed %d entries", len(got))
			}
			if tc.wantErr == nil && (len(got) != 1 || got[0].Type != "urn:test:one" || !bytes.Equal(got[0].Data, tc.want)) {
				t.Errorf("decoded bindings = %d entries, want one binding of type urn:test:one with %d data bytes", len(got), len(tc.want))
			}
		})
	}
}

func TestRequireChannelAdviceMatchesRetainedAlternatives(t *testing.T) {
	t.Parallel()

	want := []ChannelBinding{{Type: "urn:test:first", Data: []byte("first")}, {Type: "urn:test:second", Data: []byte("second")}}
	for _, tc := range []struct {
		name             string
		actual, expected []ChannelBinding
		wantErr          error
	}{
		{"exact_second_alternative", []ChannelBinding{{Type: "urn:test:second", Data: []byte("second")}}, want, nil},
		{"empty_data_acknowledges_matching_type", []ChannelBinding{{Type: "urn:test:second"}}, want, nil},
		{"out_of_band_type", []ChannelBinding{{Data: []byte("first")}}, want, nil},
		{"different_type", []ChannelBinding{{Type: "urn:test:other", Data: []byte("first")}}, want, ErrConditions},
		{"different_data", []ChannelBinding{{Type: "urn:test:first", Data: []byte("other")}}, want, ErrConditions},
		{"missing_advice", nil, want, ErrConditions},
		{"nothing_retained", nil, nil, nil},
		{"invalid_retained_data", nil, []ChannelBinding{{Type: "urn:test:first"}}, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := requireChannelAdvice(tc.actual, tc.expected); !errors.Is(err, tc.wantErr) {
				t.Errorf("requireChannelAdvice = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
