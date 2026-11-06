package protocol

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Local SAML vocabulary tokens shared by protocol producers and parsers. Each call site still verifies the assertion/protocol namespace or resolves the QName prefix.
const (
	xmlNameChannelBindings = "ChannelBindings"
)

// The extension's Type attribute is unqualified; it does not name an XML Schema
// instance type or an XML Encryption object type.
const (
	channelTypeAttribute = "Type"
)

// Channel bindings have fixed profile ceilings for alternatives and decoded
// transport bytes; these are not configurable zero-value defaults.
const (
	maximumChannelBindings  = 8
	maximumChannelDataBytes = 4096
)

// ChannelBindingNamespace identifies the OASIS Channel Binding Extensions 1.0.
const ChannelBindingNamespace = lexicon.NamespaceSAMLChannelBinding

// ChannelBinding carries raw channel bytes, not their base64 representation.
// Empty Data is a verification signal in Advice; requests require actual data.
// The application must obtain these bytes from its authenticated transport.
type ChannelBinding struct {
	// Type identifies the channel binding method. Empty requires an out-of-band
	// agreement.
	Type string
	// Data contains raw transport-derived binding bytes. Empty is allowed only as
	// an Advice verification signal.
	Data []byte
}

// CloneChannelBindings returns independently owned channel binding data.
func CloneChannelBindings(in []ChannelBinding) []ChannelBinding {
	out := make([]ChannelBinding, len(in))
	for i, b := range in {
		out[i] = ChannelBinding{Type: strings.Clone(b.Type), Data: bytes.Clone(b.Data)}
	}

	return out
}

// ValidateChannelBindings bounds a set and rejects ambiguous duplicate types.
// An empty Type is allowed when its meaning is established out of band.
func ValidateChannelBindings(in []ChannelBinding, allowEmpty bool) error {
	const (
		maximumChannelTypeBytes = 256
	)

	if len(in) > maximumChannelBindings {
		return ErrProfile
	}

	seen := map[string]bool{}
	for _, b := range in {
		if len(b.Type) > maximumChannelTypeBytes || strings.ContainsAny(b.Type, lexicon.XMLWhitespace) || seen[b.Type] || len(b.Data) > maximumChannelDataBytes || !allowEmpty && len(b.Data) == 0 {
			return ErrProfile
		}

		seen[b.Type] = true
	}

	return nil
}

func channelNode(b ChannelBinding) *tree.Node {
	const (
		prefixChannelBinding = "cb"
	)

	n := xmlutil.Node(prefixChannelBinding, ChannelBindingNamespace, xmlNameChannelBindings)

	n.NS = []tree.Namespace{{Prefix: prefixChannelBinding, URI: ChannelBindingNamespace}}
	if b.Type != "" {
		xmlutil.Set(n, channelTypeAttribute, b.Type)
	}

	if len(b.Data) != 0 {
		xmlutil.Text(n, base64.StdEncoding.EncodeToString(b.Data))
	}

	return n
}

func channelContainer(local string, values []ChannelBinding, allowEmpty bool) (*tree.Node, error) {
	if err := ValidateChannelBindings(values, allowEmpty); err != nil {
		return nil, err
	}

	ns, prefix := ProtocolNamespace, prefixProtocol
	if local == xmlNameAdvice {
		ns, prefix = AssertionNamespace, prefixAssertion
	}

	n := xmlutil.Node(prefix, ns, local)
	for _, b := range values {
		xmlutil.Add(n, channelNode(b))
	}

	return n, nil
}

func appendChannelContainer(parent *tree.Node, local string, values []ChannelBinding, allowEmpty bool) error {
	if len(values) == 0 {
		return nil
	}

	container, err := channelContainer(local, values, allowEmpty)
	if err != nil {
		return err
	}

	xmlutil.Add(parent, container)

	return nil
}

func readChannelContainer(e document.Element, allowEmpty bool) ([]ChannelBinding, error) {
	const (
		maximumEncodedChannelDataBytes = 8192
	)

	if xmlutil.Attrs(e, nil, nil) != nil {
		return nil, ErrProfile
	}

	children, err := xmlutil.Children(e)
	if err != nil || len(children) == 0 || len(children) > maximumChannelBindings {
		return nil, ErrProfile
	}

	var out []ChannelBinding

	for _, c := range children {
		if c.Name() != xmlutil.Name(ChannelBindingNamespace, xmlNameChannelBindings) || xmlutil.Attrs(c, nil, []string{channelTypeAttribute}) != nil {
			return nil, ErrProfile
		}

		value, err := xmlutil.SimpleText(c, maximumEncodedChannelDataBytes)
		if err != nil {
			return nil, err
		}

		data, err := decodeChannelData(value)
		if err != nil {
			return nil, err
		}

		out = append(out, ChannelBinding{Type: xmlutil.Attr(c, channelTypeAttribute), Data: data})
	}

	return out, ValidateChannelBindings(out, allowEmpty)
}

func decodeChannelData(value string) ([]byte, error) {
	// XML Schema base64Binary admits XML whitespace, including spaces and tabs.
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}

		return r
	}, value)

	data, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(data) > maximumChannelDataBytes {
		return nil, ErrProfile
	}

	return data, nil
}

func requireChannelAdvice(actual, expected []ChannelBinding) error {
	if err := ValidateChannelBindings(expected, false); err != nil {
		return err
	}

	for _, want := range expected {
		for _, got := range actual {
			if (got.Type == want.Type || got.Type == "") && (len(got.Data) == 0 || bytes.Equal(got.Data, want.Data)) {
				return nil
			}
		}
	}

	if len(expected) != 0 {
		return ErrConditions
	}

	return nil
}
