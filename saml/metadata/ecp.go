package metadata

import (
	"slices"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Maximum advertised channel-binding alternatives per endpoint; parser and builder apply the same list cardinality bound.
const (
	maximumChannelTypes = 16
)

// Metadata vocabulary local name shared by builder and parser; callers must still check the metadata or extension namespace.
const (
	xmlNameProtocolBinding         = "ProtocolBinding"
	xmlNameSupportsChannelBindings = "supportsChannelBindings"
)

// Per-token byte ceiling for channel-binding type identifiers in metadata extensions; list splitting uses only XML whitespace.
const (
	maximumChannelTypeBytes = 256
)

// HoKSSO is the HoK SSO profile discriminator used as a metadata Binding.
// The hoksso:ProtocolBinding attribute specifies the actual SAML transport.
const HoKSSO = "urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser"

// ChannelBindingNamespace identifies SAML Channel Binding Extensions CS01.
const ChannelBindingNamespace = lexicon.NamespaceSAMLChannelBinding

// HolderOfKey reports an explicitly advertised HoK endpoint.
func (e Endpoint) HolderOfKey() bool { return e.Binding == HoKSSO }

// TransportBinding returns the SAML transport, preserving Binding separately.
func (e Endpoint) TransportBinding() string {
	if e.HolderOfKey() {
		return e.ProtocolBinding
	}

	return e.Binding
}

// AcceptsTransport reports whether the endpoint supports the transport and
// permits the requested proof policy. HoK-only endpoints require holderOfKey.
func (e Endpoint) AcceptsTransport(binding string, holderOfKey bool) bool {
	return e.TransportBinding() == binding && (!e.HolderOfKey() || holderOfKey)
}

// SupportsChannelBinding reports an exact advertised binding type. It grants
// no proof of transport security or actual protocol-level channel comparison.
func (e Endpoint) SupportsChannelBinding(kind string) bool {
	return slices.Contains(e.SupportedChannelBindings, kind)
}

// SelectHoKACS selects only HoK-advertised endpoints for an actual transport,
// applying IndexedEndpointType defaults in metadata order. It never selects a
// bearer-only endpoint or silently normalizes the metadata Binding.
func SelectHoKACS(endpoints []Endpoint, transport string, index *uint16) (Endpoint, error) {
	var candidates []Endpoint

	for _, endpoint := range endpoints {
		if endpoint.HolderOfKey() && endpoint.ProtocolBinding == transport {
			candidates = append(candidates, endpoint)
		}
	}

	return SelectACS(candidates, HoKSSO, index)
}

// HoKACS selects an explicitly advertised HoK ACS for the given transport.
func (r *Role) HoKACS(transport string, index *uint16) (Endpoint, error) {
	if r == nil || r.kind != ServiceProvider {
		return Endpoint{}, ErrMetadata
	}

	return SelectHoKACS(r.endpoints[AssertionConsumerService], transport, index)
}

func cloneEndpoint(e Endpoint) Endpoint {
	e.SupportedChannelBindings = slices.Clone(e.SupportedChannelBindings)
	return e
}

func cloneEndpoints(in []Endpoint) []Endpoint {
	out := slices.Clone(in)
	for i := range out {
		out[i] = cloneEndpoint(out[i])
	}

	return out
}

func endpointAttributes(e document.Element, required, optional []string) error {
	seen := map[string]bool{}

	for _, a := range e.Attributes() {
		if a.Name == (document.Name{Space: HoKSSO, Local: xmlNameProtocolBinding}) || a.Name == (document.Name{Space: ChannelBindingNamespace, Local: xmlNameSupportsChannelBindings}) {
			continue
		}

		if a.Name.Space != "" || !slices.Contains(required, a.Name.Local) && !slices.Contains(optional, a.Name.Local) {
			return ErrMetadata
		}

		seen[a.Name.Local] = true
	}

	for _, name := range required {
		if !seen[name] {
			return ErrMetadata
		}
	}

	return nil
}

func readEndpointExtensions(element document.Element, endpoint *Endpoint) error {
	const (
		maximumChannelTypesTextBytes = 8192
	)

	if value, present := element.Attribute(document.Name{Space: HoKSSO, Local: xmlNameProtocolBinding}); present {
		if !profile.URI(value) || value == HoKSSO {
			return ErrMetadata
		}

		endpoint.ProtocolBinding = value
	}

	if endpoint.HolderOfKey() && endpoint.ProtocolBinding == "" {
		return ErrMetadata
	}

	if value, present := element.Attribute(document.Name{Space: ChannelBindingNamespace, Local: xmlNameSupportsChannelBindings}); present {
		if len(value) > maximumChannelTypesTextBytes {
			return ErrMetadata
		}

		values := strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' })
		if len(values) > maximumChannelTypes {
			return ErrMetadata
		}

		endpoint.SupportedChannelBindings = make([]string, len(values))
		for i, value := range values {
			if len(value) > maximumChannelTypeBytes {
				return ErrMetadata
			}

			endpoint.SupportedChannelBindings[i] = value
		}
	}

	return nil
}

func endpointExtensions(node *tree.Node, endpoint Endpoint) {
	const (
		prefixChannelBinding = "cb"
		prefixHoKSSO         = "hoksso"
	)

	if endpoint.ProtocolBinding != "" {
		node.NS = append(node.NS, tree.Namespace{Prefix: prefixHoKSSO, URI: HoKSSO})
		node.Attrs = append(node.Attrs, tree.Attribute{Name: xmlutil.Name(HoKSSO, xmlNameProtocolBinding), Prefix: prefixHoKSSO, Value: endpoint.ProtocolBinding})
	}

	if endpoint.SupportedChannelBindings != nil {
		node.NS = append(node.NS, tree.Namespace{Prefix: prefixChannelBinding, URI: ChannelBindingNamespace})
		node.Attrs = append(node.Attrs, tree.Attribute{Name: xmlutil.Name(ChannelBindingNamespace, xmlNameSupportsChannelBindings), Prefix: prefixChannelBinding, Value: strings.Join(endpoint.SupportedChannelBindings, " ")})
	}
}

func validateEndpointExtensionValues(endpoints map[string][]Endpoint) error {
	for _, group := range endpoints {
		for _, endpoint := range group {
			if len(endpoint.SupportedChannelBindings) > maximumChannelTypes {
				return ErrMetadata
			}

			for _, value := range endpoint.SupportedChannelBindings {
				if value == "" || len(value) > maximumChannelTypeBytes || strings.ContainsAny(value, lexicon.XMLWhitespace) {
					return ErrMetadata
				}
			}
		}
	}

	return nil
}
