package binding

import (
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SHA-1 is the SAML type 0x0004 source identifier, not a signature.
	"encoding/base64"
	"encoding/binary"
	"html"
	"net/url"
	"unicode/utf8"

	"github.com/skarm/xmlsec/saml/internal/profile"
)

// Fixed type 0x0004 binary layout: two-octet type, two-octet endpoint index, twenty-octet source and twenty-octet opaque handle; parsing and emission must stay identical.
const (
	artifactEndpointOffset  = 2
	artifactHandleOffset    = 24
	artifactIdentifierBytes = 20
	artifactSourceOffset    = 4
	artifactTypeCode        = 4
	artifactWireBytes       = 44
)

// The HTTP Artifact field carries an opaque type 0x0004 lookup handle; decoding it supplies no message or peer authentication.
const (
	fieldArtifact = "SAMLart"
)

// Artifact is the fixed 44-octet SAML type 0x0004 artifact (Bindings 3.6.4.1).
// The opaque handle is a random lookup key, never an encoded SAML message.
type Artifact struct {
	// EndpointIndex selects an ArtifactResolutionService in trusted issuer
	// metadata.
	EndpointIndex uint16
	// SourceID identifies the issuing provider for routing; it does not
	// authenticate it.
	SourceID [artifactIdentifierBytes]byte
	// MessageHandle is the unpredictable, single-use message identifier.
	MessageHandle [artifactIdentifierBytes]byte
}

// NewArtifact generates an unpredictable handle and the recommended SHA-1 source
// identifier from the issuing provider's entityID.
func NewArtifact(entityID string, index uint16) (Artifact, error) {
	if !profile.URI(entityID) {
		return Artifact{}, ErrBinding
	}

	a := Artifact{EndpointIndex: index, SourceID: ArtifactSource(entityID)}
	_, err := rand.Read(a.MessageHandle[:])

	return a, err
}

// ArtifactSource computes the source identifier mandated by the selected
// entityID-based artifact profile. SHA-1 here is a routing identifier only.
func ArtifactSource(entityID string) [artifactIdentifierBytes]byte { return sha1.Sum([]byte(entityID)) } // #nosec G401 -- Interoperable SAML artifact routing identifier.

// String returns the standard Base64 representation, including padding.
func (a Artifact) String() string {
	var b [artifactWireBytes]byte
	binary.BigEndian.PutUint16(b[:artifactEndpointOffset], artifactTypeCode)
	binary.BigEndian.PutUint16(b[artifactEndpointOffset:artifactSourceOffset], a.EndpointIndex)
	copy(b[artifactSourceOffset:artifactHandleOffset], a.SourceID[:])
	copy(b[artifactHandleOffset:], a.MessageHandle[:])

	return base64.StdEncoding.EncodeToString(b[:])
}

// ParseArtifact decodes exactly one canonical type 0x0004 artifact.
func ParseArtifact(value string) (Artifact, error) {
	const (
		artifactEncodedBytes = 60
	)

	var a Artifact
	if len(value) != artifactEncodedBytes {
		return a, ErrBinding
	}

	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != artifactWireBytes || binary.BigEndian.Uint16(b[:artifactEndpointOffset]) != artifactTypeCode {
		return a, ErrBinding
	}

	a.EndpointIndex = binary.BigEndian.Uint16(b[artifactEndpointOffset:artifactSourceOffset])
	copy(a.SourceID[:], b[artifactSourceOffset:artifactHandleOffset])
	copy(a.MessageHandle[:], b[artifactHandleOffset:])

	return a, nil
}

// EncodeArtifact returns query/form fields for the HTTP Artifact binding. GET
// and POST use identical fields. RelayState is an opaque value of at most 80 bytes.
func EncodeArtifact(a Artifact, relay *string) (string, error) {
	if relay != nil && (len(*relay) > profile.HTTPRelayStateMaxBytes || !utf8.ValidString(*relay)) {
		return "", ErrBinding
	}

	v := url.Values{fieldArtifact: {a.String()}}
	if relay != nil {
		v.Set(fieldRelayState, *relay)
	}

	return v.Encode(), nil
}

// DecodeArtifact rejects duplicate SAMLart/RelayState and mixed message bindings.
// Other query parameters are preserved by the surrounding application.
func DecodeArtifact(form string) (Artifact, *string, error) {
	const (
		maximumArtifactFormBytes = 16 << 10
	)

	if len(form) > maximumArtifactFormBytes {
		return Artifact{}, nil, ErrBinding
	}

	v, err := url.ParseQuery(form)
	if err != nil || len(v[fieldArtifact]) != 1 || len(v[fieldRelayState]) > 1 || len(v[string(Request)])+len(v[string(Response)])+len(v[nameSignature])+len(v[fieldSignatureAlgorithm]) != 0 {
		return Artifact{}, nil, ErrBinding
	}

	a, err := ParseArtifact(v.Get(fieldArtifact))
	if err != nil {
		return a, nil, err
	}

	var relay *string

	if values, ok := v[fieldRelayState]; ok {
		if len(values[0]) > profile.HTTPRelayStateMaxBytes || !utf8.ValidString(values[0]) {
			return a, nil, ErrBinding
		}

		relay = &values[0]
	}

	return a, relay, nil
}

// ArtifactURL constructs a GET delivery URL at an application-trusted endpoint.
func ArtifactURL(endpoint string, a Artifact, relay *string) (string, error) {
	if !profile.Endpoint(endpoint, false) {
		return "", ErrBinding
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return "", ErrBinding
	}

	v, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", ErrBinding
	}

	for _, name := range []string{fieldArtifact, fieldRelayState, string(Request), string(Response), fieldSignatureAlgorithm, nameSignature} {
		if _, ok := v[name]; ok {
			return "", ErrBinding
		}
	}

	query, err := EncodeArtifact(a, relay)
	if err != nil {
		return "", err
	}

	if u.RawQuery != "" {
		u.RawQuery += "&"
	}

	u.RawQuery += query

	return u.String(), nil
}

// ArtifactForm renders a passive POST form without executable scripts.
// RelayState must be UTF-8 without control characters, as for WritePOSTForm.
func ArtifactForm(endpoint string, a Artifact, relay *string) ([]byte, error) {
	const (
		htmlArtifactFormPrefix = "<!doctype html><html><head><meta charset=\"utf-8\"><title>SAML artifact</title></head><body><form method=\"post\" action=\""
	)

	if !profile.Endpoint(endpoint, false) || !validHTMLRelay(relay) {
		return nil, ErrBinding
	}

	if _, err := EncodeArtifact(a, relay); err != nil {
		return nil, err
	}

	form := htmlArtifactFormPrefix + html.EscapeString(endpoint) + htmlHiddenInputPrefix + fieldArtifact + htmlInputValuePrefix + a.String() + `">`
	if relay != nil {
		form += htmlRelayInputPrefix + html.EscapeString(*relay) + `">`
	}

	return []byte(form + htmlFormSuffix), nil
}
