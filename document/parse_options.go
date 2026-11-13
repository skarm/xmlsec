package document

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/tree"
)

// EntityResolver opens an explicitly authorized external XML entity. The system
// identifier is relative to baseURI; the returned URI is the entity's actual
// retrieval base. The parser closes every returned stream, including on error.
// Resolution and blocking reads must honor cancellation. Nil permits no I/O.
type EntityResolver = tree.DTDEntityResolver

// ParseProfile selects the XML grammar and input features.
type ParseProfile uint8

const (
	// SecurityProfile is the default XML 1.0 profile. It accepts UTF-8 and
	// UTF-16, requires absolute namespace names and rejects DTDs and external
	// entities.
	SecurityProfile ParseProfile = iota
	// DTDProfile enables bounded, nonvalidating XML 1.0 DTD processing,
	// including entity expansion and attribute defaults. It accepts supported
	// single-byte encodings and relative namespace names. External entities
	// require an explicit EntityResolver.
	DTDProfile
)

// ParseOptions selects the XML profile and its resource policy. The zero value
// uses SecurityProfile and DefaultLimits.
type ParseOptions struct {
	// Limits bounds source bytes, expanded XML, entities, declarations and depth.
	// A completely zero value selects DefaultLimits; partial limits must be valid.
	Limits Limits
	// Profile selects the parser. Unknown values are rejected.
	Profile ParseProfile
	// BaseURI identifies the document entity for relative external identifiers.
	BaseURI string
	// EntityResolver supplies external subsets and entities for DTDProfile.
	// External declarations needing retrieval fail when no resolver is configured.
	EntityResolver EntityResolver
}

// Parse constructs an immutable document using the selected XML processor.
func (o ParseOptions) Parse(ctx context.Context, data []byte) (*Document, error) {
	return o.ParseReader(ctx, bytes.NewReader(data))
}

// ParseReader consumes src without closing it. Nonvalidating DTD processing
// additionally retains bounded decoded/expanded input; the security mode uses
// the incremental parser. External streams belong to the parser.
func (o ParseOptions) ParseReader(ctx context.Context, src io.Reader) (*Document, error) {
	p, err := o.options()
	if err != nil {
		return nil, err
	}

	d, err := p.ParseReader(ctx, src)

	return o.withBase(d, err)
}

// ParseText parses already decoded XML characters. An encoding declaration does
// not reinterpret them; external entities still use their own byte encoding.
func (o ParseOptions) ParseText(ctx context.Context, text string) (*Document, error) {
	p, err := o.options()
	if err != nil {
		return nil, err
	}

	d, err := p.ParseText(ctx, text)

	return o.withBase(d, err)
}

func (o ParseOptions) options() (tree.ParseOptions, error) {
	p := tree.ParseOptions{Limits: limitsOrDefault(o.Limits), BaseURI: o.BaseURI, DTDResolver: o.EntityResolver}

	switch o.Profile {
	case SecurityProfile:
		if o.EntityResolver != nil {
			return tree.ParseOptions{}, ErrUnsupported
		}
	case DTDProfile:
		p.AllowDTD = true
		p.AllowSingleByteEncodings = true
		p.AllowRelativeNamespaces = true
	default:
		return tree.ParseOptions{}, fmt.Errorf("%w: XML parse profile %d", ErrUnsupported, o.Profile)
	}

	if err := p.Limits.Validate(); err != nil {
		return tree.ParseOptions{}, err
	}

	return p, nil
}

func (o ParseOptions) withBase(d *Document, err error) (*Document, error) {
	if err != nil {
		return nil, err
	}

	if o.BaseURI != "" {
		_, root := tree.Unwrap(d.Root())
		tree.SetNodeBase(d, root, o.BaseURI)
	}

	return d, nil
}
