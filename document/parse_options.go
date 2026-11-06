package document

import (
	"bytes"
	"context"
	"io"

	"github.com/skarm/xmlsec/internal/tree"
)

// EntityResolver opens an explicitly authorized external XML entity. The system
// identifier is relative to baseURI; the returned URI is the entity's actual
// retrieval base. The parser closes every returned stream, including on error.
// Resolution and blocking reads must honor cancellation. Nil permits no I/O.
type EntityResolver = tree.DTDEntityResolver

// ParseOptions selects the XML processor and its resource policy. The zero value
// retains the DTD-free security parser and uses DefaultLimits.
type ParseOptions struct {
	// Limits bounds source bytes, expanded XML, entities, declarations and depth.
	// A completely zero value selects DefaultLimits; partial limits must be valid.
	Limits Limits
	// NonValidating enables XML 1.0 internal/external DTD processing, entity and
	// attribute expansion, supported single-byte encodings, and Namespaces 1.0
	// relative namespace names. It does not perform DTD validity checking.
	NonValidating bool
	// BaseURI identifies the document entity for relative external identifiers.
	BaseURI string
	// EntityResolver supplies external subsets, parameter and general entities.
	// There is no implicit filesystem, network or catalog access. External
	// declarations needing retrieval fail when no resolver is configured.
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
	if !o.NonValidating && o.EntityResolver != nil {
		return tree.ParseOptions{}, ErrUnsupported
	}

	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits()
	}

	if err := o.Limits.Validate(); err != nil {
		return tree.ParseOptions{}, err
	}

	return tree.ParseOptions{
		Limits: o.Limits, BaseURI: o.BaseURI, DTDResolver: o.EntityResolver,
		AllowDTD: o.NonValidating, AllowSingleByteEncodings: o.NonValidating,
		AllowRelativeNamespaces: o.NonValidating,
	}, nil
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
