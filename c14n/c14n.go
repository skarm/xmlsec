package c14n

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

const (
	// Exclusive is the Exclusive C14N 1.0 algorithm URI.
	Exclusive = tree.AlgorithmExclusive
	// ExclusiveWithComments is the Exclusive C14N 1.0 with-comments URI.
	ExclusiveWithComments = Exclusive + "WithComments"
	// Canonical10 is the Canonical XML 1.0 algorithm URI.
	Canonical10 = tree.AlgorithmCanonical10
	// Canonical10WithComments is the Canonical XML 1.0 with-comments URI.
	Canonical10WithComments = Canonical10 + "#WithComments"
	// Canonical11 is the Canonical XML 1.1 algorithm URI.
	Canonical11 = tree.AlgorithmCanonical11
	// Canonical11WithComments is the Canonical XML 1.1 with-comments URI.
	Canonical11WithComments = Canonical11 + "#WithComments"
)

// Options selects a canonicalization algorithm, namespace prefix list and output budget.
type Options struct {
	// Algorithm is a canonicalization URI. Empty selects
	// Exclusive C14N 1.0. A WithComments URI always includes selected comments.
	Algorithm string
	// WithComments enables comments also with a base (non-WithComments) URI.
	WithComments bool
	// InclusivePrefixes applies only to Exclusive C14N. Missing prefixes are
	// ignored; #default names the default namespace. It does not select nodes
	// omitted from an explicit NodeSet and does not rewrite QName string values.
	InclusivePrefixes []string
	// MaxOutputBytes bounds canonical bytes; zero uses 32 MiB. A failing write may have
	// emitted a prefix of the output. Callers must discard partial output after any error.
	MaxOutputBytes int
}

// WriteDocument includes document-level PIs and, when requested, comments.
func WriteDocument(ctx context.Context, w io.Writer, d *document.Document, opt Options) error {
	return tree.Canonical(ctx, w, d, nil, nil, options(opt))
}

// WriteElement selects the element, every descendant, and all their attributes
// and in-scope namespace nodes. Context is taken from the original snapshot.
// Inclusive algorithms apply their respective orphan xml:* inheritance rules.
func WriteElement(ctx context.Context, w io.Writer, e document.Element, opt Options) error {
	d, n := tree.Unwrap(e)
	return tree.Canonical(ctx, w, d, n, nil, options(opt))
}

// WriteNodeSet processes precisely the selected nodes, with the context/fix-up
// rules of the requested algorithm. It does not evaluate XPath expressions.
func WriteNodeSet(ctx context.Context, w io.Writer, set document.NodeSet, opt Options) error {
	return tree.Canonical(ctx, w, set.Document(), nil, &set, options(opt))
}

func options(opt Options) tree.CanonicalOptions {
	return tree.CanonicalOptions{
		Algorithm:         opt.Algorithm,
		Comments:          opt.WithComments,
		InclusivePrefixes: opt.InclusivePrefixes,
		MaxBytes:          opt.MaxOutputBytes,
	}
}
