package reference

import (
	"context"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

const (
	// XPath is the XMLDSig XPath 1.0 transform URI.
	XPath = "http://www.w3.org/TR/1999/REC-xpath-19991116"
	// XPathFilter2 is the XMLDSig XPath Filter 2.0 transform URI.
	XPathFilter2 = "http://www.w3.org/2002/06/xmldsig-filter2"
	// XSLT is the XMLDSig XSLT transform URI.
	XSLT = "http://www.w3.org/TR/1999/REC-xslt-19991116"
)

// XPathExpression supplies XPath 1.0 source and static namespace bindings.
// A default binding does not put unprefixed names in an element namespace.
// Here must identify the original expression element for runtime context; it
// cannot substitute a caller-created expression for one in the signature.
type XPathExpression struct {
	// Expression is the XPath source evaluated with these namespace bindings.
	Expression string `json:"expression"`
	// Filter is the Filter2 operation: intersect, subtract or union.
	// It must be empty for an ordinary XPath transform.
	Filter string `json:"filter,omitempty"`
	// Namespaces records prefix bindings at the XPath parameter element.
	Namespaces map[string]string `json:"namespaces,omitempty"`
	// Here is the original XPath parameter element for here(); it is not serialized.
	Here document.Element `json:"-"`
}

// ExtensionContext supplies signature and ID context from the reference processor.
// IDRules must match same-document resolution; implementations must not guess IDs.
type ExtensionContext struct {
	// Signature is the containing signature handle used by signature-aware transforms.
	Signature document.Element
	// IDRules supplies the same explicit ID typing used for same-document resolution.
	IDRules []IDAttributeRule
}

// ExtensionProcessor executes application-approved programs within explicit limits.
// Validate must reject unapproved programs; Apply must enforce execution limits.
// The library also checks output kind, snapshot identity, subset membership and
// size. Implementations must support concurrent use and cooperative cancellation;
// a context cannot interrupt a callback that ignores it. No processor is enabled
// by default. Package transform provides an implementation.
type ExtensionProcessor interface {
	// Validate approves a transform program before any chain execution or resource
	// resolution. It must reject programs outside application policy.
	Validate(context.Context, Transform) error
	// Apply executes an approved transform under context and processing limits. Returned
	// node sets must retain snapshot identity and stay within the permitted input
	// selection.
	Apply(context.Context, Transform, Data, ExtensionContext) (Data, error)
}

// ReaderExtensionProcessor executes approved XSLT programs using input and output
// streams. Write and WriteReader prefer it when available; otherwise they buffer
// octets for ExtensionProcessor.Apply. Streams remain caller-owned and errors can
// leave partial output. The implementation determines storage needs, which may
// include complete trees, results or byte buffers.
type ReaderExtensionProcessor interface {
	ExtensionProcessor
	// WriteTransform handles the XSLT transform. The library bounds actual I/O
	// and drains unread input before declaring success. The processor must also
	// bound its own execution work and intermediate structures.
	WriteTransform(context.Context, io.Writer, io.Reader, Transform, ExtensionContext) error
}

// IsExtension reports whether the URI identifies XPath, Filter2 or XSLT processing.
func IsExtension(a string) bool { return a == XPath || a == XPathFilter2 || a == XSLT }

// ValidateTransformParameters checks structure only: it does not approve a
// program, execute it or require a backend. Builders may use this function.
func ValidateTransformParameters(t Transform) error {
	if !IsExtension(t.Algorithm) {
		if len(t.XPath) != 0 || len(t.Stylesheet) != 0 {
			return fmt.Errorf("%w: foreign transform parameters", ErrInput)
		}

		return nil
	}

	if len(t.InclusivePrefixes) != 0 {
		return fmt.Errorf("%w: inclusive prefixes on extension", ErrInput)
	}

	if t.Algorithm == XSLT {
		_, err := checkedStylesheet(context.Background(), t)
		return err
	}

	if len(t.Stylesheet) != 0 || len(t.XPath) == 0 || len(t.XPath) > 16 || t.Algorithm == XPath && len(t.XPath) != 1 {
		return fmt.Errorf("%w: XPath parameter count", ErrInput)
	}

	if err := validateTransformParametersXPath(&t); err != nil {
		return err
	}

	return nil
}

// PrepareTransforms approves the entire chain before execution. High-level
// verifiers call this for every reachable reference before resolving resources.
func PrepareTransforms(ctx context.Context, ts []Transform, opt Options) error {
	if ctx == nil {
		return ErrInput
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	opt, err := normalize(opt)
	if err != nil {
		return err
	}

	if err := validate(ctx, ts, opt); err != nil {
		return err
	}

	return approveTransforms(ctx, ts, opt)
}

func checkedStylesheet(ctx context.Context, t Transform) (*document.Document, error) {
	if len(t.InclusivePrefixes) != 0 || len(t.XPath) != 0 || len(t.Stylesheet) == 0 || len(t.Stylesheet) > 1<<20 {
		return nil, fmt.Errorf("%w: stylesheet size/parameters", ErrInput)
	}

	doc, err := document.Parse(ctx, t.Stylesheet, document.DefaultLimits())
	if err != nil {
		return nil, fmt.Errorf("%w: stylesheet: %w", ErrInput, err)
	}

	name := doc.Root().Name()
	if name.Space != lexicon.NamespaceXSLT || name.Local != "stylesheet" && name.Local != "transform" {
		return nil, fmt.Errorf("%w: XSLT stylesheet root", ErrInput)
	}

	version, ok := doc.Root().Attribute(document.Name{Local: "version"})
	if !ok || version != "1.0" {
		return nil, fmt.Errorf("%w: XSLT 1.0 required", ErrUnsupported)
	}

	return doc, nil
}

func validateTransformParametersNCName(p string, u string) error {
	if p != "" && !tree.NCName(p) || p == "xmlns" || p == "xml" && u != tree.XMLNamespace || len(u) > 4096 || !utf8.ValidString(u) || p != "" && u == "" {
		return fmt.Errorf("%w: XPath namespace", ErrInput)
	}

	return nil
}

func validateTransformParametersAlgorithm(t *Transform, x *XPathExpression) error {
	if t.Algorithm == XPath && x.Filter != "" || t.Algorithm == XPathFilter2 && x.Filter != "intersect" && x.Filter != "subtract" && x.Filter != "union" {
		return fmt.Errorf("%w: XPath filter operation", ErrInput)
	}

	return nil
}

func validateTransformParametersXPath(t *Transform) error {
	for _, x := range t.XPath {
		if len(x.Expression) == 0 || len(x.Expression) > 16<<10 || !utf8.ValidString(x.Expression) || len(x.Namespaces) > 128 {
			return fmt.Errorf("%w: XPath expression/context size", ErrLimit)
		}

		if err := validateTransformParametersAlgorithm(t, &x); err != nil {
			return err
		}

		for p, u := range x.Namespaces {
			if err := validateTransformParametersNCName(p, u); err != nil {
				return err
			}
		}
	}

	return nil
}

func approveTransforms(ctx context.Context, ts []Transform, opt Options) error {
	for i, t := range ts {
		if err := ctx.Err(); err != nil {
			return err
		}

		if !IsExtension(t.Algorithm) {
			continue
		}

		program := CloneTransforms([]Transform{t})[0]
		if err := opt.Extension.Validate(ctx, program); err != nil {
			return &StepError{i, t.Algorithm, err}
		}
	}

	return ctx.Err()
}

// Check all budgets before copying parameters. Each callback gets a separate
// copy so approval cannot mutate either the caller's data or the executed chain.
func snapshotTransforms(ctx context.Context, ts []Transform, opt Options) ([]Transform, error) {
	if err := validate(ctx, ts, opt); err != nil {
		return nil, err
	}

	owned := CloneTransforms(ts)
	if err := approveTransforms(ctx, owned, opt); err != nil {
		return nil, err
	}

	return owned, nil
}

func checkedTransform(ctx context.Context, t Transform) (*document.Document, error) {
	if t.Algorithm == XSLT {
		return checkedStylesheet(ctx, t)
	}

	return nil, ValidateTransformParameters(t)
}

func cloneRules(rules []IDAttributeRule) []IDAttributeRule {
	out := append([]IDAttributeRule(nil), rules...)
	for i := range out {
		out[i].Elements = append([]document.Name(nil), out[i].Elements...)
	}

	return out
}
