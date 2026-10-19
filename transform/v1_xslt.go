package transform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	"github.com/skarm/xmlsec/transform/internal/xslt"
)

const stylesheetNamespace = "http://www.w3.org/1999/XSL/Transform"

func compileV1Stylesheet(e *Engine, source []byte) (*xslt.Stylesheet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), max(e.limits.Timeout, 3*time.Second))
	defer cancel()

	limits := document.DefaultLimits()
	limits.MaxBytes = 1 << 20

	d, err := document.Parse(ctx, source, limits)
	if err != nil {
		return nil, v1Error(err)
	}

	if err = checkStylesheet(d.Node()); err != nil {
		return nil, err
	}
	// Keep the previous 1.0 syntax/resource preflight, and use the same embedded
	// XSLT executor as the modern API in its backwards-compatible mode.
	native, err := xdm.WrapDocument(ctx, d)
	if err != nil {
		return nil, v1Error(err)
	}

	compiled, err := xslt.NewCompiler().ParseOptions(e.parseOptions()).Compile(ctx, native)
	if err != nil {
		return nil, v1Error(err)
	}

	return compiled, nil
}

func checkStylesheet(n document.Node) error {
	if e, ok := n.Element(); ok {
		if err := checkStylesheetElement(e); err != nil {
			return err
		}
	}

	for _, child := range n.Children() {
		if err := checkStylesheet(child); err != nil {
			return err
		}
	}

	return nil
}

func checkStylesheetElement(e document.Element) error {
	name := e.Name()

	attrs, known := xslt.XSLT10ElementAttributes(name.Local)
	if name.Space == stylesheetNamespace && (name.Local == "include" || name.Local == "import") {
		return fmt.Errorf("%w: XMLDSig stylesheet resources are disabled", reference.ErrUnsupported)
	}

	if name.Space == stylesheetNamespace && !known {
		return fmt.Errorf("%w: XSLT instruction %s", reference.ErrUnsupported, name.Local)
	}

	ns := make(map[string]string)
	for _, b := range e.NamespaceNodes() {
		ns[b.Name().Local] = b.Value()
	}

	for _, a := range e.Attributes() {
		if err := checkStylesheetAttribute(a, name, attrs, ns); err != nil {
			return err
		}
	}

	return nil
}

func checkStylesheetAttribute(a tree.Attribute, name tree.Name, attrs string, ns map[string]string) error {
	if a.Name.Space == document.XMLNamespace {
		return nil
	}

	if err := checkStylesheetAttributeName(a.Name, name, attrs); err != nil {
		return err
	}

	if err := checkStylesheetProfileAttribute(a, name); err != nil {
		return err
	}

	if name.Space == stylesheetNamespace && a.Name.Space == "" && containsWord("select test match use count from value", a.Name.Local) {
		return checkStylesheetXPath(a.Value, ns)
	}

	if name.Space != stylesheetNamespace && a.Name.Space != stylesheetNamespace || name.Space == stylesheetNamespace && isStylesheetAVT(name.Local, a.Name.Local) {
		return checkStylesheetAVT(a.Value, ns)
	}

	return nil
}

func checkStylesheetAttributeName(attribute, element tree.Name, attrs string) error {
	if element.Space == stylesheetNamespace && attribute.Space == "" && !containsWord(attrs, attribute.Local) {
		return fmt.Errorf("%w: XSLT attribute %s", reference.ErrUnsupported, attribute.Local)
	}

	if attribute.Space == stylesheetNamespace && (element.Space == stylesheetNamespace || !containsWord("version extension-element-prefixes exclude-result-prefixes use-attribute-sets", attribute.Local)) {
		return fmt.Errorf("%w: XSLT attribute %s", reference.ErrUnsupported, attribute.Local)
	}

	return nil
}

func containsWord(words, word string) bool {
	for s := range strings.FieldsSeq(words) {
		if s == word {
			return true
		}
	}

	return false
}

func isStylesheetAVT(element, attribute string) bool {
	switch element {
	case "element", "attribute":
		return attribute == "name" || attribute == "namespace"
	case "processing-instruction":
		return attribute == "name"
	case "sort":
		return containsWord("lang data-type order case-order", attribute)
	case "number":
		return containsWord("format lang letter-value grouping-separator grouping-size", attribute)
	}

	return false
}

func checkStylesheetXPath(code string, ns map[string]string) error {
	if len(code) > 16<<10 {
		return reference.ErrLimit
	}

	return staticStylesheetXPath(reference.XPathExpression{Expression: code, Namespaces: ns})
}

// Scan AVTs with XPath quoting, and honor doubled braces outside expressions.
func checkStylesheetAVT(value string, ns map[string]string) error {
	for i := 0; i < len(value); i++ {
		if value[i] != '{' && value[i] != '}' {
			continue
		}

		if i+1 < len(value) && value[i+1] == value[i] {
			i++
			continue
		}

		if value[i] == '}' {
			return fmt.Errorf("%w: unmatched AVT brace", reference.ErrInput)
		}

		start := i + 1

		var quote byte

		for i++; i < len(value); i++ {
			c := value[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				}

				continue
			}

			if c == '\'' || c == '"' {
				quote = c
				continue
			}

			if c == '}' {
				break
			}
		}

		if i == len(value) {
			return fmt.Errorf("%w: unterminated AVT", reference.ErrInput)
		}

		if err := checkStylesheetXPath(value[start:i], ns); err != nil {
			return err
		}
	}

	return nil
}

func (p *v1Processor) applyStylesheet(ctx context.Context, tr reference.Transform, in reference.Data) (reference.Data, error) {
	source, ok := in.Bytes()
	if !ok {
		return reference.Data{}, reference.ErrInput
	}

	if len(source) > p.input {
		return reference.Data{}, reference.ErrLimit
	}

	ctx, cancel, err := p.engine.invocation(ctx)
	if err != nil {
		return reference.Data{}, v1Error(err)
	}
	defer cancel()

	d, err := p.engine.parse(ctx, source, "")
	if err != nil {
		return reference.Data{}, v1Error(err)
	}

	key, err := Fingerprint(tr)
	if err != nil {
		return reference.Data{}, err
	}

	s := Stylesheet{engine: p.engine, native: p.stylesheets[key]}

	out, err := s.Transform(ctx, d, XSLTContext{})
	if err != nil {
		return reference.Data{}, v1Error(err)
	}

	return reference.Octets(out.Primary), nil
}

func v1Error(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, ErrUnsupported) {
		return fmt.Errorf("%w: %w", reference.ErrUnsupported, err)
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, reference.ErrLimit) {
		return err
	}

	if errors.Is(err, ErrLimit) || errors.Is(err, xpath.ErrBudget) || errors.Is(err, document.ErrLimit) {
		return fmt.Errorf("%w: %w", reference.ErrLimit, err)
	}

	return fmt.Errorf("%w: XSLT: %w", reference.ErrInput, err)
}

func staticStylesheetXPath(x reference.XPathExpression) error {
	expr, err := xpath.NewCompiler().Language(10, x.Namespaces).Compile(x.Expression)
	if err != nil {
		return executionError(err)
	}

	if err = expr.Validate(x.Namespaces); err != nil {
		return executionError(err)
	}

	for _, ref := range expr.StaticReferences(x.Namespaces).FunctionNames {
		bounds, known := xslt.XPath10FunctionArity(ref.Name)
		if ref.Prefix != "" || !known || ref.Name == "document" || ref.Arity < bounds[0] || bounds[1] >= 0 && ref.Arity > bounds[1] {
			return fmt.Errorf("%w: XPath extension function %s", reference.ErrUnsupported, ref.Name)
		}
	}

	return nil
}

func checkStylesheetProfileAttribute(a tree.Attribute, name tree.Name) error {
	if !(a.Name.Space == "" && name.Space == stylesheetNamespace || a.Name.Space == stylesheetNamespace) {
		return nil
	}

	if a.Name.Local == "version" && (name.Local == "stylesheet" || name.Local == "transform" || a.Name.Space == stylesheetNamespace) && a.Value != "1.0" {
		return fmt.Errorf("%w: XSLT 1.0 required", reference.ErrUnsupported)
	}

	if a.Name.Local == "extension-element-prefixes" && strings.TrimSpace(a.Value) != "" {
		return fmt.Errorf("%w: XSLT extension elements", reference.ErrUnsupported)
	}

	return nil
}
