package xmlenc

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/uriref"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/resource"
)

type graphCipherPlan struct {
	document   *graphDocument
	element    document.Element
	maximum    int
	uri        string
	transforms []reference.Transform
	local      bool
	inline     bool
}

func (g *keyGraph) absoluteReference(source *graphDocument, element document.Element, raw string) (*url.URL, error) {
	if !validGraphReference(raw) {
		return nil, ErrFormat
	}

	_, node := tree.Unwrap(element)

	resolved, err := uriref.Resolve(raw, g.baseURI, source.uri, node)
	if err != nil {
		return nil, errors.Join(ErrFormat, err)
	}

	if !validGraphReference(resolved) {
		return nil, ErrFormat
	}

	uri, err := url.Parse(resolved)
	if err != nil || uri.User != nil {
		return nil, ErrFormat
	}

	if !uri.IsAbs() {
		return nil, ErrPolicy
	}

	return uri, nil
}

func (g *keyGraph) referenceOptions(maximum int) (reference.Options, error) {
	if g.remaining.MaxBytes < 1 || g.remaining.MaxNodes < 1 {
		return reference.Options{}, graphLimitError()
	}

	allowed := g.options.CipherTransforms
	if len(allowed) == 0 {
		allowed = []string{reference.Base64, c14n.Canonical10}
	}

	for _, algorithm := range allowed {
		switch algorithm {
		case reference.Base64, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments, c14n.Exclusive, c14n.ExclusiveWithComments:
		default:
			return reference.Options{}, ErrPolicy
		}
	}

	return reference.Options{AllowedTransforms: allowed, MaxTransforms: 8, MaxInputBytes: g.remaining.MaxBytes, MaxOutputBytes: min(maximum, g.remaining.MaxBytes), MaxProducedBytes: g.remaining.MaxBytes, MaxNodeVisits: g.remaining.MaxNodes, XMLLimits: g.profile.options.XMLLimits}, nil
}

func (g *keyGraph) cipherPlan(doc *graphDocument, data document.Element, maximum int) (*graphCipherPlan, error) {
	if !exactAttributes(data) || len(data.Children()) != 1 || !graphStructuralText(data) {
		return nil, ErrFormat
	}

	p := &graphCipherPlan{document: doc, element: data, maximum: maximum}

	child := data.Children()[0]
	if child.Name() == elementName(Namespace, "CipherValue") {
		if !exactAttributes(child) || len(child.Children()) != 0 {
			return nil, ErrFormat
		}

		p.inline = true

		return p, nil
	}

	if child.Name() != elementName(Namespace, "CipherReference") || !exactAttributes(child, "URI") || !graphStructuralText(child) {
		return nil, ErrFormat
	}

	p.uri = attributeValue(child, "URI")
	if !validGraphReference(p.uri) {
		return nil, ErrFormat
	}

	var err error

	p.transforms, err = graphCipherTransforms(child)
	if err != nil {
		return nil, err
	}

	options, err := g.referenceOptions(maximum)
	if err != nil {
		return nil, err
	}

	if err := reference.ValidateTransforms(p.transforms, options); err != nil {
		return nil, errors.Join(ErrPolicy, err)
	}

	if err := g.authorizeCipher(p); err != nil {
		return nil, err
	}

	return p, nil
}

func (g *keyGraph) authorizeCipher(p *graphCipherPlan) error {
	if p.uri == "" || strings.HasPrefix(p.uri, "#") {
		p.local = true
		if _, _, err := p.document.resolver.Target(g.ctx, p.uri); err != nil {
			return errors.Join(ErrFormat, err)
		}

		return nil
	}

	absolute, err := g.absoluteReference(p.document, p.element.Children()[0], p.uri)
	if err != nil {
		return err
	}

	if absolute.Fragment != "" {
		return ErrPolicy
	}

	p.uri = absolute.String()

	external := g.profile.options.External
	if external == nil || p.uri != external.URI {
		return ErrPolicy
	}

	if len(p.transforms) > 1 || len(p.transforms) == 1 && p.transforms[0].Algorithm != reference.Base64 {
		return ErrPolicy
	}

	return nil
}

func graphCipherTransforms(child document.Element) ([]reference.Transform, error) {
	if len(child.Children()) == 0 {
		return nil, nil
	}

	containers, err := childElements(child, elementName(Namespace, lexicon.DSigElementTransforms))
	if err != nil {
		return nil, err
	}

	transforms := containers[0]
	if !exactAttributes(transforms) || !graphStructuralText(transforms) || len(transforms.Children()) == 0 {
		return nil, ErrFormat
	}

	result := make([]reference.Transform, 0, len(transforms.Children()))
	for _, item := range transforms.Children() {
		transform, err := graphCipherTransform(item)
		if err != nil {
			return nil, err
		}

		result = append(result, transform)
	}

	return result, nil
}

func graphCipherTransform(item document.Element) (reference.Transform, error) {
	if item.Name() != elementName(SignatureNamespace, lexicon.DSigElementTransform) || !exactAttributes(item, "Algorithm") || !graphStructuralText(item) {
		return reference.Transform{}, ErrFormat
	}

	t := reference.Transform{Algorithm: attributeValue(item, "Algorithm")}
	if len(item.Children()) == 0 {
		return t, nil
	}

	children, err := childElements(item, elementName(c14n.Exclusive, "InclusiveNamespaces"))
	if err != nil || !exactAttributes(children[0], "PrefixList") || len(children[0].Children()) != 0 || !xmlSpace(children[0].Text()) {
		return reference.Transform{}, ErrFormat
	}

	t.InclusivePrefixes = strings.Fields(attributeValue(children[0], "PrefixList"))

	return t, nil
}

func graphStructuralText(element document.Element) bool {
	_, node := tree.Unwrap(element)
	if node == nil {
		return false
	}

	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return false
		}
	}

	return true
}

func (g *keyGraph) readCipher(plan *graphCipherPlan) ([]byte, error) {
	if err := g.ctx.Err(); err != nil {
		return nil, err
	}

	if g.remaining.MaxBytes == 0 {
		return nil, graphLimitError()
	}

	if plan.inline {
		value, err := decodeCipherValue(g.ctx, plan.element, min(plan.maximum, g.remaining.MaxBytes))
		if err != nil {
			return nil, err
		}

		if err := g.charge(0, len(value)); err != nil {
			clear(value)
			return nil, err
		}

		return value, nil
	}

	if plan.local {
		resolved, err := plan.document.resolver.Resolve(g.ctx, plan.uri)
		if err != nil {
			return nil, errors.Join(ErrFormat, err)
		}

		options, err := g.referenceOptions(plan.maximum)
		if err != nil {
			return nil, err
		}

		output, err := reference.Process(g.ctx, resolved.Data(), plan.transforms, options)
		if err != nil {
			if g.ctx.Err() != nil {
				return nil, g.ctx.Err()
			}

			return nil, errors.Join(ErrFormat, err)
		}

		if err := g.charge(output.NodeVisits(), output.ProducedBytes()); err != nil {
			return nil, err
		}

		return output.Bytes(), nil
	}

	if g.remaining.MaxResources < 1 || g.remaining.MaxBytes < 1 {
		return nil, graphLimitError()
	}

	g.remaining.MaxResources--
	external := *g.profile.options.External
	original := external.Resolver
	actual := 0
	external.Resolver = resource.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		source, err := original.Resolve(ctx, uri)
		if nilcheck.IsNil(source) {
			return source, err
		}

		return &graphCountedReader{ReadCloser: source, count: &actual}, err
	})
	limit := min(external.MaxBytes, g.remaining.MaxBytes)
	transformed := len(plan.transforms) == 1

	value, err := readCipherResource(g.ctx, &external, limit, min(plan.maximum, g.remaining.MaxBytes), transformed)
	if err != nil {
		return nil, err
	}

	produced := 0
	if transformed {
		produced = len(value)
	}

	if err := g.charge(0, actual+produced); err != nil {
		clear(value)
		return nil, err
	}

	return value, nil
}

type graphCountedReader struct {
	io.ReadCloser
	count *int
}

func (r *graphCountedReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 && n <= len(p) {
		*r.count += n
	}

	return n, err
}
