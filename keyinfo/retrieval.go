package keyinfo

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

type retrievalPlan struct {
	uri, typ   string
	transforms []reference.Transform
	processing reference.Options
	base64     bool
}

type retrievalOutput struct {
	digest   [32]byte
	resource string
}

// Freeze and validate processing policy before any resource or program callback.
func (p *parser) configureRetrieval() error {
	if p.options.RetrievalProcessing == nil {
		return nil
	}

	o := *p.options.RetrievalProcessing

	o.AllowedTransforms = append([]string(nil), o.AllowedTransforms...)
	if o.Signature.Valid() || len(o.IDRules) != 0 {
		return fmt.Errorf("%w: retrieval Signature and IDRules belong to the parser", ErrPolicy)
	}

	if err := reference.PrepareTransforms(p.ctx, nil, o); err != nil {
		return retrievalError(err)
	}

	defaults := reference.DefaultOptions()
	for _, limit := range []struct {
		value             *int
		fallback, maximum int
	}{
		{&o.MaxTransforms, defaults.MaxTransforms, 64},
		{&o.MaxInputBytes, defaults.MaxInputBytes, p.limits.MaxBlobBytes * 2},
		{&o.MaxOutputBytes, defaults.MaxOutputBytes, p.limits.MaxBlobBytes * 2},
		{&o.MaxProducedBytes, defaults.MaxProducedBytes, p.limits.MaxTransformBytes},
		{&o.MaxNodeVisits, defaults.MaxNodeVisits, p.limits.MaxTransformNodes},
	} {
		if *limit.value == 0 {
			*limit.value = limit.fallback
		}

		*limit.value = min(*limit.value, limit.maximum)
	}

	if o.XMLLimits == (document.Limits{}) {
		o.XMLLimits = document.DefaultLimits()
	}

	o.XMLLimits.MaxBytes = min(o.XMLLimits.MaxBytes, p.limits.MaxBlobBytes*2)
	o.XMLLimits.MaxNodes = min(o.XMLLimits.MaxNodes, p.limits.MaxElements*8, p.limits.MaxTransformNodes)
	o.XMLLimits.MaxNodeSetNodes = min(o.XMLLimits.MaxNodeSetNodes, p.limits.MaxTransformNodes)
	o.XMLLimits.MaxDepth = min(o.XMLLimits.MaxDepth, 64)
	p.options.RetrievalProcessing = &o

	return nil
}

func retrievalType(typ string) (document.Name, error) {
	switch typ {
	case "":
		return document.Name{}, nil
	case RawX509Certificate, Namespace + nameX509Data:
		return document.Name{Space: Namespace, Local: nameX509Data}, nil
	case Namespace + nameRSAKeyValue:
		return document.Name{Space: Namespace, Local: nameRSAKeyValue}, nil
	case Namespace + nameDSAKeyValue:
		return document.Name{Space: Namespace, Local: nameDSAKeyValue}, nil
	case Namespace11 + nameECKeyValue:
		return document.Name{Space: Namespace11, Local: nameECKeyValue}, nil
	case Namespace11 + nameDEREncodedKeyValue:
		return document.Name{Space: Namespace11, Local: nameDEREncodedKeyValue}, nil
	default:
		return document.Name{}, fmt.Errorf("%w: RetrievalMethod Type", ErrUnsupported)
	}
}

func (p *parser) prepareRetrieval(s *scope, n *tree.Node) (retrievalPlan, error) {
	key := visitKey{s.doc, n}
	if plan, ok := p.retrievalPlans[key]; ok {
		return plan, nil
	}

	var plan retrievalPlan

	children, err := structure(n, Namespace, "RetrievalMethod", "URI", "Type")
	if err != nil {
		return plan, err
	}

	var ok bool

	plan.uri, ok = attr(n, "URI")
	if !ok {
		return plan, fmt.Errorf("%w: RetrievalMethod URI is required", ErrInput)
	}

	if len(plan.uri) > 8192 {
		return plan, ErrLimit
	}

	plan.typ, _ = attr(n, "Type")

	representation, err := retrievalType(plan.typ)
	if err != nil {
		return plan, err
	}

	if representation.Local != "" {
		if err := p.requireKeyData(representation); err != nil {
			return plan, err
		}
	}

	if p.options.RetrievalProcessing == nil {
		plan.base64, err = retrievalTransform(children, plan.typ)
	} else {
		plan.processing = *p.options.RetrievalProcessing
		plan.processing.IDRules = append(DefaultIDRules(), p.options.AdditionalIDRules...)

		for parent := n.Parent; parent != nil; parent = parent.Parent {
			if is(parent, Namespace, lexicon.DSigElementSignature) {
				plan.processing.Signature = tree.Wrap(s.doc, parent)
				break
			}
		}

		plan.transforms, err = p.parseRetrievalTransforms(s, children, plan.processing)
	}

	if err != nil {
		return plan, err
	}

	plan.uri, err = p.resourceURI(s, n, plan.uri)
	if err != nil {
		return plan, err
	}

	if externalURI(plan.uri) && !p.allow[plan.uri] {
		return plan, fmt.Errorf("%w: external URI not allowed", ErrPolicy)
	}

	for _, t := range plan.transforms {
		if t.Algorithm == reference.EnvelopedSignature && (!plan.processing.Signature.Valid() || externalURI(plan.uri)) {
			return plan, fmt.Errorf("%w: retrieval enveloped transform requires its local containing Signature", ErrInput)
		}
	}

	if p.retrievalPlans == nil {
		p.retrievalPlans = make(map[visitKey]retrievalPlan)
	}

	p.retrievalPlans[key] = plan

	return plan, nil
}

func (p *parser) parseRetrievalTransforms(s *scope, children []*tree.Node, opt reference.Options) ([]reference.Transform, error) {
	var transforms []reference.Transform

	if len(children) != 0 {
		if len(children) != 1 {
			return nil, ErrInput
		}

		nodes, err := structure(children[0], Namespace, lexicon.DSigElementTransforms)
		if err != nil {
			return nil, err
		}

		if len(nodes) == 0 {
			return nil, ErrInput
		}

		if len(nodes) > opt.MaxTransforms {
			return nil, ErrLimit
		}

		for _, node := range nodes {
			transform, err := transformxml.Parse(p.ctx, s.doc, node)
			if err != nil {
				return nil, retrievalError(err)
			}

			transforms = append(transforms, transform)
		}
	}

	if err := reference.PrepareTransforms(p.ctx, transforms, opt); err != nil {
		return nil, retrievalError(err)
	}

	return transforms, nil
}

func (p *parser) readRawResource(uri string) ([]byte, error) {
	if data, ok := p.rawResources[uri]; ok {
		return data, nil
	}

	var data []byte

	err := p.consumeResource(uri, func(src io.Reader) error {
		var err error

		data, err = io.ReadAll(src)

		return err
	})
	if err != nil {
		return nil, err
	}

	if p.rawResources == nil {
		p.rawResources = make(map[string][]byte)
	}

	p.rawResources[uri] = data

	return data, nil
}

func (p *parser) processRetrieval(s *scope, n *tree.Node, depth int, plan retrievalPlan) error {
	bytesLeft := p.limits.MaxTransformBytes - p.transformBytes

	nodesLeft := p.limits.MaxTransformNodes - p.transformNodes
	if bytesLeft < 1 || nodesLeft < 1 {
		return ErrLimit
	}

	opt := plan.processing
	opt.MaxProducedBytes = min(opt.MaxProducedBytes, bytesLeft)
	opt.MaxNodeVisits = min(opt.MaxNodeVisits, nodesLeft)
	opt.XMLLimits.MaxNodes = min(opt.XMLLimits.MaxNodes, nodesLeft)

	var (
		output bytes.Buffer
		report *reference.Report
		err    error
	)

	origin := *s
	if externalURI(plan.uri) {
		origin.resource = plan.uri

		var data []byte

		data, err = p.readRawResource(plan.uri)
		if err == nil {
			report, err = reference.WriteReader(p.ctx, &output, bytes.NewReader(data), plan.transforms, opt)
		}
	} else {
		var resolved reference.Resolved

		resolved, err = s.resolver.Resolve(p.ctx, plan.uri)
		if err == nil {
			report, err = reference.Write(p.ctx, &output, resolved.Data(), plan.transforms, opt)
		}
	}

	if err != nil {
		return retrievalError(err)
	}

	p.transformBytes += report.ProducedBytes()

	p.transformNodes += report.NodeVisits()
	if plan.typ == RawX509Certificate {
		if err := p.charge(output.Len()); err != nil {
			return err
		}

		return p.certificate(&origin, n, output.Bytes())
	}

	next, err := p.retrievalScope(output.Bytes(), origin.resource)
	if err != nil {
		return err
	}

	return p.acceptRetrievalTarget(tree.Root(next.doc), next, plan.typ, depth)
}

func (p *parser) retrievalScope(data []byte, resource string) (*scope, error) {
	key := retrievalOutput{digest: sha256.Sum256(data), resource: resource}
	if cached, ok := p.transformedScopes[key]; ok {
		return cached, nil
	}

	remaining := p.limits.MaxTransformNodes - p.transformNodes
	if remaining < 2 {
		return nil, ErrLimit
	}

	limits := p.options.RetrievalProcessing.XMLLimits
	limits.MaxNodes = min(limits.MaxNodes, remaining/2)
	limits.MaxNodeSetNodes = min(limits.MaxNodeSetNodes, remaining/2)

	doc, err := document.Parse(p.ctx, data, limits)
	if err != nil {
		return nil, retrievalError(err)
	}

	nodes, err := doc.AllNodes(p.ctx)
	if err != nil {
		return nil, retrievalError(err)
	}
	// Account for parsing and indexing the resulting snapshot, including its
	// expanded namespace/attribute nodes. Cached snapshots keep graph identity.
	if nodes.Len() > remaining/2 {
		return nil, ErrLimit
	}

	p.transformNodes += 2 * nodes.Len()

	next, err := p.newScope(doc, resource)
	if err != nil {
		return nil, err
	}

	if p.transformedScopes == nil {
		p.transformedScopes = make(map[retrievalOutput]*scope)
	}

	p.transformedScopes[key] = next

	return next, nil
}

func retrievalError(err error) error {
	if err == nil {
		return nil
	}

	var category error

	switch {
	case errors.Is(err, reference.ErrPolicy):
		category = ErrPolicy
	case errors.Is(err, reference.ErrLimit), errors.Is(err, document.ErrLimit):
		category = ErrLimit
	case errors.Is(err, reference.ErrUnsupported), errors.Is(err, document.ErrUnsupported):
		category = ErrUnsupported
	case errors.Is(err, reference.ErrInput), errors.Is(err, document.ErrMalformed):
		category = ErrInput
	default:
		return err
	}

	return errors.Join(category, err)
}
