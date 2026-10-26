package keyinfo

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/uriref"
	"github.com/skarm/xmlsec/reference"
)

type resourceBlob struct {
	data   []byte
	base64 bool
}

func (p *parser) configureExternal() error {
	if p.options.External == nil {
		return nil
	}

	e := p.options.External
	if nilcheck.IsNil(e.Resolver) || len(e.AllowedURIs) == 0 || len(e.AllowedURIs) > 1024 {
		return fmt.Errorf("%w: external resolver/allowlist", ErrPolicy)
	}
	// Copy configuration before invoking any caller callback.
	copied := *e
	copied.AllowedURIs = append([]string(nil), e.AllowedURIs...)

	p.options.External = &copied

	var err error

	p.baseURI, err = uriref.Base(copied.BaseURI)
	if err != nil {
		return fmt.Errorf("%w: external BaseURI: %w", ErrPolicy, err)
	}

	if len(copied.BaseURI) > 8192 || (p.baseURI != nil && p.baseURI.User != nil) {
		return fmt.Errorf("%w: external BaseURI", ErrPolicy)
	}

	for _, u := range copied.AllowedURIs {
		if !validExternalURI(u) {
			return fmt.Errorf("%w: external URI allowlist", ErrPolicy)
		}

		if _, exists := p.allow[u]; exists {
			return fmt.Errorf("%w: external URI allowlist", ErrPolicy)
		}

		p.allow[u] = struct{}{}
	}

	return nil
}

func (p *parser) resourceURI(s *scope, n *tree.Node, uri string) (string, error) {
	if len(uri) > 8192 {
		return "", ErrLimit
	}

	if !externalURI(uri) {
		return uri, nil
	}

	resolved, err := uriref.Resolve(uri, p.baseURI, s.resource, n)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInput, err)
	}

	if !validExternalURI(resolved) {
		return "", fmt.Errorf("%w: resolved external URI not allowed", ErrPolicy)
	}

	if _, allowed := p.allow[resolved]; !allowed {
		return "", fmt.Errorf("%w: resolved external URI not allowed", ErrPolicy)
	}

	return resolved, nil
}

func (p *parser) keyInfoReferenceURI(s *scope, n *tree.Node) (string, error) {
	children, err := structure(n, Namespace11, nameKeyInfoReference, "Id", "URI")
	if err != nil {
		return "", err
	}

	uri, present := attr(n, "URI")
	if len(children) != 0 || !present {
		return "", fmt.Errorf("%w: KeyInfoReference URI/structure", ErrInput)
	}

	return p.resourceURI(s, n, uri)
}

func (p *parser) consumeResource(uri string, consume func(io.Reader) error) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}

	if _, exists := p.allow[uri]; !exists {
		return fmt.Errorf("%w: external URI not allowed", ErrPolicy)
	}

	if p.externalReads >= p.limits.MaxExternalResources {
		return ErrLimit
	}

	p.externalReads++

	reader, err := p.options.External.Resolver.Resolve(p.ctx, uri)
	if err != nil {
		if !nilcheck.IsNil(reader) {
			err = errors.Join(err, reader.Close())
		}

		return fmt.Errorf("%w: %w", ErrResource, err)
	}

	if nilcheck.IsNil(reader) {
		return fmt.Errorf("%w: nil reader", ErrResource)
	}

	remaining := p.limits.MaxExternalBytes - p.externalBytes

	maximum := min(p.limits.MaxBlobBytes*2, remaining)
	if p.options.RetrievalProcessing != nil {
		maximum = min(maximum, p.options.RetrievalProcessing.MaxInputBytes)
	}

	source := &streamio.Reader{Context: p.ctx, Source: reader, Limit: int64(maximum), LimitError: ErrLimit}
	readErr := consume(source)

	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr, p.ctx.Err()); err != nil {
		return fmt.Errorf("%w: %w", ErrResource, err)
	}

	p.externalBytes += int(source.ReadBytes)
	p.result.external = append(p.result.external, uri)

	return nil
}

func (p *parser) readCertificate(uri string, decode bool) ([]byte, error) {
	if cached, ok := p.resources[uri]; ok {
		if cached.base64 != decode {
			return nil, fmt.Errorf("%w: conflicting resource representations", ErrInput)
		}

		return cached.data, nil
	}

	if _, ok := p.parsedResources[uri]; ok {
		return nil, fmt.Errorf("%w: XML resource used as certificate octets", ErrInput)
	}

	var output []byte

	maximum := min(p.limits.MaxBlobBytes, p.limits.MaxTotalBytes-p.total)
	if maximum < 2 {
		return nil, ErrLimit
	}

	err := p.consumeResource(uri, func(src io.Reader) error {
		if decode {
			src = streamio.NewBase64Decoder(base64.StdEncoding.Strict(), &streamio.XMLWhitespaceReader{Source: src})
		}

		value, err := der.ReadSequence(p.ctx, src, maximum)
		if err != nil {
			if errors.Is(err, der.ErrLimit) {
				return errors.Join(ErrLimit, err)
			}

			return errors.Join(ErrInput, err)
		}

		output = value.FullBytes

		return nil
	})
	if err != nil {
		return nil, err
	}

	p.resources[uri] = resourceBlob{data: output, base64: decode}

	return output, nil
}

func (p *parser) certificateTransforms() reference.Options {
	return reference.Options{AllowedTransforms: []string{reference.Base64}, MaxTransforms: 1, MaxInputBytes: p.limits.MaxBlobBytes * 2, MaxOutputBytes: p.limits.MaxBlobBytes, MaxProducedBytes: p.limits.MaxBlobBytes, MaxNodeVisits: p.limits.MaxElements * 8}
}

func (p *parser) resolveXML(s *scope, uri string) (*tree.Node, *scope, error) {
	if len(uri) > 8192 {
		return nil, nil, ErrLimit
	}

	if !externalURI(uri) {
		target, whole, err := s.resolver.Target(p.ctx, uri)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInput, err)
		}

		if whole {
			return tree.Root(s.doc), s, nil
		}

		_, n := tree.Unwrap(target)

		return n, s, nil
	}

	if cached, ok := p.parsedResources[uri]; ok {
		return tree.Root(cached.doc), cached, nil
	}

	if p.options.RetrievalProcessing != nil {
		data, err := p.readRawResource(uri)
		if err != nil {
			return nil, nil, err
		}

		next, err := p.retrievalScope(data, uri)
		if err != nil {
			return nil, nil, err
		}

		p.parsedResources[uri] = next

		return tree.Root(next.doc), next, nil
	}

	if _, ok := p.resources[uri]; ok {
		return nil, nil, fmt.Errorf("%w: certificate resource used as XML", ErrInput)
	}

	limits := document.DefaultLimits()
	limits.MaxBytes = min(limits.MaxBytes, p.limits.MaxBlobBytes*2)
	limits.MaxNodes = min(limits.MaxNodes, p.limits.MaxElements*8)
	limits.MaxDepth = min(limits.MaxDepth, 64)

	var d *document.Document

	err := p.consumeResource(uri, func(src io.Reader) error {
		var err error

		d, err = document.ParseReader(p.ctx, src, limits)

		return err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: remote XML: %w", ErrInput, err)
	}

	next, err := p.newScope(d, uri)
	if err != nil {
		return nil, nil, err
	}

	p.parsedResources[uri] = next

	return tree.Root(d), next, nil
}

func (p *parser) retrieve(s *scope, n *tree.Node, depth int) error {
	if depth >= p.limits.MaxDepth {
		return ErrLimit
	}

	plan, err := p.prepareRetrieval(s, n)
	if err != nil {
		return err
	}

	if p.options.RetrievalProcessing != nil && (len(plan.transforms) != 0 || plan.typ == RawX509Certificate) {
		return p.processRetrieval(s, n, depth, plan)
	}

	if plan.typ == RawX509Certificate {
		return p.retrieveRawCertificate(s, n, plan.uri, depth, plan.base64)
	}

	target, scope, err := p.resolveXML(s, plan.uri)
	if err != nil {
		return err
	}

	return p.acceptRetrievalTarget(target, scope, plan.typ, depth)
}

func (p *parser) acceptRetrievalTarget(target *tree.Node, scope *scope, typ string, depth int) error {
	if typ != "" && typ != target.Name.Space+target.Name.Local {
		return fmt.Errorf("%w: RetrievalMethod Type does not match target", ErrInput)
	}

	if is(target, Namespace, lexicon.DSigElementKeyInfo) {
		return p.keyInfo(scope, target, depth+1)
	}

	if is(target, Namespace, nameRSAKeyValue) || is(target, Namespace, nameDSAKeyValue) || is(target, Namespace11, nameECKeyValue) {
		leave, err := p.enter(scope, target, depth+1)
		if err != nil {
			return err
		}
		defer leave()

		return p.bareKey(scope, target)
	}

	return p.item(scope, target, depth+1)
}

func (p *parser) retrieveRawCertificate(s *scope, n *tree.Node, uri string, depth int, base64Transform bool) error {
	var err error

	if depth >= p.limits.MaxDepth {
		return ErrLimit
	}

	var raw []byte

	if externalURI(uri) {
		raw, err = p.readCertificate(uri, base64Transform)
		if err != nil {
			return err
		}
	} else {
		if !base64Transform {
			return fmt.Errorf("%w: a raw certificate requires octets or Base64", ErrInput)
		}

		resolved, err := s.resolver.Resolve(p.ctx, uri)
		if err != nil {
			return err
		}

		var output bytes.Buffer
		if _, err := reference.Write(p.ctx, &output, resolved.Data(), []reference.Transform{{Algorithm: reference.Base64}}, p.certificateTransforms()); err != nil {
			return fmt.Errorf("%w: %w", ErrInput, err)
		}

		raw = output.Bytes()
	}

	if err := p.charge(len(raw)); err != nil {
		return err
	}
	// The source of a raw resource is the RetrievalMethod in the referring doc.
	origin := *s
	if externalURI(uri) {
		origin.resource = uri
	}

	return p.certificate(&origin, n, raw)
}

func validExternalURI(uri string) bool {
	if len(uri) > 8192 || uriref.Validate(uri) != nil {
		return false
	}

	u, e := url.Parse(uri)

	return e == nil && u.IsAbs() && u.User == nil
}

func validKeyURI(uri string) bool {
	if len(uri) > 8192 || uriref.Validate(uri) != nil {
		return false
	}

	u, err := url.Parse(uri)

	return err == nil && u.User == nil
}

func retrievalTransform(c []*tree.Node, typ string) (bool, error) {
	base64Transform := false

	if len(c) > 0 {
		if len(c) != 1 {
			return false, ErrInput
		}

		tc, err := structure(c[0], Namespace, lexicon.DSigElementTransforms)
		if err != nil {
			return false, err
		}

		if len(tc) != 1 {
			return false, fmt.Errorf("%w: RetrievalMethod transform chain", ErrUnsupported)
		}

		body, err := structure(tc[0], Namespace, lexicon.DSigElementTransform, "Algorithm")
		if err != nil {
			return false, err
		}

		a, _ := attr(tc[0], "Algorithm")
		if len(body) != 0 || a != reference.Base64 || typ != RawX509Certificate {
			return false, fmt.Errorf("%w: only Base64 rawX509Certificate retrieval supported", ErrUnsupported)
		}

		base64Transform = true
	}

	return base64Transform, nil
}

func externalURI(uri string) bool { return uri != "" && !strings.HasPrefix(uri, "#") }
