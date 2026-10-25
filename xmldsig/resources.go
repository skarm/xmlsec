package xmldsig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/uriref"
	"github.com/skarm/xmlsec/reference"
)

// ExternalReferences enables explicitly allowlisted external octet streams in
// the general Signature API. It does not enable network access. URI spelling is
// exact unless BaseURI explicitly enables relative URI resolution. KeyInfo
// discovery never invokes this Resolver. Explicit external Manifest traversal
// shares this allowlist and its limits.
// AllowedURIs is an allowlist, not an exact set requirement (use ExpectedURIs for
// the direct SignedInfo references). All reader and resolver methods must honor
// context themselves if they can block.
type ExternalReferences struct {
	// Resolver is the required trusted application adapter for authorized resources.
	// It receives the complete authorized URI, including any fragment, and must
	// return the identified subresource as octets. Fragment interpretation and
	// standalone XML serialization belong to this adapter, not to a hidden XML
	// selector or an HTTP request with its fragment silently discarded.
	Resolver Resolver
	// AllowedURIs is a required allowlist of exact URI strings. It does not
	// require every URI to be referenced; use SignatureOptions.ExpectedURIs for that.
	AllowedURIs []string
	// BaseURI opts into RFC 3986 relative URI resolution. It must be an absolute,
	// hierarchical, fragment-free URI identifying the signature document. Nested
	// external Manifests instead use their complete resolved resource URI as the
	// retrieval base. Inherited xml:base on permitted XML containers is applied
	// before checking the exact resolved URI against AllowedURIs. Empty keeps the
	// existing literal-URI contract. Empty and #fragment references always select
	// the containing document, independently of BaseURI and xml:base.
	BaseURI string
	Limits  ResourceLimits
	replay  *resourceSession
}

type resourceSession struct {
	source             Resolver
	allowed            map[string]bool
	cache              map[[32]byte]ReferenceResult
	fingerprints       map[string][]byte
	limits             ResourceLimits
	remaining          int
	captureManifests   bool
	captureTransformed bool
	baseURI            *url.URL
}

func newResourceSession(opt *ExternalReferences) (*resourceSession, error) {
	if opt == nil {
		return nil, nil
	}

	if nilcheck.IsNil(opt.Resolver) || len(opt.AllowedURIs) == 0 || len(opt.AllowedURIs) > 1024 {
		return nil, fmt.Errorf("%w: external resolver and explicit bounded URI allowlist required", ErrPolicy)
	}

	limits, err := normalizeResourceLimits(opt.Limits)
	if err != nil {
		return nil, err
	}

	s := &resourceSession{source: opt.Resolver, allowed: make(map[string]bool), cache: make(map[[32]byte]ReferenceResult), fingerprints: make(map[string][]byte), limits: limits, remaining: limits.MaxTotalResourceBytes}

	s.baseURI, err = resourceBaseURI(opt.BaseURI)
	if err != nil {
		return nil, err
	}

	for _, uri := range opt.AllowedURIs {
		if err := validExternalReferenceURI(uri); err != nil {
			return nil, err
		}

		if s.baseURI != nil {
			parsed, _ := url.Parse(uri) // validated above
			if !parsed.IsAbs() {
				return nil, fmt.Errorf("%w: resolved absolute URI allowlist required with BaseURI", ErrPolicy)
			}
		}

		if s.allowed[uri] {
			return nil, fmt.Errorf("%w: duplicate external URI allowlist entry", ErrPolicy)
		}

		s.allowed[uri] = true
	}

	if opt.replay != nil {
		maps.Copy(s.fingerprints, opt.replay.fingerprints)

		for key, result := range opt.replay.cache {
			if cacheableExternalTransforms(result.transforms) {
				s.cache[key] = result
			}
		}
	}

	return s, nil
}

func resourceBaseURI(value string) (*url.URL, error) {
	base, err := uriref.Base(value)
	if err != nil {
		return nil, fmt.Errorf("%w: BaseURI: %w", ErrPolicy, err)
	}

	return base, nil
}

// Program fingerprints exclude runtime expression handles. Even identical
// approved programs can make different execution decisions for two References;
// their results cannot be shared across references or signing/self-check passes.
func cacheableExternalTransforms(transforms []reference.Transform) bool {
	for _, tr := range transforms {
		if reference.IsExtension(tr.Algorithm) {
			return false
		}
	}

	return true
}

func (s *resourceSession) permits(uri string) error {
	if s == nil || !s.allowed[uri] {
		return fmt.Errorf("%w: external URI not allowed: %q", ErrPolicy, uri)
	}

	return validExternalReferenceURI(uri)
}

// replayOptions reuses authenticated processing evidence for the signing
// self-check. Only built-in chains independent of the signature are replayed
// from evidence; application extensions execute again with the final context.
func (s *resourceSession) replayOptions() *ExternalReferences {
	allowed := make([]string, 0, len(s.allowed))
	for uri := range s.allowed {
		allowed = append(allowed, uri)
	}

	opt := &ExternalReferences{AllowedURIs: allowed, Limits: s.limits, Resolver: s.source, replay: s}
	if s.baseURI != nil {
		opt.BaseURI = s.baseURI.String()
	}

	return opt
}

// referenceURI does not authorize or fetch anything. Same-document references
// are handled by taskTarget before this method, including under xml:base.
func (s *resourceSession) referenceURI(scope *manifestScope, ref coreReference) (string, error) {
	if err := validExternalReferenceURI(ref.uri); err != nil {
		return "", err
	}

	var base *url.URL
	if s != nil {
		base = s.baseURI
	}

	resolved, err := uriref.Resolve(ref.uri, base, scope.uri, ref.digestNode.Parent)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrReference, err)
	}

	return resolved, nil
}

func (s *resourceSession) process(ctx context.Context, b *coreBudget, ref coreReference, opt reference.Options) (ReferenceResult, error) {
	if err := s.permits(ref.uri); err != nil {
		return ReferenceResult{}, err
	}

	key, err := referenceCacheKey(ctx, ref)
	if err != nil {
		return ReferenceResult{}, err
	}

	cacheable := cacheableExternalTransforms(ref.transforms)
	if cached, ok := s.cache[key]; ok && cacheable {
		if cached.processed.ProducedBytes() > b.bytes || cached.processed.NodeVisits() > b.visits {
			return ReferenceResult{}, ErrPolicy
		}

		b.bytes -= cached.processed.ProducedBytes()
		b.visits -= cached.processed.NodeVisits()

		return cached, nil
	}

	h, err := hashForDigest(ref.method)
	if err != nil {
		return ReferenceResult{}, err
	}

	digest := h.New()
	source := &referenceSource{resolver: s.source, uri: ref.uri, limits: s.limits, captureManifest: s.captureManifests && ref.typeURI == ManifestType && externalManifestProvenance(ref.transforms)}

	opt.MaxNodeVisits = b.visits
	if b.visits <= 0 {
		return ReferenceResult{}, ErrPolicy
	}

	writer, captured := manifestOutputWriter(digest, s.captureTransformed && ref.typeURI == ManifestType && !externalManifestProvenance(ref.transforms))

	report, err := source.write(ctx, writer, ref.transforms, opt, &b.bytes, &s.remaining)
	if err != nil {
		return ReferenceResult{}, err
	}

	b.visits -= report.NodeVisits()

	result := ReferenceResult{uri: ref.uri, typeURI: ref.typeURI, digestMethod: ref.method, transforms: ref.transforms, processed: report, external: source, processing: opt, digest: digest.Sum(nil)}
	if captured != nil {
		result.manifestInput = captured.Bytes()
	}

	if previous := s.fingerprints[ref.uri]; previous != nil && !bytes.Equal(previous, source.rawDigest) {
		return ReferenceResult{}, ErrDigest
	}

	s.fingerprints[ref.uri] = source.rawDigest
	if cacheable {
		s.cache[key] = result
	}

	return result, nil
}

// Keep only a fixed-size cache key, without Base64/JSON copies of stylesheets.
// Length-delimited source bytes preserve exact transform identity; application
// allowlist fingerprints remain the separate public ProgramFingerprint format.
func referenceCacheKey(ctx context.Context, ref coreReference) ([32]byte, error) {
	metadata := append([]reference.Transform(nil), ref.transforms...)
	for i := range metadata {
		metadata[i].Stylesheet = nil
	}

	encoded, err := json.Marshal(struct {
		URI, Method, Type string
		Transforms        []reference.Transform
	}{ref.uri, ref.method, ref.typeURI, metadata})
	if err != nil {
		return [32]byte{}, err
	}

	hash := sha256.New()
	_, _ = hash.Write(encoded)

	var length [8]byte
	for _, tr := range ref.transforms {
		binary.BigEndian.PutUint64(length[:], uint64(len(tr.Stylesheet)))
		_, _ = hash.Write(length[:])

		for data := tr.Stylesheet; len(data) != 0; {
			if err := ctx.Err(); err != nil {
				return [32]byte{}, err
			}

			size := min(len(data), 32<<10)
			_, _ = hash.Write(data[:size])
			data = data[size:]
		}
	}

	var result [32]byte
	hash.Sum(result[:0])

	return result, ctx.Err()
}

func externalURI(uri string) bool { return uri != "" && !strings.HasPrefix(uri, "#") }

// processCoreTask is shared by generation and verification. Node identity is
// preserved only for the supported same-document provenance-preserving chain.
func processCoreTask(ctx context.Context, doc *document.Document, p *corePlan, b *coreBudget, task *coreTask) (*reference.Report, ReferenceResult, error) {
	ref := task.ref
	if task.external {
		ref.uri = task.resourceURI
		result, err := p.external.process(ctx, b, ref, p.processing)
		result.uri = task.ref.uri // expose signed spelling separately from resolver identity

		return result.processed, result, err
	}

	rr := ReferenceResult{uri: ref.uri, typeURI: ref.typeURI, digestMethod: ref.method, transforms: ref.transforms}

	var (
		data     reference.Data
		resolved reference.Resolved
	)

	var err error

	resolver := p.resolver

	if task.scope != nil {
		doc = task.scope.doc
		resolver = task.scope.resolver
	}

	resolved, err = resolver.Resolve(ctx, ref.uri)
	if err != nil {
		return nil, rr, err
	}

	data = resolved.Data()
	rr.target = resolved.Target()

	h, err := hashForDigest(ref.method)
	if err != nil {
		return nil, rr, err
	}

	digest := h.New()

	writer, captured := manifestOutputWriter(digest, p.graph.policy.AllowTransformed && transformedManifestEdge(task))

	out, err := b.write(ctx, writer, data, ref.transforms, p.processing)
	if err != nil {
		return nil, rr, err
	}

	rr.processed, rr.resolver, rr.processing, rr.digest = out, resolver, p.processing, digest.Sum(nil)
	if captured != nil {
		rr.manifestInput = captured.Bytes()
	}

	rr.coverageDoc, rr.coverageRoot, rr.coverageExclude = coreCoverage(doc, p.sig, resolved, out)

	return out, rr, nil
}

func taskTarget(ctx context.Context, scope *manifestScope, p *corePlan, r coreReference) (*tree.Node, bool, string, error) {
	if externalURI(r.uri) {
		uri, err := p.external.referenceURI(scope, r)
		if err != nil {
			return nil, true, "", err
		}

		if err := p.external.permits(uri); err != nil {
			return nil, true, uri, err
		}

		if err := validateDetachedTransforms(r.transforms, p.processing); err != nil {
			return nil, true, uri, err
		}

		return nil, true, uri, nil
	}

	e, whole, err := scope.resolver.Target(ctx, r.uri)
	if err != nil {
		return nil, false, "", err
	}

	_, n := tree.Unwrap(e)
	if whole {
		n = tree.Root(scope.doc)
	}

	return n, false, "", nil
}
