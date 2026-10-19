package xmldsig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// ExternalReferences enables explicitly allowlisted external octet streams in
// the general Signature API. It does not enable network access or XML base URI
// resolution. URI spelling is exact; relative URI interpretation is the caller's
// responsibility. KeyInfo and remote Manifest discovery never invoke Resolver.
// AllowedURIs is an allowlist, not an exact set requirement (use ExpectedURIs for
// the direct SignedInfo references). All reader and resolver methods must honor
// context themselves if they can block.
type ExternalReferences struct {
	// Resolver is the required trusted application adapter for authorized resources.
	Resolver Resolver
	// AllowedURIs is a required allowlist of exact URI strings. It does not
	// require every URI to be referenced; use SignatureOptions.ExpectedURIs for that.
	AllowedURIs []string
	Limits      ResourceLimits
	replay      *resourceSession
}

type resourceSession struct {
	source       Resolver
	allowed      map[string]bool
	cache        map[[32]byte]ReferenceResult
	fingerprints map[string][]byte
	limits       ResourceLimits
	remaining    int
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
	for _, uri := range opt.AllowedURIs {
		if err := validExternalURI(uri); err != nil {
			return nil, err
		}

		if s.allowed[uri] {
			return nil, fmt.Errorf("%w: duplicate external URI allowlist entry", ErrPolicy)
		}

		s.allowed[uri] = true
	}

	if opt.replay != nil {
		maps.Copy(s.fingerprints, opt.replay.fingerprints)

		for key, result := range opt.replay.cache {
			builtin := true

			for _, tr := range result.transforms {
				if reference.IsExtension(tr.Algorithm) {
					builtin = false
					break
				}
			}

			if builtin {
				s.cache[key] = result
			}
		}
	}

	return s, nil
}

func (s *resourceSession) permits(uri string) error {
	if s == nil || !s.allowed[uri] {
		return fmt.Errorf("%w: external URI not allowed: %q", ErrPolicy, uri)
	}

	return validExternalURI(uri)
}

// replayOptions reuses authenticated processing evidence for the signing
// self-check. Only built-in chains independent of the signature are replayed
// from evidence; application extensions execute again with the final context.
func (s *resourceSession) replayOptions() *ExternalReferences {
	allowed := make([]string, 0, len(s.allowed))
	for uri := range s.allowed {
		allowed = append(allowed, uri)
	}

	return &ExternalReferences{AllowedURIs: allowed, Limits: s.limits, Resolver: s.source, replay: s}
}

func (s *resourceSession) process(ctx context.Context, b *coreBudget, ref coreReference, opt reference.Options) (ReferenceResult, error) {
	if err := s.permits(ref.uri); err != nil {
		return ReferenceResult{}, err
	}

	key, err := referenceCacheKey(ctx, ref)
	if err != nil {
		return ReferenceResult{}, err
	}

	if cached, ok := s.cache[key]; ok {
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
	source := &referenceSource{resolver: s.source, uri: ref.uri, limits: s.limits}

	opt.MaxNodeVisits = b.visits
	if b.visits <= 0 {
		return ReferenceResult{}, ErrPolicy
	}

	report, err := source.write(ctx, digest, ref.transforms, opt, &b.bytes, &s.remaining)
	if err != nil {
		return ReferenceResult{}, err
	}

	b.visits -= report.NodeVisits()

	result := ReferenceResult{uri: ref.uri, typeURI: ref.typeURI, digestMethod: ref.method, transforms: ref.transforms, processed: report, external: source, processing: opt, digest: digest.Sum(nil)}
	if previous := s.fingerprints[ref.uri]; previous != nil && !bytes.Equal(previous, source.rawDigest) {
		return ReferenceResult{}, ErrDigest
	}

	s.fingerprints[ref.uri] = source.rawDigest
	s.cache[key] = result

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
		result, err := p.external.process(ctx, b, ref, p.processing)
		return result.processed, result, err
	}

	rr := ReferenceResult{uri: ref.uri, typeURI: ref.typeURI, digestMethod: ref.method, transforms: ref.transforms}

	var (
		data     reference.Data
		resolved reference.Resolved
	)

	var err error

	resolved, err = p.resolver.Resolve(ctx, ref.uri)
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

	out, err := b.write(ctx, digest, data, ref.transforms, p.processing)
	if err != nil {
		return nil, rr, err
	}

	rr.processed, rr.resolver, rr.processing, rr.digest = out, p.resolver, p.processing, digest.Sum(nil)
	rr.coverageDoc, rr.coverageRoot, rr.coverageExclude = coreCoverage(doc, p.sig, resolved, out)

	return out, rr, nil
}

func taskTarget(ctx context.Context, doc *document.Document, p *corePlan, r coreReference) (*tree.Node, bool, error) {
	if externalURI(r.uri) {
		if err := p.external.permits(r.uri); err != nil {
			return nil, true, err
		}

		if err := validateDetachedTransforms(r.transforms, p.processing); err != nil {
			return nil, true, err
		}

		return nil, true, nil
	}

	e, whole, err := p.resolver.Target(ctx, r.uri)
	if err != nil {
		return nil, false, err
	}

	_, n := tree.Unwrap(e)
	if whole {
		n = tree.Root(doc)
	}

	return n, false, nil
}
