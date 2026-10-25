package xades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/historical"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/pki"
	referencepkg "github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	historicalSignedInfoElement     = "SignedInfo"
	historicalSignatureValueElement = "SignatureValue"
	historicalDataObject            = "data"
	historicalKeyInfoElement        = "KeyInfo"
)

type historicalObjects struct {
	ctx                context.Context
	maximum, remaining int
	objects            []historical.Object
	index              map[[32]byte]int
	references         [][32]byte
	signedInfo         [32]byte
	signedInfoOptions  c14n.Options
}

func (b *historicalObjects) add(raw []byte, kind string, contains [][32]byte) ([32]byte, error) {
	key := sha256.Sum256(raw)
	if previous, ok := b.index[key]; ok {
		object := &b.objects[previous]
		if !bytes.Equal(object.Bytes, raw) || object.Kind != kind && object.Kind != historicalDataObject && kind != historicalDataObject {
			return key, historical.ErrInput
		}

		if object.Kind == historicalDataObject {
			object.Kind = kind
		}

		for _, child := range contains {
			if !slices.Contains(object.Contains, child) {
				object.Contains = append(object.Contains, child)
			}
		}

		return key, nil
	}

	if len(raw) == 0 && kind != historicalDataObject || len(raw) > b.remaining || len(b.objects) >= b.maximum {
		return key, historical.ErrLimit
	}

	b.remaining -= len(raw)
	b.index[key] = len(b.objects)
	b.objects = append(b.objects, historical.Object{Bytes: raw, Kind: kind, Contains: slices.Clone(contains)})

	return key, b.ctx.Err()
}

func (b *historicalObjects) write(write func(io.Writer) error) ([]byte, error) {
	var output bytes.Buffer

	writer := &streamio.Writer{Context: b.ctx, Target: &output, Limit: int64(b.remaining), LimitError: historical.ErrLimit}
	if err := write(writer); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func (b *historicalObjects) canonical(e document.Element, options c14n.Options) ([32]byte, []byte, error) {
	raw, err := b.write(func(dst io.Writer) error { return c14n.WriteElement(b.ctx, dst, e, options) })
	if err != nil {
		return [32]byte{}, nil, err
	}

	contained, err := b.contained(raw)
	if err != nil {
		return [32]byte{}, nil, err
	}

	key, err := b.add(raw, historicalDataObject, contained)

	return key, raw, err
}

// contained parses the actual canonical/processed octets, rather than assuming
// that transforms retained the original XML's embedded certificate/token bytes.
func (b *historicalObjects) contained(raw []byte) ([][32]byte, error) {
	if len(raw) == 0 || raw[0] != '<' {
		return nil, nil
	}

	doc, err := document.Parse(b.ctx, raw, document.DefaultLimits())
	if err != nil {
		if b.ctx.Err() != nil {
			return nil, b.ctx.Err()
		}

		return nil, nil // Sparse C14N need not be a well-formed XML document.
	}

	var out [][32]byte

	stack := []document.Element{doc.Root()}

	for len(stack) != 0 {
		if err := b.ctx.Err(); err != nil {
			return nil, err
		}

		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		stack = append(stack, node.Children()...)

		key, valid, err := b.containedNode(node)
		if err != nil {
			return nil, err
		}

		if valid {
			out = append(out, key)
		}
	}

	return out, nil
}

func historicalContainedKind(node document.Element) string {
	switch node.Name() {
	case ds(historicalSignatureValueElement):
		return "signature"
	case ds("X509Certificate"), name("EncapsulatedX509Certificate"):
		return "certificate"
	case name("EncapsulatedCRLValue"):
		return "crl"
	case name("EncapsulatedOCSPValue"):
		return "ocsp"
	case name("EncapsulatedTimeStamp"):
		return "timestamp"
	}

	return ""
}

func (b *historicalObjects) containedNode(node document.Element) ([32]byte, bool, error) {
	kind := historicalContainedKind(node)
	if kind == "" {
		return [32]byte{}, false, nil
	}

	value, err := decodeElementBase64(b.ctx, node, b.remaining*2, b.remaining)
	if err != nil {
		// Arbitrary signed data may contain lookalike invalid values.
		return [32]byte{}, false, b.ctx.Err()
	}

	certificates, valid, err := b.containedCertificates(kind, value)
	if err != nil || !valid {
		return [32]byte{}, false, err
	}

	var children [][32]byte

	for _, raw := range certificates {
		key, err := b.add(raw, "certificate", nil)
		if err != nil {
			return [32]byte{}, false, err
		}

		children = append(children, key)
	}

	key, err := b.add(value, kind, children)

	return key, err == nil, err
}

func (b *historicalObjects) containedCertificates(kind string, value []byte) ([][]byte, bool, error) {
	switch kind {
	case "timestamp":
		token, err := timestamp.ParseToken(b.ctx, value)
		if err == nil {
			return token.Certificates(), true, nil
		}

		return nil, false, nil
	case "certificate":
		_, err := x509cert.ParseWithMaxBytes(value, len(value))

		return nil, err == nil, nil
	case "crl":
		return nil, validateMaterialObject(1, value) == nil, nil
	case "ocsp":
		if validateEmbeddedOCSP(value) == nil {
			certificates, err := pki.InspectOCSPCertificates(b.ctx, value)
			if err != nil {
				return nil, false, b.ctx.Err()
			}

			return certificates, true, nil
		}

		return nil, false, nil
	default:
		return nil, true, nil
	}
}

type historicalInputBuilder struct {
	ctx      context.Context
	baseline *BaselineResult
	options  BaselineVerifyOptions
	config   historical.Config
	result   historical.Input
	evidence ValidationEvidence
	objects  *historicalObjects
	sig      document.Element
	value    document.Element
	unsigned document.Element
	entries  []document.Element
}

func historicalInput(ctx context.Context, baseline *BaselineResult, baselineOptions BaselineVerifyOptions, config historical.Config, input ValidationEvidence) (historical.Input, ValidationEvidence, error) {
	if baseline == nil || baseline.Basic() == nil {
		return historical.Input{}, input, ErrProfile
	}

	input.Signer = historicalEvidenceSlices(input.Signer)
	input.TSA = historicalEvidenceSlices(input.TSA)

	builder := historicalInputBuilder{
		ctx: ctx, baseline: baseline, options: baselineOptions, config: config, evidence: input,
		objects: &historicalObjects{ctx: ctx, maximum: config.MaxObjects, remaining: config.MaxBytes, index: make(map[[32]byte]int)},
		sig:     baseline.Basic().Signature().Signature(),
	}
	if err := builder.initializeSignature(); err != nil {
		return builder.result, builder.evidence, err
	}

	if err := builder.recordReferences(); err != nil {
		return builder.result, builder.evidence, err
	}

	if err := builder.recordSignedInfo(); err != nil {
		return builder.result, builder.evidence, err
	}

	if err := builder.recordPolicy(); err != nil {
		return builder.result, builder.evidence, err
	}

	if err := builder.prepareUnsigned(); err != nil {
		return builder.result, builder.evidence, err
	}

	if err := builder.recordUnsignedMaterial(); err != nil {
		return builder.result, builder.evidence, err
	}

	if err := builder.recordCertificateReferences(); err != nil {
		return builder.result, builder.evidence, err
	}

	if len(baseline.DataTimestamps()) > config.MaxTimestamps {
		return builder.result, builder.evidence, historical.ErrLimit
	}

	if err := appendHistoricalDataTimestamps(ctx, baseline, builder.objects, &builder.result); err != nil {
		return builder.result, builder.evidence, err
	}

	if err := builder.recordUnsignedTimestamps(); err != nil {
		return builder.result, builder.evidence, err
	}

	builder.result.Objects = builder.objects.objects

	return builder.result, builder.evidence, nil
}

func (b *historicalInputBuilder) initializeSignature() error {
	value, err := childNamed(b.sig, ds(historicalSignatureValueElement))
	if err != nil {
		return err
	}

	b.value = value

	signatureValue, err := decodeElementBase64(b.ctx, value, 1<<20, 1<<20)
	if err != nil {
		return err
	}

	b.result.Signature, err = b.objects.add(signatureValue, "signature", nil)
	if err != nil {
		return err
	}

	basic, baseline := b.baseline.Basic(), b.baseline
	b.result.Certificate = basic.CertificateDER()
	b.result.ClaimedTime = basic.ClaimedSigningTime()
	b.result.ClaimedTimeAfter = func(threshold time.Time) (bool, error) {
		comparison, err := baseline.CompareSigningTime(threshold)

		return comparison > 0, err
	}

	b.result.SignatureMethod, b.result.Hashes, err = historicalSignatureMethod(basic)
	if err != nil {
		return err
	}

	if parameters := basic.Signature().Parameters().PSS; parameters != nil {
		b.result.Uses = append(b.result.Uses, historical.MaterialUse{Object: b.result.Signature, Hash: parameters.MGFHash})
		if !slices.Contains(b.result.Hashes, parameters.MGFHash) {
			b.result.Hashes = append(b.result.Hashes, parameters.MGFHash)
		}
	}

	return nil
}

// Record exact material/algorithm pairs even without an archive timestamp.
// SignatureValue proof cannot stand in for proof of a referenced data object.
func (b *historicalInputBuilder) recordReferences() error {
	for _, ref := range historicalAllReferences(b.baseline.Basic()) {
		raw, err := b.objects.write(func(dst io.Writer) error {
			_, err := ref.WriteDigestInput(b.ctx, dst)

			return err
		})
		if err != nil {
			return err
		}

		children, err := b.objects.contained(raw)
		if err != nil {
			return err
		}

		key, err := b.objects.add(raw, historicalDataObject, children)
		if err != nil {
			return err
		}

		hash, err := historicalHash(ref.DigestMethod())
		if err != nil {
			return err
		}

		b.result.Uses = append(b.result.Uses, historical.MaterialUse{Object: key, Hash: hash})
		b.objects.references = append(b.objects.references, key)
	}

	return nil
}

func (b *historicalInputBuilder) recordSignedInfo() error {
	if b.baseline.Basic().Signature().SignatureMethod() == xmldsig.Ed25519 {
		return nil
	}

	si, err := childNamed(b.sig, ds(historicalSignedInfoElement))
	if err != nil {
		return err
	}

	options, err := historicalSignedInfoOptions(si, b.config.MaxBytes)
	if err != nil {
		return err
	}

	key, _, err := b.objects.canonical(si, options)
	if err != nil {
		return err
	}

	b.result.Uses = append(b.result.Uses, historical.MaterialUse{Object: key, Hash: b.result.Hashes[0]})
	b.objects.signedInfo, b.objects.signedInfoOptions = key, options

	return nil
}

func (b *historicalInputBuilder) recordPolicy() error {
	policy := b.baseline.SignaturePolicy()
	if policy == nil || policy.Implied {
		return nil
	}

	key, err := b.objects.add(bytes.Clone(b.options.PolicyDocument), historicalDataObject, nil)
	if err != nil {
		return err
	}

	hash, err := historicalHash(policy.DigestMethod)
	if err != nil {
		return err
	}

	b.result.Hashes = append(b.result.Hashes, hash)
	b.result.Uses = append(b.result.Uses, historical.MaterialUse{Object: key, Hash: hash})

	return nil
}

func (b *historicalInputBuilder) prepareUnsigned() error {
	for _, child := range b.baseline.UnsignedProperties().Children() {
		if child.Name() == name("UnsignedSignatureProperties") {
			if b.unsigned.Valid() {
				return ErrProfile
			}

			b.unsigned = child
		}
	}

	b.entries = b.baseline.UnsignedSignatureProperties()
	if len(b.entries) > 140 {
		return historical.ErrLimit
	}

	return nil
}

// Material stays untrusted regardless of its XAdES container. Each PKI session
// still applies actual issuer, scope and path checks.
func (b *historicalInputBuilder) recordUnsignedMaterial() error {
	for _, entry := range b.entries {
		var material ValidationMaterial

		var err error

		switch entry.Name() {
		case name("CertificateValues"):
			material.Certificates, err = parseCertificateValues(b.ctx, entry)
		case name("RevocationValues"):
			material.CRLs, material.OCSPResponses, err = parseRevocationValues(b.ctx, entry)
		case name141("TimeStampValidationData"):
			material, err = parseTSVD(b.ctx, entry)
		case name("SignatureTimeStamp"), name141("ArchiveTimeStamp"):
			continue
		default:
			return fmt.Errorf("%w: unsupported historical unsigned property %s", ErrProfile, entry.Name().Local)
		}

		if err != nil {
			return err
		}

		if err := checkRawMaterial(b.ctx, material); err != nil {
			return err
		}

		for _, destination := range []*pki.Evidence{&b.evidence.Signer, &b.evidence.TSA} {
			destination.Intermediates = appendUnique(destination.Intermediates, material.Certificates...)
			destination.CRLs = appendUnique(destination.CRLs, material.CRLs...)
			destination.OCSPResponses = appendUnique(destination.OCSPResponses, material.OCSPResponses...)
		}
	}

	return nil
}

func (b *historicalInputBuilder) recordCertificateReferences() error {
	for _, reference := range b.baseline.CertificateReferences() {
		key, err := b.objects.add(reference.CertificateDER(), "certificate", nil)
		if err != nil {
			return err
		}

		hash, err := historicalHash(reference.DigestMethod())
		if err != nil {
			return err
		}

		b.result.Hashes = append(b.result.Hashes, hash)
		b.result.Uses = append(b.result.Uses, historical.MaterialUse{Object: key, Hash: hash})
	}

	return nil
}

func (b *historicalInputBuilder) recordUnsignedTimestamps() error {
	for _, entry := range b.entries {
		if entry.Name() != name("SignatureTimeStamp") && entry.Name() != name141("ArchiveTimeStamp") {
			continue
		}

		method, tokens, err := parseHistoricalTimeStamp(b.ctx, entry, b.config.MaxBytes)
		if err != nil {
			return err
		}

		for _, raw := range tokens {
			if err := b.recordTimestamp(entry, method, raw); err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *historicalInputBuilder) recordTimestamp(entry document.Element, method string, raw []byte) error {
	if len(b.result.Timestamps) >= b.config.MaxTimestamps {
		return historical.ErrLimit
	}

	token, err := timestamp.ParseToken(b.ctx, raw)
	if err != nil {
		return err
	}

	candidate := historical.Candidate{Token: token, Archive: entry.Name() == name141("ArchiveTimeStamp")}
	if candidate.Archive {
		candidate.Imprint, candidate.Covered, err = historicalArchiveInput(b.ctx, b.objects, b.baseline, b.unsigned, entry, method, token.UnverifiedInfo().Imprint().Hash)
	} else {
		candidate.Imprint, candidate.Covered, err = b.signatureTimestampInput(method, token.UnverifiedInfo().Imprint().Hash)
	}

	if err != nil {
		return err
	}

	b.result.Timestamps = append(b.result.Timestamps, candidate)

	return nil
}

func (b *historicalInputBuilder) signatureTimestampInput(method string, hash crypto.Hash) (timestamp.Imprint, [][32]byte, error) {
	key, canonical, err := b.objects.canonical(b.value, c14n.Options{Algorithm: method, MaxOutputBytes: b.config.MaxBytes})
	if err != nil {
		return timestamp.Imprint{}, nil, err
	}

	state := hash.New()
	_, _ = state.Write(canonical)

	return timestamp.Imprint{Hash: hash, Digest: state.Sum(nil)}, [][32]byte{key}, nil
}

func historicalSignedInfoOptions(element document.Element, maximum int) (c14n.Options, error) {
	cm, err := childNamed(element, ds("CanonicalizationMethod"))
	if err != nil {
		return c14n.Options{}, err
	}

	options := c14n.Options{Algorithm: localAttribute(cm, "Algorithm"), MaxOutputBytes: maximum}
	for _, parameter := range cm.Children() {
		if parameter.Name() != (document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}) {
			return options, ErrProfile
		}

		options.InclusivePrefixes = strings.Fields(localAttribute(parameter, "PrefixList"))
	}

	return options, nil
}

// A timestamped serialization also proves an exact deterministic encoding
// obtainable from those protected bytes alone. Ancestor context is never
// borrowed from the original XML when checking this relation.
func (b *historicalObjects) linkCanonicalEncoding(parent, original [32]byte, options c14n.Options) error {
	if parent == original {
		return nil
	}

	protected, ok := b.index[parent]
	if !ok {
		return historical.ErrInput
	}

	target, ok := b.index[original]
	if !ok {
		return historical.ErrInput
	}

	doc, err := document.Parse(b.ctx, b.objects[protected].Bytes, document.DefaultLimits())
	if err != nil {
		return b.ctx.Err()
	}

	var out bytes.Buffer

	writer := &streamio.Writer{Context: b.ctx, Target: &out, Limit: int64(len(b.objects[target].Bytes)) + 1, LimitError: historical.ErrLimit}
	if err := c14n.WriteElement(b.ctx, writer, doc.Root(), options); err != nil {
		return b.ctx.Err()
	}

	if bytes.Equal(out.Bytes(), b.objects[target].Bytes) && !slices.Contains(b.objects[protected].Contains, original) {
		b.objects[protected].Contains = append(b.objects[protected].Contains, original)
	}

	return nil
}

func historicalEvidenceSlices(input pki.Evidence) pki.Evidence {
	input.Intermediates = slices.Clone(input.Intermediates)
	input.CRLs = slices.Clone(input.CRLs)
	input.OCSPResponses = slices.Clone(input.OCSPResponses)

	return input
}

type historicalArchiveBuilder struct {
	ctx      context.Context
	objects  *historicalObjects
	baseline *BaselineResult
	method   string
	state    hash.Hash
	covered  [][32]byte
}

func historicalArchiveInput(ctx context.Context, objects *historicalObjects, baseline *BaselineResult, unsigned, before document.Element, method string, hash crypto.Hash) (timestamp.Imprint, [][32]byte, error) {
	if hash == 0 || !hash.Available() {
		return timestamp.Imprint{}, nil, ErrTimestamp
	}

	builder := historicalArchiveBuilder{ctx: ctx, objects: objects, baseline: baseline, method: method, state: hash.New()}
	if err := builder.references(); err != nil {
		return timestamp.Imprint{}, nil, err
	}

	if err := builder.signatureElements(); err != nil {
		return timestamp.Imprint{}, nil, err
	}

	if err := builder.unsignedProperties(unsigned, before); err != nil {
		return timestamp.Imprint{}, nil, err
	}

	if err := builder.otherObjects(); err != nil {
		return timestamp.Imprint{}, nil, err
	}

	return timestamp.Imprint{Hash: hash, Digest: builder.state.Sum(nil)}, builder.covered, nil
}

func (b *historicalArchiveBuilder) references() error {
	for index, reference := range b.baseline.Basic().Signature().References() {
		if err := b.reference(reference, index); err != nil {
			return err
		}
	}

	return nil
}

func (b *historicalArchiveBuilder) reference(reference xmldsig.ReferenceResult, index int) error {
	raw, err := b.objects.write(func(dst io.Writer) error {
		_, err := reference.WriteCanonicalizedInput(b.ctx, dst, referencepkg.Transform{Algorithm: b.method})

		return err
	})
	if err != nil {
		return err
	}

	children, err := b.objects.contained(raw)
	if err != nil {
		return err
	}

	key, err := b.objects.add(raw, historicalDataObject, children)
	if err != nil {
		return err
	}

	steps := reference.Steps()
	if len(steps) > 0 && steps[len(steps)-1].Implicit {
		if err := b.objects.linkCanonicalEncoding(key, b.objects.references[index], c14n.Options{Algorithm: c14n.Canonical10, MaxOutputBytes: b.objects.remaining}); err != nil {
			return err
		}
	}

	if reference.Target().Same(b.baseline.Basic().SignedProperties()) && reference.CoversElement(b.baseline.Basic().SignedProperties()) {
		if err := b.linkCertificateReferences(key); err != nil {
			return err
		}
	}

	_, _ = b.state.Write(raw)
	b.covered = append(b.covered, key)

	return nil
}

func (b *historicalArchiveBuilder) linkCertificateReferences(key [32]byte) error {
	for _, certificate := range b.baseline.CertificateReferences() {
		digest, err := historicalHash(certificate.DigestMethod())
		if err != nil {
			return err
		}

		target := sha256.Sum256(certificate.CertificateDER())
		object := &b.objects.objects[b.objects.index[key]]
		object.Refs = append(object.Refs, historical.HashReference{Hash: digest, Digest: certificate.Digest(), Target: target})
	}

	return nil
}

func (b *historicalArchiveBuilder) signatureElements() error {
	sig := b.baseline.Basic().Signature().Signature()
	for _, local := range []string{historicalSignedInfoElement, historicalSignatureValueElement, historicalKeyInfoElement} {
		element, err := historicalArchiveElement(sig, local)
		if err != nil {
			return err
		}

		if !element.Valid() {
			continue
		}

		options := c14n.Options{Algorithm: b.method, MaxOutputBytes: b.objects.remaining}

		key, raw, err := b.objects.canonical(element, options)
		if err != nil {
			return err
		}

		if local == historicalSignedInfoElement && b.objects.signedInfo != ([32]byte{}) {
			if err := b.objects.linkCanonicalEncoding(key, b.objects.signedInfo, b.objects.signedInfoOptions); err != nil {
				return err
			}
		}

		_, _ = b.state.Write(raw)
		b.covered = append(b.covered, key)
	}

	return nil
}

func historicalArchiveElement(signature document.Element, local string) (document.Element, error) {
	var element document.Element

	for _, child := range signature.Children() {
		if child.Name() == ds(local) {
			if element.Valid() {
				return element, ErrProfile
			}

			element = child
		}
	}

	if !element.Valid() && local != historicalKeyInfoElement {
		return element, ErrProfile
	}

	return element, nil
}

func (b *historicalArchiveBuilder) appendCanonical(element document.Element) error {
	key, raw, err := b.objects.canonical(element, c14n.Options{Algorithm: b.method, MaxOutputBytes: b.objects.remaining})
	if err != nil {
		return err
	}

	_, _ = b.state.Write(raw)
	b.covered = append(b.covered, key)

	return nil
}

func (b *historicalArchiveBuilder) unsignedProperties(unsigned, before document.Element) error {
	for _, entry := range unsigned.Children() {
		if entry.Same(before) {
			return nil
		}

		if err := b.appendCanonical(entry); err != nil {
			return err
		}
	}

	return ErrProfile
}

func (b *historicalArchiveBuilder) otherObjects() error {
	// EN319132-1 §5.5.2.3(6) covers ALL other ds:Object elements, including
	// referenced Objects, in document order. The property-bearing Object is excluded.
	for _, object := range b.baseline.Basic().Signature().Signature().Children() {
		if object.Name() != ds("Object") || historicalObjectHasProperties(object) {
			continue
		}

		if err := b.appendCanonical(object); err != nil {
			return err
		}
	}

	return nil
}

func historicalObjectHasProperties(object document.Element) bool {
	for _, child := range object.Children() {
		if child.Name() == name("QualifyingProperties") {
			return true
		}
	}

	return false
}

func parseHistoricalTimeStamp(ctx context.Context, element document.Element, maximum int) (string, [][]byte, error) {
	if err := optionalID(element); err != nil {
		return "", nil, err
	}

	if err := elementContent(element); err != nil {
		return "", nil, err
	}

	children := element.Children()
	method := c14n.Canonical10

	if len(children) > 0 && children[0].Name() == ds("CanonicalizationMethod") {
		if attrs(children[0], "Algorithm") != nil || len(children[0].Children()) != 0 || !xmlSpace(children[0].Text()) {
			return "", nil, ErrTimestamp
		}

		method = localAttribute(children[0], "Algorithm")
		children = children[1:]
	}

	if !timestampCanonicalization(method) || len(children) == 0 || len(children) > 32 {
		return "", nil, ErrTimestamp
	}
	// EN319132-1 6.3(n) restricts SignatureTimeStamp to one token.
	// ArchiveTimeStamp141 may contain tokens from multiple TSAs (6.3(z)).
	if element.Name() == name("SignatureTimeStamp") && len(children) != 1 {
		return "", nil, ErrProfile
	}

	var tokens [][]byte

	for _, child := range children {
		if child.Name() != name("EncapsulatedTimeStamp") {
			return "", nil, ErrTimestamp
		}

		raw, err := encapsulatedBytes(ctx, child)
		if err != nil || len(raw) > maximum {
			return "", nil, errors.Join(ErrTimestamp, err)
		}

		tokens = append(tokens, raw)
	}

	return method, tokens, nil
}

func historicalHash(method string) (crypto.Hash, error) {
	switch method {
	case xmldsig.SHA1:
		return crypto.SHA1, nil
	case xmldsig.SHA256:
		return crypto.SHA256, nil
	case xmldsig.SHA384:
		return crypto.SHA384, nil
	case xmldsig.SHA512:
		return crypto.SHA512, nil
	}

	return 0, ErrProfile
}

func historicalAllReferences(basic *BasicResult) []xmldsig.ReferenceResult {
	refs := basic.Signature().References()
	for _, manifest := range basic.Signature().Manifests() {
		refs = append(refs, manifest.References()...)
	}

	return refs
}

func historicalSignatureMethod(basic *BasicResult) (x509.SignatureAlgorithm, []crypto.Hash, error) {
	algorithm, hash, err := historicalSignatureAlgorithm(basic)
	if err != nil {
		return 0, nil, err
	}

	var hashes []crypto.Hash
	if hash != 0 {
		hashes = append(hashes, hash)
	}

	for _, reference := range historicalAllReferences(basic) {
		digest, err := historicalHash(reference.DigestMethod())
		if err != nil {
			return 0, nil, err
		}

		if !slices.Contains(hashes, digest) {
			hashes = append(hashes, digest)
		}
	}

	return algorithm, hashes, nil
}

func historicalSignatureAlgorithm(basic *BasicResult) (x509.SignatureAlgorithm, crypto.Hash, error) {
	switch basic.Signature().SignatureMethod() {
	case xmldsig.RSASHA1:
		return x509.SHA1WithRSA, crypto.SHA1, nil
	case xmldsig.DSASHA1:
		return x509.DSAWithSHA1, crypto.SHA1, nil
	case xmldsig.RSASHA256:
		return x509.SHA256WithRSA, crypto.SHA256, nil
	case xmldsig.RSASHA384:
		return x509.SHA384WithRSA, crypto.SHA384, nil
	case xmldsig.RSASHA512:
		return x509.SHA512WithRSA, crypto.SHA512, nil
	case xmldsig.ECDSASHA256:
		return x509.ECDSAWithSHA256, crypto.SHA256, nil
	case xmldsig.ECDSASHA384:
		return x509.ECDSAWithSHA384, crypto.SHA384, nil
	case xmldsig.ECDSASHA512:
		return x509.ECDSAWithSHA512, crypto.SHA512, nil
	case xmldsig.RSAPSSSHA256:
		return x509.SHA256WithRSAPSS, crypto.SHA256, nil
	case xmldsig.RSAPSSSHA384:
		return x509.SHA384WithRSAPSS, crypto.SHA384, nil
	case xmldsig.RSAPSSSHA512:
		return x509.SHA512WithRSAPSS, crypto.SHA512, nil
	case xmldsig.RSAPSS:
		return historicalPSSAlgorithm(basic.Signature().Parameters().PSS)
	case xmldsig.Ed25519:
		return x509.PureEd25519, 0, nil
	case xmldsig.Ed25519ph:
		return x509.PureEd25519, crypto.SHA512, nil
	default:
		return 0, 0, fmt.Errorf("%w: historical signature algorithm", ErrProfile)
	}
}

func historicalPSSAlgorithm(parameters *xmldsig.PSSParameters) (x509.SignatureAlgorithm, crypto.Hash, error) {
	if parameters == nil {
		return 0, 0, ErrProfile
	}

	if parameters.Hash == crypto.SHA256 {
		return x509.SHA256WithRSAPSS, parameters.Hash, nil
	}

	if parameters.Hash == crypto.SHA384 {
		return x509.SHA384WithRSAPSS, parameters.Hash, nil
	}

	if parameters.Hash == crypto.SHA512 {
		return x509.SHA512WithRSAPSS, parameters.Hash, nil
	}

	return 0, 0, ErrProfile
}
