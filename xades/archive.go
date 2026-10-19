package xades

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xmldsig"
)

// AddArchiveOptions selects the timestamp request and canonicalization for an archive
// timestamp.
type AddArchiveOptions struct {
	Request timestamp.RequestOptions
	// Canonicalization defaults to Exclusive C14N.
	Canonicalization string
}

// AddArchiveTimestamp preserves existing evidence/archives in a new snapshot.
// All old and new timestamps must verify with the already embedded material.
// Changing TSA to one requiring new evidence needs a separate augmentation
// profile; this operation does not append unauthenticated fallback evidence.
func (v *Validator) AddArchiveTimestamp(ctx context.Context, doc *document.Document, selected document.Element, certificate []byte, at time.Time, transport timestamp.Transport, o AddArchiveOptions) (*document.Document, *ValidationResult, error) {
	if v == nil || ctx == nil {
		return nil, nil, ErrProfile
	}

	base := *v
	base.minimum = LevelLT

	verified, e := base.ValidateEnveloped(ctx, doc, selected, certificate, at, ValidationEvidence{})
	if e != nil {
		return nil, nil, e
	}

	if len(verified.archives) >= v.maxArchives {
		return nil, nil, ErrLevel
	}

	material, e := parsePreservation(ctx, selected, v.maxArchives)
	if e != nil {
		return nil, nil, e
	}

	method := o.Canonicalization
	if method == "" {
		method = c14n.Exclusive
	}

	imprint, e := archiveImprint(ctx, verified.basic, material.unsigned, document.Element{}, method, v.maxArchiveBytes, o.Request.Hash)
	if e != nil {
		return nil, nil, e
	}

	request, e := timestamp.CreateImprintRequest(imprint, o.Request)
	if e != nil {
		return nil, nil, e
	}

	tsa, e := v.tsa.WithEvidenceCertificates(appendUnique(append([][]byte(nil), verified.material.Certificates...), certificate))
	if e != nil {
		return nil, nil, e
	}

	token, e := tsa.Fetch(ctx, transport, request, at, verified.material.evidence())
	if e != nil {
		return nil, nil, e
	}

	return v.appendArchive(ctx, doc, selected, certificate, at, method, token.Token())
}

// AttachArchiveTimestamp authenticates a previously obtained token against the
// archive input. With no original request, it makes no nonce-correlation claim.
func (v *Validator) AttachArchiveTimestamp(ctx context.Context, doc *document.Document, selected document.Element, certificate []byte, at time.Time, tokenDER []byte, method string) (*document.Document, *ValidationResult, error) {
	if v == nil || ctx == nil {
		return nil, nil, ErrProfile
	}

	base := *v
	base.minimum = LevelLT

	verified, e := base.ValidateEnveloped(ctx, doc, selected, certificate, at, ValidationEvidence{})
	if e != nil {
		return nil, nil, e
	}

	if len(verified.archives) >= v.maxArchives {
		return nil, nil, ErrLevel
	}

	material, e := parsePreservation(ctx, selected, v.maxArchives)
	if e != nil {
		return nil, nil, e
	}

	if method == "" {
		method = c14n.Exclusive
	}

	if len(tokenDER) > v.maxTokenBytes {
		return nil, nil, ErrTimestamp
	}

	token, e := timestamp.ParseToken(ctx, tokenDER)
	if e != nil {
		return nil, nil, e
	}

	want, e := archiveImprint(ctx, verified.basic, material.unsigned, document.Element{}, method, v.maxArchiveBytes, token.UnverifiedInfo().Imprint().Hash)
	if e != nil {
		return nil, nil, e
	}

	tsa, e := v.tsa.WithEvidenceCertificates(appendUnique(append([][]byte(nil), verified.material.Certificates...), certificate))
	if e != nil {
		return nil, nil, e
	}

	if _, e = tsa.Verify(ctx, token, timestamp.Expectation{Imprint: want}, at, verified.material.evidence()); e != nil {
		return nil, nil, e
	}

	return v.appendArchive(ctx, doc, selected, certificate, at, method, token)
}

func (v *Validator) validatePreserved(ctx context.Context, doc *document.Document, sig document.Element, certificate []byte, at time.Time) (*ValidationResult, error) {
	if v.tsa == nil || v.signer.RevocationMode() == pki.NoRevocation || v.tsa.RevocationMode() == pki.NoRevocation {
		return nil, ErrLevel
	}

	basic, e := verifyBasicEnveloped(ctx, doc, sig, certificate, v.basic, true)
	if e != nil {
		return nil, e
	}

	material, e := parsePreservation(ctx, sig, v.maxArchives)
	if e != nil {
		return nil, e
	}

	signerTrust, e := v.signer.WithIntermediateCertificates(material.signer.Certificates)
	if e != nil {
		return nil, e
	}

	trust, _, e := signerTrust.Verify(ctx, certificate, at, material.signer.evidence())
	if e != nil {
		return nil, e
	}

	if trust.RevocationStatus() != pki.Valid {
		return nil, ErrLevel
	}
	// The embedded signer chain (including a certificate-form trust anchor)
	// must be complete; the trust ANCHOR decision remains out-of-band.
	available := append(append([][]byte(nil), material.signer.Certificates...), certificate)
	for _, cert := range trust.ChainDER() {
		if len(subtractDER([][]byte{cert}, available...)) != 0 {
			return nil, fmt.Errorf("%w: incomplete embedded signer chain", ErrLevel)
		}
	}

	certs := appendUnique(append([][]byte(nil), available...), material.tsa.Certificates...)

	tsa, e := v.tsa.WithEvidenceCertificates(certs)
	if e != nil {
		return nil, e
	}

	tsaProof := material.tsa.evidence()
	// Sharing revocation material is permitted; each response/CRL is still
	// checked against its actual issuer and target by the verifier.
	tsaProof.CRLs = appendUnique(tsaProof.CRLs, material.signer.CRLs...)
	tsaProof.OCSPResponses = appendUnique(tsaProof.OCSPResponses, material.signer.OCSPResponses...)

	timed, e := normalizeTimed(TimedOptions{Basic: v.basic, TSA: tsa, At: at, Evidence: tsaProof, MaxTimestamps: v.maxTimestamps, MaxTokenBytes: v.maxTokenBytes})
	if e != nil {
		return nil, e
	}

	stamps, e := verifySignatureTimestampsMode(ctx, sig, timed, false, true)
	if e != nil {
		return nil, e
	}

	for _, r := range stamps {
		if e := completeTSAChain(ctx, r, certs); e != nil {
			return nil, e
		}

		if r.Trust().RevocationStatus() != pki.Valid {
			return nil, ErrLevel
		}
	}

	result := &ValidationResult{basic: basic, trust: trust, timestamps: stamps, level: LevelLT, at: at, material: material.signer}
	result.material.Certificates = appendUnique(result.material.Certificates, material.tsa.Certificates...)
	result.material.CRLs = appendUnique(result.material.CRLs, material.tsa.CRLs...)
	result.material.OCSPResponses = appendUnique(result.material.OCSPResponses, material.tsa.OCSPResponses...)

	previous := time.Time{}
	for _, stamp := range stamps {
		if stamp.Info().GenTime().After(previous) {
			if e := completeTSAChain(ctx, stamp, certs); e != nil {
				return nil, e
			}

			previous = stamp.Info().GenTime()
		}
	}

	if err := validatePreservedArchives(ctx, &material, &timed, basic, v, tsa, &at, &tsaProof, &previous, certs, result); err != nil {
		return nil, err
	}

	if len(result.archives) > 0 {
		result.level = LevelLTA
	} else if v.minimum == LevelLTA {
		return nil, ErrLevel
	}

	return result, nil
}

func completeTSAChain(ctx context.Context, stamp *timestamp.Result, certificates [][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	present := append(append([][]byte(nil), certificates...), stamp.Token().Certificates()...)
	for _, c := range stamp.Trust().ChainDER() {
		if len(subtractDER([][]byte{c}, present...)) != 0 {
			return fmt.Errorf("%w: incomplete embedded TSA chain", ErrLevel)
		}
	}

	return nil
}

func validatePreservedArchives(ctx context.Context, material *preservation, timed *TimedOptions, basic *BasicResult, v *Validator, tsa *timestamp.Verifier, at *time.Time, tsaProof *pki.Evidence, previous *time.Time, certs [][]byte, result *ValidationResult) error {
	for _, archive := range material.archives {
		method, tokens, e := parseTimeStamp(ctx, archive, timed.MaxTokenBytes)
		if e != nil {
			return e
		}

		if len(tokens) != 1 {
			return fmt.Errorf("%w: one token per archive required by this profile", ErrProfile)
		}

		token, e := timestamp.ParseToken(ctx, tokens[0])
		if e != nil {
			return e
		}

		imprint, e := archiveImprint(ctx, basic, material.unsigned, archive, method, v.maxArchiveBytes, token.UnverifiedInfo().Imprint().Hash)
		if e != nil {
			return e
		}

		stamp, e := tsa.Verify(ctx, token, timestamp.Expectation{Imprint: imprint}, (*at), (*tsaProof))
		if e != nil {
			return fmt.Errorf("%w: archive: %w", ErrTimestamp, e)
		}

		if stamp.Trust().RevocationStatus() != pki.Valid || stamp.Info().GenTime().Before((*previous)) {
			return fmt.Errorf("%w: archive trust/chronology", ErrTimestamp)
		}

		if e := completeTSAChain(ctx, stamp, certs); e != nil {
			return e
		}

		*previous = stamp.Info().GenTime()
		result.archives = append(result.archives, stamp)
	}

	return nil
}

func (v *Validator) appendArchive(ctx context.Context, doc *document.Document, selected document.Element, certificate []byte, at time.Time, method string, token *timestamp.Token) (*document.Document, *ValidationResult, error) {
	limit := v.maxTokenBytes
	if limit == 0 {
		limit = 4 << 20
	}

	if token.Size() > limit {
		return nil, nil, ErrTimestamp
	}

	draft, un, e := unsignedDraft(ctx, doc, selected)
	if e != nil {
		return nil, nil, e
	}

	archive := node141("ArchiveTimeStamp")
	archive.NS = append(archive.NS, tree.Namespace{Prefix: "ds", URI: xmldsig.Namespace}, tree.Namespace{Prefix: nameXades, URI: Namespace})
	cm := dsnode("CanonicalizationMethod")
	attr(cm, "Algorithm", method)
	add(archive, cm)

	enc := xnode("EncapsulatedTimeStamp")
	attr(enc, "Encoding", encodingDER)

	encoded, e := encodeBase64(ctx, token.Size(), token.WriterTo(ctx))
	if e != nil {
		return nil, nil, e
	}

	text(enc, encoded)
	add(archive, enc)
	add(un, archive)

	parsed, e := publishDraft(ctx, draft)
	if e != nil {
		return nil, nil, e
	}

	full := *v
	full.minimum = LevelLTA

	r, e := full.ValidateEnveloped(ctx, parsed, xmldsig.Signatures(parsed)[0], certificate, at, ValidationEvidence{})
	if e != nil {
		return nil, nil, e
	}

	return parsed, r, nil
}

// writeArchiveInput implements EN 319 132-1 5.5.2.3's non-distributed input for this
// closed profile: processed References; SignedInfo; SignatureValue; KeyInfo;
// preceding unsigned properties; other unreferenced Objects (none in this
// profile). It never merely timestamps the SignatureValue a second time.
func writeArchiveInput(ctx context.Context, dst io.Writer, basic *BasicResult, unsigned, before document.Element, method string, maximum int) error {
	if ctx == nil || basic == nil || !unsigned.Valid() || !timestampCanonicalization(method) || maximum < 1 {
		return ErrProfile
	}

	b := &streamio.Writer{Context: ctx, Target: dst, Limit: int64(maximum), LimitError: fmt.Errorf("%w: archive input budget", ErrProfile)}

	if err := archiveInputReferences(ctx, basic, b); err != nil {
		return err
	}

	sig := basic.Signature().Signature()
	for _, local := range []string{"SignedInfo", "SignatureValue", "KeyInfo"} {
		n, e := childNamed(sig, ds(local))
		if e != nil {
			return e
		}

		options := c14n.Options{Algorithm: method, MaxOutputBytes: maximum}

		if local == "SignedInfo" {
			cm, err := childNamed(n, ds("CanonicalizationMethod"))
			if err != nil {
				return err
			}

			options.Algorithm, _ = cm.Attribute(document.Name{Local: "Algorithm"})
			for _, p := range cm.Children() {
				if p.Name() != (document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}) {
					return ErrProfile
				}

				value, _ := p.Attribute(document.Name{Local: "PrefixList"})
				options.InclusivePrefixes = strings.Fields(value)
			}
		}

		if e = c14n.WriteElement(ctx, b, n, options); e != nil {
			return e
		}
	}

	stopped := !before.Valid()
	for _, n := range unsigned.Children() {
		if before.Valid() && n.Same(before) {
			stopped = true
			break
		}

		if e := c14n.WriteElement(ctx, b, n, c14n.Options{Algorithm: method, MaxOutputBytes: maximum}); e != nil {
			return e
		}
	}

	if !stopped {
		return ErrProfile
	}
	// verifyBasicEnveloped already enforces one Object containing QualifyingProperties.
	// Other Objects, Manifest/external and distributed Include mechanisms are
	// not silently interpreted by the restricted archive implementation.
	return nil
}

func archiveImprint(ctx context.Context, basic *BasicResult, unsigned, before document.Element, method string, maximum int, h crypto.Hash) (timestamp.Imprint, error) {
	return timestampImprint(h, func(dst io.Writer) error {
		return writeArchiveInput(ctx, dst, basic, unsigned, before, method, maximum)
	})
}

func archiveInputReferences(ctx context.Context, basic *BasicResult, b io.Writer) error {
	for _, ref := range basic.Signature().References() {
		if e := ctx.Err(); e != nil {
			return e
		}

		if _, e := ref.WriteDigestInput(ctx, b); e != nil {
			return e
		}
	}

	return nil
}
