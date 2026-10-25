package xades

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/x509crl"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/xmldsig"
)

// Namespace141 is the XAdES 1.4.1 namespace URI.
const Namespace141 = "http://uri.etsi.org/01903/v1.4.1#"

// ValidationMaterial contains owned copies of embedded certificates and revocation
// objects. OCSPResponses contains complete OCSPResponse encodings. Embedded
// certificates remain untrusted and cannot become trust anchors through inclusion.
type ValidationMaterial struct {
	// Certificates contains owned DER certificate encodings without assigning trust.
	Certificates [][]byte
	// CRLs contains owned DER certificate revocation list encodings.
	CRLs [][]byte
	// OCSPResponses contains owned complete DER OCSPResponse encodings.
	OCSPResponses [][]byte
}

func (m ValidationMaterial) evidence() pki.Evidence {
	// Parsed material is privately owned and PKI verification does not mutate it.
	return pki.Evidence{CRLs: m.CRLs, OCSPResponses: m.OCSPResponses}
}

// EmbedValidationMaterial augments this profile's B-T document with the exact
// verified signer chain and TSA path material plus caller-provided CRL/OCSP.
// The new document must verify using EMBEDDED evidence only; configured roots
// remain explicit, but configured intermediate certificates cannot hide gaps.
// This is current-time evidence validation, not historical EN 319 102-1.
func (v *Validator) EmbedValidationMaterial(ctx context.Context, doc *document.Document, selected document.Element, certificate []byte, at time.Time, evidence ValidationEvidence) (*document.Document, *ValidationResult, error) {
	if !v.canEmbedMaterial(ctx) {
		return nil, nil, ErrLevel
	}

	present, e := hasPreservation(selected)
	if e != nil || present {
		return nil, nil, ErrProfile
	}

	baseV := *v
	baseV.minimum = LevelBT

	before, e := baseV.ValidateEnveloped(ctx, doc, selected, certificate, at, evidence)
	if e != nil {
		return nil, nil, e
	}

	signerCerts := subtractDER(before.trust.ChainDER(), certificate)
	// This implementation uses certificate-based trust anchors; include their
	// certificates as the format requires, without trusting them from the XML.
	if len(signerCerts) == 0 {
		return nil, nil, ErrProfile
	}

	sm := ValidationMaterial{Certificates: signerCerts, CRLs: evidence.Signer.CRLs, OCSPResponses: evidence.Signer.OCSPResponses}
	if e = checkRawMaterial(ctx, sm); e != nil {
		return nil, nil, e
	}

	if len(sm.CRLs)+len(sm.OCSPResponses) == 0 {
		return nil, nil, ErrLevel
	}

	draft, un, e := unsignedDraft(ctx, doc, selected)
	if e != nil {
		return nil, nil, e
	}

	// Retain every existing text/comment node; insert TS validation containers
	// without changing SignedInfo, SignatureValue, KeyInfo, or SignedProperties.
	original := un.Children
	un.Children = nil
	cursor := timestampMaterialCursor{result: before, signerCerts: signerCerts, certificate: certificate}

	for _, n := range original {
		un.Children = append(un.Children, n)

		if n.Kind != tree.ElementNode || n.Name != name("SignatureTimeStamp") {
			continue
		}

		tsaCerts, err := cursor.certificates(ctx, tree.Wrap(doc, n).Children())
		if err != nil {
			return nil, nil, err
		}

		tm := ValidationMaterial{Certificates: tsaCerts, CRLs: evidence.TSA.CRLs, OCSPResponses: evidence.TSA.OCSPResponses}
		if e = checkRawMaterial(ctx, tm); e != nil {
			return nil, nil, e
		}

		if len(tm.CRLs)+len(tm.OCSPResponses) == 0 {
			return nil, nil, ErrLevel
		}

		td := node141("TimeStampValidationData")
		if err := appendValidationMaterial(ctx, td, tm); err != nil {
			return nil, nil, err
		}

		add(un, td)
	}

	if err := appendValidationMaterial(ctx, un, sm); err != nil {
		return nil, nil, err
	}

	resultDoc, e := publishDraft(ctx, draft)
	if e != nil {
		return nil, nil, e
	}

	full := *v
	full.minimum = LevelLT

	r, e := full.ValidateEnveloped(ctx, resultDoc, xmldsig.Signatures(resultDoc)[0], certificate, at, ValidationEvidence{})
	if e != nil {
		return nil, nil, e
	}

	return resultDoc, r, nil
}

func node141(local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Name: name141(local), Prefix: "xades141", NS: []tree.Namespace{{Prefix: "xades141", URI: Namespace141}}}
}

func knownPreservation(n document.Name) bool {
	return n == name("CertificateValues") || n == name("RevocationValues") || n == name141("TimeStampValidationData") || n == name141("ArchiveTimeStamp")
}

func hasPreservation(sig document.Element) (bool, error) {
	u, e := unsignedProperties(sig)
	if e != nil {
		return false, e
	}

	for _, x := range u.Children() {
		if knownPreservation(x.Name()) {
			return true, nil
		}
	}

	return false, nil
}

func makeCertificateValues(ctx context.Context, entries [][]byte) (*tree.Node, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	n := xnode("CertificateValues")
	n.NS = []tree.Namespace{{Prefix: nameXades, URI: Namespace}}

	for _, b := range entries {
		encoded, err := encodeBase64(ctx, len(b), bytes.NewBuffer(b))
		if err != nil {
			return nil, err
		}

		c := xnode("EncapsulatedX509Certificate")
		text(c, encoded)
		add(n, c)
	}

	return n, nil
}

func makeRevocationValues(ctx context.Context, e pki.Evidence) (*tree.Node, error) {
	if len(e.CRLs)+len(e.OCSPResponses) == 0 {
		return nil, nil
	}

	n := xnode("RevocationValues")
	n.NS = []tree.Namespace{{Prefix: nameXades, URI: Namespace}}

	for i, entries := range [][][]byte{e.CRLs, e.OCSPResponses} {
		if len(entries) == 0 {
			continue
		}

		group, local := "CRLValues", "EncapsulatedCRLValue"
		if i == 1 {
			group, local = "OCSPValues", "EncapsulatedOCSPValue"
		}

		g := xnode(group)

		for _, b := range entries {
			encoded, err := encodeBase64(ctx, len(b), bytes.NewBuffer(b))
			if err != nil {
				return nil, err
			}

			c := xnode(local)
			text(c, encoded)
			add(g, c)
		}

		add(n, g)
	}

	return n, nil
}

func appendValidationMaterial(ctx context.Context, parent *tree.Node, m ValidationMaterial) error {
	certificates, err := makeCertificateValues(ctx, m.Certificates)
	if err != nil {
		return err
	}

	revocation, err := makeRevocationValues(ctx, m.evidence())
	if err != nil {
		return err
	}

	if certificates != nil {
		add(parent, certificates)
	}

	if revocation != nil {
		add(parent, revocation)
	}

	return nil
}

func publishDraft(ctx context.Context, d *document.Document) (*document.Document, error) {
	return tree.Reparse(ctx, d, tree.Policy(d))
}

func (v *Validator) canEmbedMaterial(ctx context.Context) bool {
	return !(v == nil || ctx == nil || v.tsa == nil || v.signer.RevocationMode() == pki.NoRevocation || v.tsa.RevocationMode() == pki.NoRevocation)
}

func name141(local string) document.Name { return document.Name{Space: Namespace141, Local: local} }

func cloneMaterial(m ValidationMaterial) ValidationMaterial {
	return ValidationMaterial{copyDER(m.Certificates), copyDER(m.CRLs), copyDER(m.OCSPResponses)}
}

func copyDER(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}

	out := make([][]byte, 0, len(in))
	for _, b := range in {
		out = append(out, bytes.Clone(b))
	}

	return out
}

func appendUnique(dst [][]byte, src ...[]byte) [][]byte {
	for _, b := range src {
		found := false

		for _, x := range dst {
			if bytes.Equal(x, b) {
				found = true
				break
			}
		}

		if !found {
			dst = append(dst, b)
		}
	}

	return dst
}

func subtractDER(in [][]byte, omit ...[]byte) [][]byte {
	var out [][]byte

	for _, b := range in {
		found := false

		for _, x := range omit {
			if bytes.Equal(b, x) {
				found = true
				break
			}
		}

		if !found {
			out = appendUnique(out, b)
		}
	}

	return out
}

func checkRawMaterial(ctx context.Context, m ValidationMaterial) error {
	if len(m.Certificates) > 64 || len(m.CRLs) > 64 || len(m.OCSPResponses) > 64 {
		return ErrProfile
	}

	total := 0

	for g, entries := range [][][]byte{m.Certificates, m.CRLs, m.OCSPResponses} {
		seen := map[[sha256.Size]byte][][]byte{}

		for _, b := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}

			total += len(b)
			if len(b) == 0 || len(b) > 4<<20 || total > 16<<20 {
				return ErrProfile
			}

			hash := sha256.Sum256(b)
			for _, previous := range seen[hash] {
				if bytes.Equal(previous, b) {
					return ErrProfile
				}
			}

			seen[hash] = append(seen[hash], b)

			if err := validateMaterialObject(g, b); err != nil {
				return err
			}
		}
	}

	return nil
}

type preservation struct {
	unsigned document.Element
	signer   ValidationMaterial
	tsa      ValidationMaterial
	archives []document.Element
}

func parsePreservation(ctx context.Context, sig document.Element, maxArchives int) (preservation, error) {
	var p preservation

	u, e := unsignedProperties(sig)
	if e != nil || !u.Valid() {
		return p, ErrLevel
	}

	p.unsigned = u
	if elementContent(u) != nil {
		return p, ErrProfile
	}

	entries := u.Children()
	if len(entries) > 140 {
		return p, ErrProfile
	}

	parser := preservationParser{ctx: ctx, value: p, maxArchives: maxArchives}
	for _, entry := range entries {
		if err := parser.accept(entry); err != nil {
			return parser.value, err
		}
	}

	p = parser.value

	if !parser.haveTimestamp || !parser.haveCV || !parser.haveRV {
		return p, ErrLevel
	}

	if e = checkRawMaterial(ctx, p.signer); e != nil {
		return p, e
	}

	if e = checkRawMaterial(ctx, p.tsa); e != nil {
		return p, e
	}

	return p, nil
}

func validateEmbeddedOCSP(b []byte) error {
	// XAdES uses the entire DER OCSPResponse (ETSI 5.4.3), unlike
	// CMS revocation formats that sometimes carry BasicOCSPResponse.
	v, e := der.Read(b, 4<<20)
	if e != nil {
		return ErrProfile
	}

	f, e := der.Sequence(v, 2, 2)
	if e != nil {
		return ErrProfile
	}

	var status asn1.Enumerated
	if der.Decode(f[0], &status) != nil || status != 0 {
		return ErrProfile
	}

	body, e := der.Explicit(f[1], 0)
	if e != nil {
		return ErrProfile
	}

	parts, e := der.Sequence(body, 2, 2)
	if e != nil || !der.OIDEqual(parts[0], asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}) {
		return ErrProfile
	}

	if !der.Is(parts[1], 0, asn1.TagOctetString, false) {
		return ErrProfile
	}

	if _, e = der.Read(parts[1].Bytes, 4<<20); e != nil {
		return ErrProfile
	}

	return nil
}

type preservationParser struct {
	ctx           context.Context
	value         preservation
	haveCV        bool
	haveRV        bool
	haveTimestamp bool
	phase         int
	maxArchives   int
	previous      document.Name
}

func (r *preservationParser) accept(x document.Element) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}

	var e error

	switch x.Name() {
	case name("SignatureTimeStamp"):
		if r.phase != 0 {
			return ErrProfile
		}

		r.haveTimestamp = true
	case name141("TimeStampValidationData"):
		if r.previous != name("SignatureTimeStamp") && r.previous != name141("ArchiveTimeStamp") {
			return ErrProfile
		}

		m, e := parseTSVD(r.ctx, x)
		if e != nil {
			return e
		}

		r.value.tsa.Certificates = appendUnique(r.value.tsa.Certificates, m.Certificates...)
		r.value.tsa.CRLs = appendUnique(r.value.tsa.CRLs, m.CRLs...)
		r.value.tsa.OCSPResponses = appendUnique(r.value.tsa.OCSPResponses, m.OCSPResponses...)
	case name("CertificateValues"):
		if r.haveCV || r.phase > 1 {
			return ErrProfile
		}

		r.phase = 1
		r.haveCV = true

		r.value.signer.Certificates, e = parseCertificateValues(r.ctx, x)
		if e != nil {
			return e
		}
	case name("RevocationValues"):
		if r.haveRV || r.phase > 2 {
			return ErrProfile
		}

		r.phase = 2
		r.haveRV = true

		r.value.signer.CRLs, r.value.signer.OCSPResponses, e = parseRevocationValues(r.ctx, x)
		if e != nil {
			return e
		}
	case name141("ArchiveTimeStamp"):
		if !r.haveRV || !r.haveCV || len(r.value.archives) >= r.maxArchives {
			return ErrProfile
		}

		r.phase = 3

		r.value.archives = append(r.value.archives, x)
	default:
		return ErrProfile
	}

	r.previous = x.Name()

	return nil
}

func encapsulatedBytes(ctx context.Context, e document.Element) ([]byte, error) {
	if len(e.Children()) != 0 {
		return nil, ErrProfile
	}

	for _, a := range e.Attributes() {
		if a.Name == (document.Name{Local: "Id"}) && tree.NCName(a.Value) {
			continue
		}

		if a.Name == (document.Name{Local: "Encoding"}) && a.Value == encodingDER {
			continue
		}

		return nil, ErrProfile
	}

	return decodeElementBase64(ctx, e, 6<<20, 4<<20)
}

func parseCertificateValues(ctx context.Context, e document.Element) ([][]byte, error) {
	if elementContent(e) != nil || e.Name() != name("CertificateValues") || optionalID(e) != nil || len(e.Children()) < 1 || len(e.Children()) > 64 {
		return nil, ErrProfile
	}

	var out [][]byte

	for _, c := range e.Children() {
		if c.Name() != name("EncapsulatedX509Certificate") {
			return nil, ErrProfile
		}

		b, err := encapsulatedBytes(ctx, c)
		if err != nil {
			return nil, err
		}

		out = append(out, b)
	}

	return out, nil
}

func parseRevocationValues(ctx context.Context, e document.Element) ([][]byte, [][]byte, error) {
	if elementContent(e) != nil || e.Name() != name("RevocationValues") || optionalID(e) != nil {
		return nil, nil, ErrProfile
	}

	cs := e.Children()
	if len(cs) < 1 || len(cs) > 2 {
		return nil, nil, ErrProfile
	}

	var crls, ocsps [][]byte

	last := -1

	for _, g := range cs {
		var kind int

		local := ""

		switch g.Name() {
		case name("CRLValues"):
			kind = 0
			local = "EncapsulatedCRLValue"
		case name("OCSPValues"):
			kind = 1
			local = "EncapsulatedOCSPValue"
		default:
			return nil, nil, ErrProfile
		}

		if kind <= last || attrs(g) != nil || len(g.Children()) < 1 || len(g.Children()) > 64 {
			return nil, nil, ErrProfile
		}

		last = kind

		for _, n := range g.Children() {
			if n.Name() != name(local) {
				return nil, nil, ErrProfile
			}

			b, e := encapsulatedBytes(ctx, n)
			if e != nil {
				return nil, nil, e
			}

			if kind == 0 {
				crls = append(crls, b)
			} else {
				ocsps = append(ocsps, b)
			}
		}
	}

	return crls, ocsps, nil
}

func parseTSVD(ctx context.Context, e document.Element) (ValidationMaterial, error) {
	var m ValidationMaterial
	// Direct incorporation immediately after its timestamp: URI is not used.
	if elementContent(e) != nil || e.Name() != name141("TimeStampValidationData") || optionalID(e) != nil || len(e.Children()) < 1 || len(e.Children()) > 2 {
		return m, ErrProfile
	}

	last := -1

	for _, c := range e.Children() {
		switch c.Name() {
		case name("CertificateValues"):
			if last >= 0 {
				return m, ErrProfile
			}

			last = 0

			a, err := parseCertificateValues(ctx, c)
			if err != nil {
				return m, err
			}

			m.Certificates = a
		case name("RevocationValues"):
			if last >= 1 {
				return m, ErrProfile
			}

			last = 1

			a, b, err := parseRevocationValues(ctx, c)
			if err != nil {
				return m, err
			}

			m.CRLs = a
			m.OCSPResponses = b
		default:
			return m, ErrProfile
		}
	}

	return m, checkRawMaterial(ctx, m)
}

func elementContent(e document.Element) error {
	_, n := tree.Unwrap(e)
	if n == nil {
		return ErrProfile
	}

	for _, c := range n.Children {
		if c.Kind == tree.TextNode && !xmlSpace(c.Data) {
			return ErrProfile
		}
	}

	return nil
}

type timestampMaterialCursor struct {
	result      *ValidationResult
	next        int
	signerCerts [][]byte
	certificate []byte
}

func (c *timestampMaterialCursor) certificates(ctx context.Context, children []document.Element) ([][]byte, error) {
	var tsaCerts [][]byte

	for _, enc := range children {
		if enc.Name() != name("EncapsulatedTimeStamp") {
			continue
		}

		if c.next >= len(c.result.timestamps) {
			return nil, ErrProfile
		}

		tok := c.result.timestamps[c.next]
		c.next++

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		omit := append(append([][]byte(nil), c.signerCerts...), c.certificate)
		omit = append(omit, tok.Token().Certificates()...)
		tsaCerts = appendUnique(tsaCerts, subtractDER(tok.Trust().ChainDER(), omit...)...)
	}

	return tsaCerts, nil
}

func validateMaterialObject(kind int, raw []byte) error {
	switch kind {
	case 0:
		if _, e := x509cert.ParseWithMaxBytes(raw, len(raw)); e != nil {
			return fmt.Errorf("%w: embedded certificate", ErrProfile)
		}
	case 1:
		if _, e := x509crl.ParseEvidence(raw, len(raw)); e != nil {
			return fmt.Errorf("%w: embedded CRL", ErrProfile)
		}
	case 2:
		if err := validateEmbeddedOCSP(raw); err != nil {
			return err
		}
	}

	return nil
}
