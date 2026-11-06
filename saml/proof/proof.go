// Package proof verifies ECP 2013 proof of possession. A Verified value establishes
// possession of a certificate's key for one immutable SOAP message, not identity,
// certificate trust, SAML validity, freshness or replay protection.
//
// XML proof formats have separate APIs: [SignEnvelopedXML] and
// [VerifyEnvelopedXML] use the declared W3C transform; [SignCS01CompatXML] and
// [VerifyCS01CompatXML] use the explicitly agreed CS01 compatibility form.
// Neither API settles the ambiguous no-Transforms wording in ECP CS01 2.3.11.
package proof

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// Decoded certificate byte ceiling shared by proof construction/parsing; exact certificate bytes identify possession, not a trust chain.
const (
	maximumCertificateBytes = 64 << 10
)

// WS-Security wrapper local name shared by signing and decoding; its presence supplies no certificate or identity trust.
const (
	xmlNameSecurity = "Security"
)

// SecurityNamespace identifies the WS-Security header containing an XML proof.
const SecurityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

// ErrProof reports a malformed, mismatched or unverifiable proof of possession.
var ErrProof = errors.New("SAML ECP proof rejected")

// Options bounds XML processing and restricts proof signature algorithms.
type Options struct {
	// SOAP bounds envelope parsing and declares understood SOAP headers.
	SOAP binding.SOAPOptions
	// Policy restricts the XML proof's signature and reference algorithms.
	Policy xmldsig.Policy
	// Certificate optionally pins the exact attesting certificate. Without it,
	// XML verification obtains a candidate from KeyInfo, without granting trust.
	Certificate []byte
}

// Verified binds a proven certificate to the exact immutable received message.
// Its zero value grants no proof. Applications must independently associate the
// certificate with the principal before issuing an assertion (ECP 2.3.5.1).
type Verified struct {
	// message is the exact immutable SOAP message covered by the proof.
	message *binding.SOAPMessage
	// certificate retains the exact DER certificate whose possession was proven.
	certificate []byte
	// xml records whether proof was established by an XML signature.
	xml bool
}

// Certificate returns an owned copy of the exact attesting certificate bytes.
func (p *Verified) Certificate() []byte {
	if p == nil {
		return nil
	}

	return bytes.Clone(p.certificate)
}

// Envelope returns the immutable message authenticated by this proof.
func (p *Verified) Envelope() *document.Document {
	if p == nil || p.message == nil {
		return nil
	}

	return p.message.Envelope()
}

// Payload returns a context-preserving view of the exact SOAP body message.
func (p *Verified) Payload(ctx context.Context) (*document.Document, error) {
	if p == nil || p.message == nil {
		return nil, ErrProof
	}

	return p.message.Payload(ctx)
}

// Covers checks the exact SOAP payload snapshot; it never matches by XML ID.
func (p *Verified) Covers(d *document.Document) bool {
	if p == nil || p.message == nil || d == nil {
		return false
	}

	view, err := p.message.Payload(context.Background())
	if err != nil {
		return false
	}

	return tree.ContextElement(d.Root()).Same(tree.ContextElement(view.Root()))
}

// XML reports a whole-message XML proof rather than a TLS client proof.
func (p *Verified) XML() bool { return p != nil && p.message != nil && p.xml }

// Message returns the immutable SOAP message whose key possession was verified.
// Its body still requires independent SAML signature/profile verification.
func (p *Verified) Message() *binding.SOAPMessage {
	if p == nil {
		return nil
	}

	return p.message
}

// VerifyTLSRequest reads one bounded POST and obtains the certificate from the
// completed server-side TLS handshake. Use the original net/http server request,
// never a synthetic TLS state or a certificate copied from a proxy header.
// RequestClientCert/RequireAnyClientCert can establish possession without PKIX;
// certificate-to-principal association is a separate application decision.
func VerifyTLSRequest(ctx context.Context, r *http.Request, o Options) (*Verified, error) {
	const (
		defaultSOAPBytes = 2 << 20
		maximumSOAPBytes = 16 << 20
	)

	if ctx == nil || r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.PeerCertificates) == 0 || r.Method != http.MethodPost || r.Body == nil {
		return nil, ErrProof
	}

	media, _, err := mime.ParseMediaType(r.Header.Get(lexicon.HeaderContentType))
	if err != nil || media != lexicon.MediaTypeSOAP && media != lexicon.MediaTypePAOS {
		return nil, ErrProof
	}

	cert, err := certificate(r.TLS.PeerCertificates[0].Raw)
	if err != nil || len(o.Certificate) != 0 && !bytes.Equal(o.Certificate, cert.Raw) {
		return nil, ErrProof
	}

	limit := o.SOAP.MaxBytes
	if limit == 0 {
		limit = defaultSOAPBytes
	}

	if limit < 1 || limit > maximumSOAPBytes {
		return nil, ErrProof
	}

	raw, err := io.ReadAll(&streamio.Reader{Context: ctx, Source: r.Body, Limit: int64(limit), LimitError: ErrProof})
	if err != nil {
		return nil, err
	}

	m, err := binding.DecodeSOAP(ctx, raw, o.SOAP)
	if err != nil {
		return nil, err
	}

	return &Verified{message: m, certificate: bytes.Clone(cert.Raw)}, nil
}

func certificate(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > maximumCertificateBytes {
		return nil, ErrProof
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil || signature.Key(cert.PublicKey) != nil {
		return nil, ErrProof
	}

	return cert, nil
}

func decode(ctx context.Context, raw []byte, o Options) (*binding.SOAPMessage, error) {
	o.SOAP.Understood = append(append([]document.Name(nil), o.SOAP.Understood...), xmlutil.Name(SecurityNamespace, xmlNameSecurity))
	return binding.DecodeSOAP(ctx, raw, o.SOAP)
}
