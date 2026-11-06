package binding

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Bound supplied SOAP headers and understood-header declarations to 64 entries before wrapping or dispatch; payload bytes have a separate limit.
const (
	maximumSOAPHeaders = 64
)

// Canonical HTTP field spelling shared by SOAP/URI transports; the associated cache directives keep protocol responses out of intermediary storage.
const (
	headerCacheControl = "Cache-Control"
	headerPragma       = "Pragma"
)

// Outgoing fault messages and parsed fault message/actor text are bounded to 4096 UTF-8 bytes; remote diagnostics supply no trusted routing or identity.
const (
	maximumSOAPFaultTextBytes = 4096
)

// SOAP 1.1 HTTP output declares XML in UTF-8; receiver MIME checks and XML parsing still validate the actual message independently.
const (
	mediaTypeSOAPUTF8 = lexicon.MediaTypeSOAP + "; charset=" + lexicon.EncodingUTF8
)

// SOAP 1.1 containers use the envelope namespace while fault members are unqualified; these local tokens never replace expanded-name checks.
const (
	xmlNameBody        = "Body"
	xmlNameEnvelope    = "Envelope"
	xmlNameFault       = "Fault"
	xmlNameFaultcode   = "faultcode"
	xmlNameFaultstring = "faultstring"
	xmlNameHeader      = "Header"
)

// Standard SOAP 1.1 fault codes emitted by this closed profile; a parsed fault still resolves its QName and treats remote diagnostic text as untrusted.
const (
	faultCodeClient          = "Client"
	faultCodeMustUnderstand  = "MustUnderstand"
	faultCodeVersionMismatch = "VersionMismatch"
)

// Suggested prefix for emitted SOAP envelopes. Verification compares expanded names, never the sender's prefix spelling.
const (
	prefixSOAP = "env"
)

// Transport cache directive for sensitive SAML responses; shared writers must retain the same no-store/HTTP compatibility behavior.
const (
	cacheControlNoStore = "no-cache, no-store"
	cachePragma         = "no-cache"
)

const (
	// SOAPNamespace is the SOAP 1.1 envelope namespace required by SAML Bindings 3.2.
	SOAPNamespace = "http://schemas.xmlsoap.org/soap/envelope/"
	// SOAPNext targets the next SOAP processor.
	SOAPNext = "http://schemas.xmlsoap.org/soap/actor/next"
)

// SOAPFault describes a SOAP processing error, distinct from a SAML error status.
// Code is the expanded SOAP fault code and Message is untrusted remote text.
type SOAPFault struct {
	// Code is the expanded SOAP fault code.
	Code document.Name
	// Message is untrusted diagnostic text from the remote processor.
	Message string
}

// Error implements error without interpreting the remote fault text.
func (f *SOAPFault) Error() string { return "SOAP fault: " + f.Code.Local + ": " + f.Message }

// SOAPOptions bounds parsing and declares the headers handled by the caller.
// A mandatory header for this actor or SOAPNext that is not listed causes a
// MustUnderstand fault. Listed headers must still be semantically validated.
type SOAPOptions struct {
	// MaxBytes bounds the serialized envelope in bytes. Zero selects 2 MiB; the
	// maximum is 16 MiB.
	MaxBytes int
	// XMLLimits bounds envelope parsing. Zero fields use document defaults;
	// its byte limit is also capped by MaxBytes.
	XMLLimits document.Limits
	// Actor identifies the SOAP processor whose targeted mandatory headers must be
	// understood. Empty selects the ultimate receiver.
	Actor string
	// Understood lists at most 64 expanded header names handled by the caller.
	// Listing a name does not validate its contents.
	Understood []document.Name
}

// SOAPMessage retains the original envelope and namespace context. Parsing does
// not authenticate a SAML message. Payload must pass protocol verification.
type SOAPMessage struct {
	// doc retains the original immutable envelope and namespace context.
	doc *document.Document
	// body identifies the sole protocol payload within SOAP Body.
	body document.Element
	// headers retains the direct SOAP header elements without authenticating them.
	headers []document.Element
}

// Envelope returns the immutable original envelope.
func (m *SOAPMessage) Envelope() *document.Document { return m.doc }

// Headers returns a copy of the direct SOAP header list.
func (m *SOAPMessage) Headers() []document.Element {
	return append([]document.Element(nil), m.headers...)
}

// Payload returns an immutable subtree view, retaining original ancestor context
// for signature verification. WrapSOAP preserves it for forwarding. Use Envelope
// to serialize the original message; isolated XML output rejects inherited xml:*
// attributes that cannot be flattened onto a schema-constrained SAML root.
func (m *SOAPMessage) Payload(ctx context.Context) (*document.Document, error) {
	if ctx == nil || m == nil {
		return nil, ErrBinding
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return tree.ScopeDocument(m.doc, m.body)
}

// WrapSOAP puts one message into a SOAP 1.1 body and copies optional headers.
// Exclusive C14N signatures survive wrapping. Inclusive signatures must be made
// in the final namespace context; protocol.SignSOAP supports that operation.
func WrapSOAP(ctx context.Context, payload *document.Document, headers ...document.Element) (*document.Document, error) {
	if ctx == nil || payload == nil || !payload.Root().Valid() || len(headers) > maximumSOAPHeaders {
		return nil, ErrBinding
	}

	_, node := tree.Unwrap(payload.Root())
	prefix := soapPrefix(node)
	n := xmlutil.Node(prefix, SOAPNamespace, xmlNameEnvelope)

	n.NS = []tree.Namespace{{Prefix: prefix, URI: SOAPNamespace}}
	if len(headers) > 0 {
		h := xmlutil.Node(prefix, SOAPNamespace, xmlNameHeader)

		for _, e := range headers {
			if !e.Valid() || e.Name().Space == "" {
				return nil, ErrBinding
			}

			_, node := tree.Unwrap(e)
			xmlutil.Add(h, tree.ImportSubtree(node))
		}

		xmlutil.Add(n, h)
	}

	b := xmlutil.Node(prefix, SOAPNamespace, xmlNameBody)
	seen := map[document.Name]bool{}

	for ancestor := node.Parent; ancestor != nil; ancestor = ancestor.Parent {
		for _, attr := range ancestor.Attrs {
			if attr.Name.Space == tree.XMLNamespace && !seen[attr.Name] {
				b.Attrs = append(b.Attrs, attr)
				seen[attr.Name] = true
			}
		}
	}

	xmlutil.Add(b, tree.ImportSubtree(node))
	xmlutil.Add(n, b)

	return xmlutil.Document(ctx, n)
}

func soapPrefix(node *tree.Node) string {
	for ancestor := node.Parent; ancestor != nil; ancestor = ancestor.Parent {
		if ancestor.Name == xmlutil.Name(SOAPNamespace, xmlNameEnvelope) {
			return ancestor.Prefix
		}
	}

	for _, ns := range node.NS {
		if ns.URI == SOAPNamespace {
			return ns.Prefix
		}
	}

	return prefixSOAP
}

// DecodeSOAP parses a bounded SOAP 1.1 envelope and enforces a single body
// element. Unknown optional headers are retained. SOAP faults are returned as
// *SOAPFault errors; a valid remote fault also returns its message for forwarding.
// Other failures return no message. SAML status failures remain ordinary messages.
func DecodeSOAP(ctx context.Context, raw []byte, o SOAPOptions) (*SOAPMessage, error) {
	const (
		maximumSOAPEnvelopeChildren = 2
	)

	maxBytes, err := soapMaximum(o)
	if err != nil || len(raw) > maxBytes {
		return nil, ErrBinding
	}

	d, err := document.Parse(ctx, raw, xmlutil.XMLLimits(o.XMLLimits, maxBytes))
	if err != nil {
		return nil, err
	}

	r := d.Root()
	if r.Name() != xmlutil.Name(SOAPNamespace, xmlNameEnvelope) {
		return nil, soapFault(faultCodeVersionMismatch, "expected SOAP 1.1")
	}

	cs, err := xmlutil.Children(r)
	if err != nil || len(cs) == 0 || len(cs) > maximumSOAPEnvelopeChildren {
		return nil, soapFault(faultCodeClient, "invalid SOAP envelope")
	}

	m := &SOAPMessage{doc: d}
	i := 0

	if cs[0].Name() == xmlutil.Name(SOAPNamespace, xmlNameHeader) {
		m.headers, err = xmlutil.Children(cs[0])
		if err != nil || len(m.headers) > maximumSOAPHeaders {
			return nil, soapFault(faultCodeClient, "invalid SOAP header")
		}

		if err := validateSOAPHeaders(m.headers, o); err != nil {
			return nil, err
		}

		i++
	}

	if i != len(cs)-1 || cs[i].Name() != xmlutil.Name(SOAPNamespace, xmlNameBody) {
		return nil, soapFault(faultCodeClient, "missing SOAP body")
	}

	bs, err := xmlutil.Children(cs[i])
	if err != nil || len(bs) != 1 {
		return nil, soapFault(faultCodeClient, "SOAP body must contain one message")
	}

	m.body = bs[0]
	if m.body.Name() == xmlutil.Name(SOAPNamespace, xmlNameFault) {
		err := readSOAPFault(m.body)

		if _, ok := errors.AsType[*SOAPFault](err); ok {
			return m, err
		}

		return nil, err
	}

	if m.body.Name().Space != ProtocolNamespace {
		return nil, soapFault(faultCodeClient, "expected SAML protocol message")
	}

	return m, nil
}

// FaultSOAP constructs a SOAP 1.1 fault envelope suitable for an HTTP 500 response.
func FaultSOAP(ctx context.Context, f SOAPFault) (*document.Document, error) {
	const (
		faultCodeServer          = "Server"
		qualifiedSOAPFaultPrefix = prefixSOAP + ":"
	)

	if f.Code.Space != SOAPNamespace || !slices.Contains([]string{faultCodeVersionMismatch, faultCodeMustUnderstand, faultCodeClient, faultCodeServer}, f.Code.Local) || len(f.Message) > maximumSOAPFaultTextBytes {
		return nil, ErrBinding
	}

	n := xmlutil.Node(prefixSOAP, SOAPNamespace, xmlNameFault)
	n.NS = []tree.Namespace{{Prefix: prefixSOAP, URI: SOAPNamespace}}
	c := xmlutil.Node("", "", xmlNameFaultcode)
	xmlutil.Text(c, qualifiedSOAPFaultPrefix+f.Code.Local)
	xmlutil.Add(n, c)

	s := xmlutil.Node("", "", xmlNameFaultstring)
	xmlutil.Text(s, f.Message)
	xmlutil.Add(n, s)

	d, err := xmlutil.Document(ctx, n)
	if err != nil {
		return nil, err
	}

	return WrapSOAP(ctx, d)
}

// SOAPClient performs a SAML SOAP HTTP exchange to an application-trusted URL.
// Redirects are always rejected, including when Client normally follows them.
// Client transports may implement TLS/mTLS and deadlines. The default client has
// a 30 second timeout. AllowHTTP is intended for explicitly trusted local links.
type SOAPClient struct {
	// Client supplies the HTTP transport and timeout. Nil selects a 30-second
	// timeout. The client is copied and redirects are disabled.
	Client *http.Client
	// Options bounds outgoing envelopes and parsing of incoming SOAP messages.
	Options SOAPOptions
	// AllowHTTP permits explicitly configured plain HTTP endpoints. The default
	// requires HTTPS.
	AllowHTTP bool
}

// RoundTrip sends an already constructed SOAP envelope and returns its parsed
// response. A valid XML signature must still authenticate the returned payload.
func (c SOAPClient) RoundTrip(ctx context.Context, endpoint string, envelope *document.Document) (message *SOAPMessage, err error) {
	const (
		headerSOAPAction = "SoapAction"
		samlSOAPAction   = "\"http://www.oasis-open.org/committees/security\""
	)

	if ctx == nil || envelope == nil || envelope.Root().Name() != xmlutil.Name(SOAPNamespace, xmlNameEnvelope) || !profile.Endpoint(endpoint, c.AllowHTTP) {
		return nil, ErrBinding
	}

	maxBytes, err := soapMaximum(c.Options)
	if err != nil {
		return nil, err
	}

	raw, err := envelope.XML(ctx)
	if err != nil {
		return nil, err
	}

	if len(raw) > maxBytes {
		return nil, ErrBinding
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}

	req.Header.Set(lexicon.HeaderContentType, mediaTypeSOAPUTF8)
	req.Header.Set(headerSOAPAction, samlSOAPAction)
	req.Header.Set(headerCacheControl, cacheControlNoStore)
	req.Header.Set(headerPragma, cachePragma)

	client := soapHTTPClient(c.Client)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			message = nil
			err = errors.Join(err, closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		return nil, fmt.Errorf("%w: SOAP HTTP status %d", ErrBinding, resp.StatusCode)
	}

	media, _, err := mime.ParseMediaType(resp.Header.Get(lexicon.HeaderContentType))
	if err != nil || media != soapMediaType {
		return nil, ErrBinding
	}

	data, err := io.ReadAll(&streamio.Reader{Context: ctx, Source: resp.Body, Limit: int64(maxBytes), LimitError: ErrBinding})
	if err != nil {
		return nil, err
	}

	m, err := DecodeSOAP(ctx, data, c.Options)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrBinding
	}

	return m, nil
}

// ReadSOAPRequest checks the SOAP HTTP binding and reads at most its byte budget.
// It does not require any particular SOAPAction value (SAML Bindings 3.2.3).
func ReadSOAPRequest(ctx context.Context, r *http.Request, o SOAPOptions) (*SOAPMessage, error) {
	if ctx == nil || r == nil || nilcheck.IsNil(r.Body) || r.Method != http.MethodPost {
		return nil, soapFault(faultCodeClient, "expected SOAP POST")
	}

	media, _, err := mime.ParseMediaType(r.Header.Get(lexicon.HeaderContentType))
	if err != nil || media != soapMediaType {
		return nil, soapFault(faultCodeClient, "expected text/xml")
	}

	maxBytes, err := soapMaximum(o)
	if err != nil {
		return nil, err
	}

	raw, err := io.ReadAll(&streamio.Reader{Context: ctx, Source: r.Body, Limit: int64(maxBytes), LimitError: ErrBinding})
	if err != nil {
		return nil, err
	}

	return DecodeSOAP(ctx, raw, o)
}

// WriteSOAPResponse writes a SAML SOAP response with HTTP 200, or a SOAP Fault
// with HTTP 500. SAML failure statuses deliberately retain HTTP 200.
func WriteSOAPResponse(ctx context.Context, w http.ResponseWriter, envelope *document.Document) error {
	return WriteSOAPResponseWithOptions(ctx, w, envelope, SOAPOptions{})
}

// WriteSOAPResponseWithOptions additionally recognizes explicitly processed
// extension headers and applies their configured XML/byte limits.
func WriteSOAPResponseWithOptions(ctx context.Context, w http.ResponseWriter, envelope *document.Document, o SOAPOptions) error {
	const (
		cacheControlPrivate = "no-cache, no-store, must-revalidate, private"
		headerETag          = "ETag"
		headerLastModified  = "Last-Modified"
	)

	if ctx == nil || nilcheck.IsNil(w) || envelope == nil {
		return ErrBinding
	}

	raw, err := envelope.XML(ctx)
	if err != nil {
		return err
	}

	message, err := DecodeSOAP(ctx, raw, o)

	var fault *SOAPFault

	status := http.StatusOK

	if err != nil {
		if message == nil || !errors.As(err, &fault) {
			return err
		}

		status = http.StatusInternalServerError
	}

	w.Header().Set(lexicon.HeaderContentType, mediaTypeSOAPUTF8)
	w.Header().Set(headerCacheControl, cacheControlPrivate)
	w.Header().Set(headerPragma, cachePragma)
	w.Header().Del(headerETag)
	w.Header().Del(headerLastModified)
	w.WriteHeader(status)

	n, err := w.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}

	return err
}

func soapMaximum(o SOAPOptions) (int, error) {
	const (
		defaultSOAPBytes = 2 << 20
		maximumSOAPBytes = 16 << 20
	)

	n := o.MaxBytes
	if n == 0 {
		n = defaultSOAPBytes
	}

	if n < 1 || n > maximumSOAPBytes || len(o.Understood) > maximumSOAPHeaders {
		return 0, ErrBinding
	}

	return n, nil
}

func soapHTTPClient(source *http.Client) *http.Client {
	const (
		defaultHTTPTimeout = 30 * time.Second
	)

	client := http.Client{Timeout: defaultHTTPTimeout}
	if source != nil {
		client = *source
	}

	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &client
}

func soapFault(code, message string) *SOAPFault {
	return &SOAPFault{Code: xmlutil.Name(SOAPNamespace, code), Message: message}
}

func readSOAPFault(e document.Element) error {
	const (
		maximumSOAPFaultChildren  = 4
		maximumSOAPFaultCodeBytes = 256
		minimumSOAPFaultChildren  = 2
		xmlNameDetail             = "detail"
		xmlNameFaultactor         = "faultactor"
	)

	cs, err := xmlutil.Children(e)
	if err != nil || len(cs) < minimumSOAPFaultChildren || len(cs) > maximumSOAPFaultChildren || cs[0].Name() != xmlutil.Name("", xmlNameFaultcode) || cs[1].Name() != xmlutil.Name("", xmlNameFaultstring) {
		return ErrBinding
	}

	code, err := xmlutil.Simple(cs[0], maximumSOAPFaultCodeBytes)
	if err != nil {
		return ErrBinding
	}

	message, err := xmlutil.Simple(cs[1], maximumSOAPFaultTextBytes)
	if err != nil {
		return ErrBinding
	}

	prefix, local, ok := strings.Cut(strings.TrimSpace(code), ":")
	if !ok {
		local = prefix
		prefix = ""
	}

	if !tree.NCName(local) || prefix != "" && !tree.NCName(prefix) {
		return ErrBinding
	}

	ns, ok := cs[0].Namespace(prefix)
	if !ok && prefix != "" {
		return ErrBinding
	}

	position := 2
	if position < len(cs) && cs[position].Name() == xmlutil.Name("", xmlNameFaultactor) {
		actor, err := xmlutil.Simple(cs[position], maximumSOAPFaultTextBytes)
		if err != nil || !profile.URI(actor) {
			return ErrBinding
		}

		position++
	}

	if position < len(cs) && cs[position].Name() == xmlutil.Name("", xmlNameDetail) {
		position++
	}

	if position != len(cs) {
		return ErrBinding
	}

	return &SOAPFault{Code: xmlutil.Name(ns, local), Message: message}
}

func validateSOAPHeaders(headers []document.Element, o SOAPOptions) error {
	const (
		soapActorAttribute          = "actor"
		soapBooleanFalse            = "0"
		soapBooleanTrue             = "1"
		soapMustUnderstandAttribute = "mustUnderstand"
	)

	for _, h := range headers {
		if h.Name().Space == "" {
			return soapFault(faultCodeClient, "unqualified SOAP header")
		}

		must, present := h.Attribute(xmlutil.Name(SOAPNamespace, soapMustUnderstandAttribute))
		if present && must != soapBooleanFalse && must != soapBooleanTrue {
			return soapFault(faultCodeClient, "invalid mustUnderstand")
		}

		actor, _ := h.Attribute(xmlutil.Name(SOAPNamespace, soapActorAttribute))
		if must != soapBooleanTrue || actor != "" && actor != SOAPNext && actor != o.Actor {
			continue
		}

		known := false

		for _, name := range o.Understood {
			if name == h.Name() {
				known = true
				break
			}
		}

		if !known {
			return soapFault(faultCodeMustUnderstand, "unsupported mandatory SOAP header")
		}
	}

	return nil
}
