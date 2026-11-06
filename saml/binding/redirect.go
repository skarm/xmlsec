package binding

import (
	"bufio"
	"compress/flate"
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/saml/internal/profile"

	"github.com/skarm/xmlsec/document"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/xmldsig"
)

// Decoded Redirect signature byte ceiling shared by Base64 decoding and encoded-query preflight; canonical XML has an independent budget.
const (
	maximumRedirectSignatureBytes = 2048
)

// Poll cancellation every 4096 encoded query octets. This bit mask bounds uninterrupted scanning work; it is not a query-size limit.
const (
	contextPollMask = 4095
)

// Retain at most four idle DEFLATE writers. Busy callers never wait for a cache slot, and Reset detaches the previous output.
const (
	idleRedirectCompressors = 4
)

// SigAlg is a signed Redirect query field and a forbidden collision in Artifact URLs; never normalize the received signed octets.
const (
	fieldSignatureAlgorithm = "SigAlg"
)

// The optional Redirect codec declaration must name the fixed raw-DEFLATE encoding; it never enables an arbitrary decompressor.
const (
	fieldSAMLEncoding = "SAMLEncoding"
)

// These separators are part of the exact Redirect signature input. Sign and verify retain field order and original encoded octets rather than normalizing the query.
const (
	relayQueryPrefix              = "&" + fieldRelayState + "="
	signatureAlgorithmQueryPrefix = "&" + fieldSignatureAlgorithm + "="
)

const (
	// Opaque HTTP binding correlation data, never a return URL or an identity;
	// all codecs apply the shared byte ceiling before publishing the value.
	fieldRelayState = "RelayState"
	// Redirect query field, distinct from the XMLDSig element of the same name.
	// This field is excluded from the exact octets that its value authenticates.
	nameSignature = "Signature"
)

// ProtocolNamespace is the SAML 2.0 protocol namespace URI.
const ProtocolNamespace = lexicon.NamespaceSAMLProtocol

// RedirectBinding is the SAML HTTP-Redirect binding URI.
const RedirectBinding = lexicon.SAMLBindingHTTPRedirect

// DeflateEncoding is the SAML raw DEFLATE encoding URI.
const DeflateEncoding = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"

var (
	// ErrEncoding reports invalid SAML Redirect encoding.
	ErrEncoding = errors.New("invalid SAML Redirect encoding")
	// ErrPolicy reports SAML Redirect policy violation.
	ErrPolicy = errors.New("SAML Redirect policy violation")
)

// Keep at most four idle compressors; bursts never wait for an idle writer.
// Reset detaches the previous output and starts an independent DEFLATE stream.
// The retained compression workspace is bounded independently of caller input.
//
//nolint:gochecknoglobals // Bounded workspace reuse, not a shared protocol policy.
var redirectCompressors = make(chan *flate.Writer, idleRedirectCompressors)

// Kind identifies the SAMLRequest or SAMLResponse field in a supported binding.
type Kind string

const (
	// Request identifies a SAMLRequest binding field.
	Request Kind = "SAMLRequest"
	// Response identifies a SAMLResponse binding field.
	Response Kind = "SAMLResponse"
)

// Options selects Redirect signature policy and limits for the query, decompression
// and XML parsing.
type Options struct {
	// SignatureMethod defaults to RSA-SHA256 for creation. Verification reads SigAlg from
	// the query.
	SignatureMethod string
	// Policy sets accepted signature algorithms and key limits. Zero selects
	// xmldsig.DefaultPolicy.
	Policy xmldsig.Policy
	// MaxQueryBytes bounds the encoded query; zero uses 128 KiB.
	MaxQueryBytes int
	// MaxCompressedBytes bounds the compressed message; zero uses 64 KiB.
	MaxCompressedBytes int
	// MaxMessageBytes bounds the decompressed XML message; zero uses 2 MiB.
	MaxMessageBytes int
	// XMLLimits bounds XML parsing and is intersected with MaxMessageBytes.
	// Zero selects document.DefaultLimits.
	XMLLimits document.Limits
}

// RedirectResult authenticates the exact received binding bytes with an explicitly
// trusted key. SSO acceptance still requires protocol validation and replay checks;
// this result is not a VerifiedAssertion.
type RedirectResult struct {
	doc      *document.Document
	kind     Kind
	relay    string
	method   string
	hasRelay bool
}

type queryPart struct {
	raw   string
	value string
	size  int
}

// VerifyRedirect authenticates the original URL-encoded values before DEFLATE
// or XML parsing. Do not pass url.Values.Encode(): re-encoding loses signed bytes.
// Unknown nonduplicate query parameters are ignored and never returned as trusted.
func VerifyRedirect(ctx context.Context, rawQuery string, key crypto.PublicKey, opt Options) (*RedirectResult, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	opt, err := normalize(opt)
	if err != nil {
		return nil, err
	}

	if len(rawQuery) > opt.MaxQueryBytes {
		return nil, ErrPolicy
	}

	params, err := parseQuery(ctx, rawQuery)
	if err != nil {
		return nil, err
	}

	request, hasRequest := params[string(Request)]

	response, hasResponse := params[string(Response)]
	if hasRequest == hasResponse {
		return nil, fmt.Errorf("%w: exactly one SAMLRequest/SAMLResponse required", ErrEncoding)
	}

	kind, msg := Request, request
	if hasResponse {
		kind, msg = Response, response
	}

	sm, ok := params[fieldSignatureAlgorithm]
	if !ok || sm.value == "" {
		return nil, ErrEncoding
	}

	sv, ok := params[nameSignature]
	if !ok {
		return nil, ErrEncoding
	}

	if enc, ok := params[fieldSAMLEncoding]; ok && enc.value != DeflateEncoding {
		return nil, ErrPolicy
	}

	relay, hasRelay := params[fieldRelayState]
	if hasRelay && len(relay.value) > profile.HTTPRelayStateMaxBytes {
		return nil, ErrPolicy
	}

	signedParts := []io.Reader{strings.NewReader(string(kind) + "="), strings.NewReader(msg.raw)}
	if hasRelay {
		signedParts = append(signedParts, strings.NewReader(relayQueryPrefix), strings.NewReader(relay.raw))
	}

	signedParts = append(signedParts, strings.NewReader(signatureAlgorithmQueryPrefix), strings.NewReader(sm.raw))

	signature, err := decodeBase64(sv.value, maximumRedirectSignatureBytes)
	if err != nil {
		return nil, err
	}

	if err = xmldsig.VerifyMessageReader(ctx, io.MultiReader(signedParts...), signature, key, sm.value, opt.Policy); err != nil {
		return nil, err
	}

	if msg.size > base64.StdEncoding.EncodedLen(opt.MaxCompressedBytes) {
		return nil, ErrEncoding
	}

	value := &redirectBase64Reader{source: msg.raw}
	decoder := base64.NewDecoder(base64.StdEncoding.Strict(), value)
	source := bufio.NewReader(&streamio.Reader{Context: ctx, Source: decoder, Limit: int64(opt.MaxCompressedBytes), LimitError: ErrEncoding})
	inflater := flate.NewReader(source)
	d, readErr := document.ParseReader(ctx, &streamio.Reader{Context: ctx, Source: inflater, Limit: int64(opt.MaxMessageBytes), LimitError: ErrPolicy}, opt.XMLLimits)

	closeErr := inflater.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncoding, err)
	}

	// Only bare EOF proves that the compressed input ended without a source failure.
	if _, err := source.Peek(1); err != io.EOF {
		return nil, errors.Join(ErrEncoding, err)
	}

	if value.source != "" || value.size%4 != 0 || value.padding > 2 {
		return nil, ErrEncoding
	}

	actual, err := kindOf(d)
	if err != nil || actual != kind {
		return nil, ErrEncoding
	}

	for _, child := range d.Root().Children() {
		if child.Name() == (document.Name{Space: xmldsig.Namespace, Local: nameSignature}) {
			return nil, fmt.Errorf("%w: protocol root Signature must be removed in Redirect binding", ErrEncoding)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &RedirectResult{doc: d, kind: kind, relay: relay.value, hasRelay: hasRelay, method: sm.value}, nil
}

// Document returns the immutable document snapshot.
func (r *RedirectResult) Document() *document.Document {
	if r == nil {
		return nil
	}

	return r.doc
}

// Kind returns Request or Response for the authenticated Redirect message.
func (r *RedirectResult) Kind() Kind {
	if r == nil {
		return ""
	}

	return r.kind
}

// RelayState returns the opaque relay state, with a separate presence flag where
// applicable.
func (r *RedirectResult) RelayState() (string, bool) {
	if r == nil {
		return "", false
	}

	return r.relay, r.hasRelay
}

// SignatureMethod returns the authenticated signature algorithm URI.
func (r *RedirectResult) SignatureMethod() string {
	if r == nil {
		return ""
	}

	return r.method
}

// SignRedirect returns the raw query component, NOT an endpoint URL. The endpoint
// must come from trusted configuration/metadata, not an arbitrary RelayState.
// Any direct ds:Signature on the protocol root is removed in a private snapshot;
// nested signatures remain. RelayState nil and a present empty string differ.
func SignRedirect(ctx context.Context, d *document.Document, kind Kind, relay *string, signer crypto.Signer, opt Options) (string, error) {
	const (
		signatureQueryPrefix = "&" + nameSignature + "="
	)

	if ctx == nil {
		return "", ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	opt, err := normalize(opt)
	if err != nil {
		return "", err
	}

	actual, err := kindOf(d)
	if err != nil {
		return "", err
	}

	if kind != actual {
		return "", ErrEncoding
	}

	if relay != nil && len(*relay) > profile.HTTPRelayStateMaxBytes {
		return "", fmt.Errorf("%w: RelayState exceeds 80 bytes", ErrPolicy)
	}

	// A shallow private root suffices: serialization only reads retained nodes.
	root := *tree.Root(d)

	root.Children = make([]*tree.Node, 0, len(root.Children))
	for _, n := range tree.Root(d).Children {
		if n.Kind == tree.ElementNode && n.Name == (document.Name{Space: xmldsig.Namespace, Local: nameSignature}) {
			continue
		}

		root.Children = append(root.Children, n)
	}

	children := append([]*tree.Node(nil), tree.Children(d)...)
	for i, node := range children {
		if node == tree.Root(d) {
			children[i] = &root
			break
		}
	}

	snapshot := tree.FromNodes(children, tree.Policy(d))

	var encoded strings.Builder

	queryWriter := &streamio.Writer{Context: ctx, Target: &encoded, Limit: int64(opt.MaxQueryBytes), LimitError: ErrPolicy}
	if _, err := queryWriter.WriteString(string(kind) + "="); err != nil {
		return "", err
	}

	base64Writer := base64.NewEncoder(base64.StdEncoding, &queryBase64Writer{dst: queryWriter})
	compressed := &streamio.Writer{Context: ctx, Target: base64Writer, Limit: int64(opt.MaxCompressedBytes), LimitError: ErrPolicy}

	compressor, err := redirectCompressor(compressed)
	if err != nil {
		return "", err
	}

	defer releaseRedirectCompressor(compressor)

	if _, err := snapshot.WriteXML(ctx, compressor, opt.MaxMessageBytes); err != nil {
		_ = compressor.Close()

		if errors.Is(err, document.ErrLimit) {
			return "", errors.Join(ErrPolicy, err)
		}

		return "", err
	}

	if err := compressor.Close(); err != nil {
		return "", err
	}

	if err := base64Writer.Close(); err != nil {
		return "", err
	}

	if relay != nil {
		if _, err := queryWriter.WriteString(relayQueryPrefix + url.QueryEscape(*relay)); err != nil {
			return "", err
		}
	}

	if _, err := queryWriter.WriteString(signatureAlgorithmQueryPrefix + url.QueryEscape(opt.SignatureMethod)); err != nil {
		return "", err
	}

	signature, err := xmldsig.SignMessageReader(ctx, strings.NewReader(encoded.String()), signer, opt.SignatureMethod, opt.Policy)
	if err != nil {
		return "", err
	}

	if _, err := queryWriter.WriteString(signatureQueryPrefix + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))); err != nil {
		return "", err
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	query := encoded.String()

	return query, nil
}

func parseQuery(ctx context.Context, raw string) (map[string]queryPart, error) {
	const (
		firstURIASCII             = 0x21
		lastURIASCII              = 0x7e
		maximumRedirectParameters = 32
	)

	for i := range len(raw) {
		if i&contextPollMask == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		if raw[i] < firstURIASCII || raw[i] > lastURIASCII {
			return nil, fmt.Errorf("%w: query must be ASCII URI octets", ErrEncoding)
		}
	}

	out := make(map[string]queryPart)

	for count := 0; ; count++ {
		if count == maximumRedirectParameters {
			return nil, ErrPolicy
		}

		part, rest, more := strings.Cut(raw, "&")

		name, value, ok := strings.Cut(part, "=")
		if !ok || name == "" || strings.ContainsAny(name, "%+") || strings.ContainsAny(part, ";#\r\n\t ") {
			return nil, ErrEncoding
		}

		if _, found := out[name]; found {
			return nil, fmt.Errorf("%w: duplicate query parameter", ErrEncoding)
		}

		size, err := queryValueSize(ctx, value)
		if err != nil {
			return nil, err
		}

		decoded, err := queryMetadata(name, value, size)
		if err != nil {
			return nil, err
		}

		out[name] = queryPart{raw: value, value: decoded, size: size}

		if !more {
			break
		}

		raw = rest
	}

	return out, nil
}

func queryMetadata(name, raw string, size int) (string, error) {
	const (
		maximumEncodingURIBytes = 4096
	)

	switch name {
	case fieldRelayState:
		if size > profile.HTTPRelayStateMaxBytes {
			return "", ErrPolicy
		}
	case nameSignature:
		if size > base64.StdEncoding.EncodedLen(maximumRedirectSignatureBytes) {
			return "", ErrEncoding
		}
	case fieldSignatureAlgorithm:
		if size > maximumEncodingURIBytes {
			return "", ErrPolicy
		}
	case fieldSAMLEncoding:
		if size != len(DeflateEncoding) {
			return "", ErrPolicy
		}
	default:
		return "", nil
	}
	// Unescaped metadata would otherwise retain the entire received query
	// through a short substring in RedirectResult.
	if !strings.ContainsAny(raw, "%+") {
		return strings.Clone(raw), nil
	}

	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", errors.Join(ErrEncoding, err)
	}

	return decoded, nil
}

func queryValueSize(ctx context.Context, value string) (int, error) {
	size := 0

	for i := 0; i < len(value); i++ {
		if i&contextPollMask == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}

		if value[i] == '%' {
			if i+2 >= len(value) || formHex(value[i+1]) < 0 || formHex(value[i+2]) < 0 {
				return 0, ErrEncoding
			}

			i += 2
		}

		size++
	}

	return size, nil
}

func decodeBase64(value string, maximum int) ([]byte, error) {
	if strings.ContainsAny(value, lexicon.XMLWhitespace) || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, ErrEncoding
	}

	out, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(out) > maximum {
		return nil, ErrEncoding
	}

	return out, nil
}

func redirectCompressor(dst io.Writer) (*flate.Writer, error) {
	select {
	case writer := <-redirectCompressors:
		writer.Reset(dst)
		return writer, nil
	default:
		return flate.NewWriter(dst, flate.DefaultCompression)
	}
}

func releaseRedirectCompressor(writer *flate.Writer) {
	writer.Reset(io.Discard)

	select {
	case redirectCompressors <- writer:
	default:
	}
}

func normalize(o Options) (Options, error) {
	const (
		defaultRedirectCompressedBytes = 64 << 10
		defaultRedirectMessageBytes    = 2 << 20
		defaultRedirectQueryBytes      = 128 << 10
		maximumRedirectCompressedBytes = 2 << 20
		maximumRedirectMessageBytes    = 16 << 20
		maximumRedirectQueryBytes      = 4 << 20
	)

	if o.MaxQueryBytes == 0 {
		o.MaxQueryBytes = defaultRedirectQueryBytes
	}

	if o.MaxCompressedBytes == 0 {
		o.MaxCompressedBytes = defaultRedirectCompressedBytes
	}

	if o.MaxMessageBytes == 0 {
		o.MaxMessageBytes = defaultRedirectMessageBytes
	}

	if o.MaxQueryBytes < 1 || o.MaxQueryBytes > maximumRedirectQueryBytes || o.MaxCompressedBytes < 1 || o.MaxCompressedBytes > maximumRedirectCompressedBytes || o.MaxMessageBytes < 1 || o.MaxMessageBytes > maximumRedirectMessageBytes {
		return o, ErrPolicy
	}

	if o.XMLLimits == (document.Limits{}) {
		o.XMLLimits = document.DefaultLimits()
	}

	if o.XMLLimits.MaxBytes > o.MaxMessageBytes {
		o.XMLLimits.MaxBytes = o.MaxMessageBytes
	}

	if err := o.XMLLimits.Validate(); err != nil {
		return o, err
	}

	if o.SignatureMethod == "" {
		o.SignatureMethod = xmldsig.RSASHA256
	}

	return o, nil
}

func kindOf(d *document.Document) (Kind, error) {
	const (
		xmlNameSubjectQuery = "SubjectQuery"
	)

	n := d.Root().Name()
	if n.Space != ProtocolNamespace {
		return "", fmt.Errorf("%w: expected SAML 2.0 protocol root", ErrEncoding)
	}

	switch n.Local {
	case lexicon.SAMLElementAuthnRequest, lexicon.SAMLElementLogoutRequest, lexicon.SAMLElementArtifactResolve, lexicon.SAMLElementManageNameIDRequest, lexicon.SAMLElementNameIDMappingRequest, lexicon.SAMLElementAuthnQuery, lexicon.SAMLElementAttributeQuery, lexicon.SAMLElementAuthzDecisionQuery, lexicon.SAMLElementAssertionIDRequest, xmlNameSubjectQuery:
		return Request, nil
	case lexicon.SAMLElementResponse, lexicon.SAMLElementLogoutResponse, lexicon.SAMLElementArtifactResponse, lexicon.SAMLElementManageNameIDResponse, lexicon.SAMLElementNameIDMappingResponse:
		return Response, nil
	default:
		return "", fmt.Errorf("%w: unsupported protocol message", ErrPolicy)
	}
}

// redirectBase64Reader decodes URL escapes without collecting a complete field.
// It rejects all whitespace and data after Base64 padding, even across reads.
type redirectBase64Reader struct {
	source  string
	size    int
	padding int
}

func (r *redirectBase64Reader) Read(dst []byte) (int, error) {
	used := 0
	for len(r.source) > 0 && used < len(dst) {
		c := r.source[0]

		r.source = r.source[1:]

		switch c {
		case '%':
			if len(r.source) < 2 || formHex(r.source[0]) < 0 || formHex(r.source[1]) < 0 {
				return used, ErrEncoding
			}

			c = byte(formHex(r.source[0])&15)<<4 | byte(formHex(r.source[1])&15)
			r.source = r.source[2:]
		case '+':
			c = ' '
		}

		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			return used, ErrEncoding
		}

		r.size++
		if c == '=' {
			r.padding++
		} else if r.padding > 0 {
			return used, ErrEncoding
		}

		dst[used] = c
		used++
	}

	if used == 0 && len(dst) > 0 {
		if r.size%4 != 0 || r.padding > 2 {
			return 0, ErrEncoding
		}

		return 0, io.EOF
	}

	return used, nil
}
