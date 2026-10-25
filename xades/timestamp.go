package xades

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
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

const (
	encodingDER = "http://uri.etsi.org/01903/v1.2.2#DER"
	encodingBER = "http://uri.etsi.org/01903/v1.2.2#BER"
)

// ErrTimestamp reports XAdES signature timestamp validation failed.
var ErrTimestamp = errors.New("XAdES signature timestamp validation failed")

// TimedOptions builds on the narrow basic-enveloped profile, and requires at
// least one valid SignatureTimeStamp. It does not establish trust in the primary
// signer certificate; use Validator or an explicit pki.Verifier for that.
type TimedOptions struct {
	Basic VerifyOptions
	// TSA supplies the immutable trusted timestamp verifier.
	TSA *timestamp.Verifier
	// At is the explicit trusted time used by this operation.
	At       time.Time
	Evidence pki.Evidence
	// MaxTimestamps bounds total timestamp tokens, including tokens sharing a container;
	// default 8, maximum 32.
	MaxTimestamps int
	// MaxTokenBytes bounds each timestamp token; default 4 MiB, maximum 16 MiB.
	MaxTokenBytes int
}

// TimedResult is an immutable basic XAdES signature with authenticated SignatureTimeStamp
// tokens.
type TimedResult struct {
	basic      *BasicResult
	timestamps []*timestamp.Result
}

// VerifyTimedEnveloped verifies the closed basic signature and all supplied
// SignatureTimeStamp tokens.
func VerifyTimedEnveloped(ctx context.Context, doc *document.Document, selected document.Element, certificateDER []byte, o TimedOptions) (*TimedResult, error) {
	o, e := normalizeTimed(o)
	if e != nil {
		return nil, e
	}

	basic, e := verifyBasicEnveloped(ctx, doc, selected, certificateDER, o.Basic, true)
	if e != nil {
		return nil, e
	}

	tokens, e := verifySignatureTimestamps(ctx, selected, o, false)
	if e != nil {
		return nil, e
	}

	return &TimedResult{basic: basic, timestamps: tokens}, nil
}

// Basic returns the immutable basic XAdES result.
func (r *TimedResult) Basic() *BasicResult {
	if r == nil {
		return nil
	}

	return r.basic
}

// Timestamps returns an owned slice of immutable verified timestamp results.
func (r *TimedResult) Timestamps() []*timestamp.Result {
	if r == nil {
		return nil
	}

	return append([]*timestamp.Result(nil), r.timestamps...)
}

// AddTimestampOptions selects timestamp validation, request and canonicalization options.
type AddTimestampOptions struct {
	Validation TimedOptions
	Request    timestamp.RequestOptions
	// Canonicalization defaults to Exclusive C14N and is serialized explicitly.
	Canonicalization string
}

// AddSignatureTimestamp verifies the original XML and every prior timestamp,
// obtains a nonce-bound response through Transport, and appends a timestamp in a
// NEW snapshot. SignatureValue is canonicalized as an ELEMENT, not decoded.
// All XML and timestamps are reverified after serialization. External TSA work
// cannot be rolled back if subsequent local verification fails.
func AddSignatureTimestamp(ctx context.Context, doc *document.Document, selected document.Element, certificateDER []byte, transport timestamp.Transport, o AddTimestampOptions) (*document.Document, *TimedResult, error) {
	validation, e := normalizeTimed(o.Validation)
	if e != nil {
		return nil, nil, e
	}

	if _, e = verifyBasicEnveloped(ctx, doc, selected, certificateDER, validation.Basic, true); e != nil {
		return nil, nil, e
	}

	existing, e := verifySignatureTimestamps(ctx, selected, validation, true)
	if e != nil {
		return nil, nil, e
	}

	if len(existing) >= validation.MaxTimestamps {
		return nil, nil, ErrTimestamp
	}

	method := o.Canonicalization
	if method == "" {
		method = c14n.Exclusive
	}

	imprint, e := canonicalImprint(ctx, selected, method, 1<<20, o.Request.Hash)
	if e != nil {
		return nil, nil, e
	}

	request, e := timestamp.CreateImprintRequest(imprint, o.Request)
	if e != nil {
		return nil, nil, e
	}

	token, e := validation.TSA.Fetch(ctx, transport, request, validation.At, validation.Evidence)
	if e != nil {
		return nil, nil, e
	}

	if token.Token().Size() > validation.MaxTokenBytes {
		return nil, nil, ErrTimestamp
	}

	return appendVerifiedTimestamp(ctx, doc, selected, certificateDER, method, token.Token(), validation)
}

// AttachSignatureTimestamp imports an already obtained CMS token. It verifies
// the token against this SignatureValue and current TSA policy; it does not
// claim request/response nonce correlation when the original request is absent.
func AttachSignatureTimestamp(ctx context.Context, doc *document.Document, selected document.Element, certificateDER, tokenDER []byte, o AddTimestampOptions) (*document.Document, *TimedResult, error) {
	validation, e := normalizeTimed(o.Validation)
	if e != nil {
		return nil, nil, e
	}

	if len(tokenDER) > validation.MaxTokenBytes {
		return nil, nil, ErrTimestamp
	}

	if _, e = verifyBasicEnveloped(ctx, doc, selected, certificateDER, validation.Basic, true); e != nil {
		return nil, nil, e
	}

	existing, e := verifySignatureTimestamps(ctx, selected, validation, true)
	if e != nil {
		return nil, nil, e
	}

	if len(existing) >= validation.MaxTimestamps {
		return nil, nil, ErrTimestamp
	}

	method := o.Canonicalization
	if method == "" {
		method = c14n.Exclusive
	}

	token, e := timestamp.ParseToken(ctx, tokenDER)
	if e != nil {
		return nil, nil, e
	}

	imprint, e := canonicalImprint(ctx, selected, method, 1<<20, token.UnverifiedInfo().Imprint().Hash)
	if e != nil {
		return nil, nil, e
	}

	verified, e := validation.TSA.Verify(ctx, token, timestamp.Expectation{Imprint: imprint}, validation.At, validation.Evidence)
	if e != nil {
		return nil, nil, e
	}

	return appendVerifiedTimestamp(ctx, doc, selected, certificateDER, method, verified.Token(), validation)
}

func normalizeTimed(o TimedOptions) (TimedOptions, error) {
	if o.TSA == nil || o.At.IsZero() {
		return o, ErrTimestamp
	}

	return normalizeTimedLimits(o)
}

func normalizeTimedLimits(o TimedOptions) (TimedOptions, error) {
	if o.MaxTimestamps == 0 {
		o.MaxTimestamps = 8
	}

	if o.MaxTokenBytes == 0 {
		o.MaxTokenBytes = 4 << 20
	}

	if o.MaxTimestamps < 1 || o.MaxTimestamps > 32 || o.MaxTokenBytes < 1 || o.MaxTokenBytes > 16<<20 {
		return o, ErrTimestamp
	}

	return o, nil
}

func qualifying(sig document.Element) (document.Element, error) {
	o, e := childNamed(sig, ds("Object"))
	if e != nil {
		return document.Element{}, e
	}

	return childNamed(o, name("QualifyingProperties"))
}

func unsignedProperties(sig document.Element) (document.Element, error) {
	qp, e := qualifying(sig)
	if e != nil {
		return document.Element{}, e
	}

	cs := qp.Children()
	if len(cs) == 1 {
		return document.Element{}, nil
	}

	if len(cs) != 2 || cs[1].Name() != name("UnsignedProperties") || optionalID(cs[1]) != nil {
		return document.Element{}, ErrProfile
	}

	f, e := children(cs[1], name("UnsignedSignatureProperties"))
	if e != nil || optionalID(f[0]) != nil {
		return document.Element{}, ErrProfile
	}

	return f[0], nil
}

func optionalID(e document.Element) error {
	a := e.Attributes()
	if len(a) == 0 {
		return nil
	}

	if len(a) != 1 || a[0].Name != (document.Name{Local: "Id"}) || !tree.NCName(a[0].Value) {
		return ErrProfile
	}

	return nil
}

func timestampCanonicalization(s string) bool {
	switch s {
	case c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments:
		return true
	}

	return false
}

func writeCanonicalValue(ctx context.Context, dst io.Writer, sig document.Element, method string, maximum int) error {
	v, e := childNamed(sig, ds("SignatureValue"))
	if e != nil {
		return e
	}

	if !timestampCanonicalization(method) {
		return ErrTimestamp
	}

	return c14n.WriteElement(ctx, dst, v, c14n.Options{Algorithm: method, MaxOutputBytes: maximum})
}

// timestampImprint feeds canonical bytes directly into the requested digest.
func timestampImprint(h crypto.Hash, write func(io.Writer) error) (timestamp.Imprint, error) {
	if h == 0 {
		h = crypto.SHA256
	}

	if h != crypto.SHA256 && h != crypto.SHA384 && h != crypto.SHA512 {
		return timestamp.Imprint{}, ErrTimestamp
	}

	digest := h.New()
	if err := write(digest); err != nil {
		return timestamp.Imprint{}, err
	}

	return timestamp.Imprint{Hash: h, Digest: digest.Sum(nil)}, nil
}

func canonicalImprint(ctx context.Context, sig document.Element, method string, maximum int, h crypto.Hash) (timestamp.Imprint, error) {
	return timestampImprint(h, func(dst io.Writer) error { return writeCanonicalValue(ctx, dst, sig, method, maximum) })
}

// parseTimeStamp supports the implicit mechanism and only explicitly named C14N
// algorithms, as required when generating/augmenting current EN 319 132-1 data.
// XMLTimeStamp, Include, transform parameters and unknown encodings fail closed.
func parseTimeStamp(ctx context.Context, e document.Element, maximum int) (string, [][]byte, error) {
	if optionalID(e) != nil {
		return "", nil, ErrProfile
	}

	cs := e.Children()
	if len(cs) < 2 || len(cs) > 33 || cs[0].Name() != ds("CanonicalizationMethod") || attrs(cs[0], "Algorithm") != nil || len(cs[0].Children()) != 0 || !xmlSpace(cs[0].Text()) {
		return "", nil, ErrTimestamp
	}

	method := localAttribute(cs[0], "Algorithm")
	if !timestampCanonicalization(method) {
		return "", nil, ErrTimestamp
	}

	var tokens [][]byte

	for _, c := range cs[1:] {
		if c.Name() != name("EncapsulatedTimeStamp") || len(c.Children()) != 0 {
			return "", nil, ErrTimestamp
		}

		for _, a := range c.Attributes() {
			if a.Name.Space != "" {
				return "", nil, ErrProfile
			}

			switch a.Name.Local {
			case "Id":
				if !tree.NCName(a.Value) {
					return "", nil, ErrProfile
				}
			case "Encoding":
				if a.Value != encodingDER && a.Value != encodingBER {
					return "", nil, ErrTimestamp
				}
			default:
				return "", nil, ErrProfile
			}
		}

		raw, e := decodeElementBase64(ctx, c, maximum*2, maximum)
		if e != nil {
			return "", nil, errors.Join(ErrTimestamp, e)
		}

		if len(raw) == 0 {
			return "", nil, ErrTimestamp
		}

		tokens = append(tokens, raw)
	}

	return method, tokens, nil
}

func verifySignatureTimestamps(ctx context.Context, sig document.Element, o TimedOptions, allowEmpty bool) ([]*timestamp.Result, error) {
	return verifySignatureTimestampsMode(ctx, sig, o, allowEmpty, false)
}

func verifySignatureTimestampsMode(ctx context.Context, sig document.Element, o TimedOptions, allowEmpty, preservation bool) ([]*timestamp.Result, error) {
	usp, e := unsignedProperties(sig)
	if e != nil {
		return nil, e
	}

	if !usp.Valid() {
		if allowEmpty {
			return nil, nil
		}

		return nil, ErrTimestamp
	}

	props := usp.Children()
	if len(props) == 0 || (!preservation && len(props) > o.MaxTimestamps) || len(props) > 140 {
		return nil, ErrTimestamp
	}

	var out []*timestamp.Result

	if returned1Value, matchedBranch := verifySignatureTimestampsModeProps(ctx, props, preservation, &o, &out, &sig); matchedBranch {
		return nil, returned1Value
	}

	if len(out) == 0 && !allowEmpty {
		return nil, ErrTimestamp
	}

	return out, nil
}

// unsignedDraft owns only the edited header and ancestor path. Existing signed
// and unsigned children stay borrowed until Reparse publishes an independent tree.
func unsignedDraft(ctx context.Context, doc *document.Document, signature document.Element) (*document.Document, *tree.Node, error) {
	owner, _ := tree.Unwrap(signature)
	if ctx == nil || doc == nil || owner != doc {
		return nil, nil, ErrProfile
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	unsigned, err := unsignedProperties(signature)
	if err != nil {
		return nil, nil, err
	}

	if unsigned.Valid() {
		_, original := tree.Unwrap(unsigned)
		owned := *original
		owned.Children = append([]*tree.Node(nil), original.Children...)
		draft, err := tree.ReplaceDraft(ctx, doc, original, &owned)

		return draft, &owned, err
	}

	properties, err := qualifying(signature)
	if err != nil {
		return nil, nil, err
	}

	_, original := tree.Unwrap(properties)
	owned := *original
	owned.Children = append([]*tree.Node(nil), original.Children...)
	container := xnode("UnsignedProperties")
	unsignedNode := xnode("UnsignedSignatureProperties")
	add(container, unsignedNode)
	add(&owned, container)
	draft, err := tree.ReplaceDraft(ctx, doc, original, &owned)

	return draft, unsignedNode, err
}

func appendVerifiedTimestamp(ctx context.Context, doc *document.Document, selected document.Element, certificateDER []byte, method string, token *timestamp.Token, validation TimedOptions) (*document.Document, *TimedResult, error) {
	draft, uspn, e := unsignedDraft(ctx, doc, selected)
	if e != nil {
		return nil, nil, e
	}

	stamp := xnode("SignatureTimeStamp")
	canonical := dsnode("CanonicalizationMethod")
	attr(canonical, "Algorithm", method)

	enc := xnode("EncapsulatedTimeStamp")

	encoded, e := encodeBase64(ctx, token.Size(), token.WriterTo(ctx))
	if e != nil {
		return nil, nil, e
	}

	text(enc, encoded)
	add(stamp, canonical)
	add(stamp, enc)
	add(uspn, stamp)

	out, e := tree.Reparse(ctx, draft, tree.Policy(doc))
	if e != nil {
		return nil, nil, e
	}

	result, e := VerifyTimedEnveloped(ctx, out, xmldsig.Signatures(out)[0], certificateDER, validation)
	if e != nil {
		return nil, nil, e
	}

	return out, result, nil
}

func verifySignatureTimestampsModeProps(ctx context.Context, props []tree.Element, preservation bool, o *TimedOptions, out *[]*timestamp.Result, sig *document.Element) (returned1Value error, matchedBranch bool) {
	for _, p := range props {
		if preservation && knownPreservation(p.Name()) {
			continue
		}

		if p.Name() != name("SignatureTimeStamp") {
			return fmt.Errorf("%w: unsupported unsigned property %s", ErrProfile, p.Name().Local), true
		}

		method, tokens, e := parseTimeStamp(ctx, p, o.MaxTokenBytes)
		if e != nil {
			return e, true
		}

		if len(tokens) > o.MaxTimestamps-len(*out) {
			return ErrTimestamp, true
		}

		for _, raw := range tokens {
			token, e := timestamp.ParseToken(ctx, raw)
			if e != nil {
				return e, true
			}

			imprint, e := canonicalImprint(ctx, *sig, method, 1<<20, token.UnverifiedInfo().Imprint().Hash)
			if e != nil {
				return e, true
			}

			r, e := o.TSA.Verify(ctx, token, timestamp.Expectation{Imprint: imprint}, o.At, o.Evidence)
			if e != nil {
				return fmt.Errorf("%w: %w", ErrTimestamp, e), true
			}

			*out = append(*out, r)
		}
	}

	return returned1Value, matchedBranch
}

func encodeBase64(ctx context.Context, size int, source io.WriterTo) (string, error) {
	var output strings.Builder

	if err := ctx.Err(); err != nil {
		return "", err
	}

	encodedSize := base64.StdEncoding.EncodedLen(size)
	output.Grow(encodedSize)
	writer := &streamio.Writer{Context: ctx, Target: &output, Limit: int64(encodedSize), LimitError: ErrProfile}
	encoder := base64.NewEncoder(base64.StdEncoding, writer)

	_, err := source.WriteTo(encoder)
	if err := errors.Join(err, encoder.Close(), ctx.Err()); err != nil {
		return "", err
	}

	return output.String(), nil
}
