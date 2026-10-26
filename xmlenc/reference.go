package xmlenc

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/resource"
)

// CipherResolver supplies ciphertext for an exact application-approved URI.
// Resolve and the returned reader must honor ctx, including blocked reads.
// The library closes every non-nil returned reader, even when Resolve fails.
// Implementations must constrain network/file access and avoid returning secrets
// or other resources merely because their locations appear in untrusted XML.
type CipherResolver = resource.Resolver

// CipherResolverFunc adapts a function to CipherResolver.
type CipherResolverFunc = resource.ResolverFunc

// ExternalCipherReference permits one exact absolute ciphertext URI. The strict
// entry points require inline EncryptedKey and deny empty/same-document URIs;
// KeyGraphOptions separately enables bounded key relationships and local cipher
// references. External ciphertext is raw bytes or one XMLDSig base64 transform,
// without fragments or arbitrary transform programs. Resolving bytes asserts no trust:
// plaintext is returned only after the selected cipher and resource checks.
// GCM authenticates ciphertext; explicit legacy CBC remains unauthenticated.
type ExternalCipherReference struct {
	// Resolver is an application-owned adapter; nil and typed-nil are rejected.
	Resolver CipherResolver
	// URI is compared exactly, without rewriting or deriving a local file path.
	URI string
	// MaxBytes bounds bytes read before transforms. Zero uses the plaintext
	// budget's base64 size plus 4096 whitespace bytes; maximum is 64 MiB.
	MaxBytes int
}

// ExternalizeCiphertext replaces selected EncryptedData's inline CipherValue
// with a raw-byte CipherReference in a new snapshot, returning owned ciphertext
// for the application to store at uri. It performs no I/O and does not change
// EncryptedKey. Selection must belong to doc; the original snapshot is retained.
// This operation does not authenticate the envelope, its URI or its metadata.
// Decryption requires an explicit matching Options.External resolver and the
// same caller-selected cipher policy. CBC adds no authentication to the resource.
func ExternalizeCiphertext(ctx context.Context, doc *document.Document, selected document.Element, uri string) (*document.Document, document.Element, []byte, error) {
	if ctx == nil || !validCipherURI(uri) {
		return nil, document.Element{}, nil, ErrPolicy
	}

	node, err := selectedNode(doc, selected)
	if err != nil || selected.Name() != elementName(Namespace, "EncryptedData") {
		return nil, document.Element{}, nil, ErrFormat
	}

	var cipherData *tree.Node

	for _, child := range node.Children {
		if child.Name == elementName(Namespace, "CipherData") {
			if cipherData != nil {
				return nil, document.Element{}, nil, ErrFormat
			}

			cipherData = child
		}
	}

	if cipherData == nil {
		return nil, document.Element{}, nil, ErrFormat
	}

	// AES-CBC needs an IV plus up to one complete padding block.
	ciphertext, err := decodeCipherValue(ctx, tree.Wrap(doc, cipherData), (32<<20)+32)
	if err != nil {
		return nil, document.Element{}, nil, err
	}

	root := *node

	root.Children = append([]*tree.Node(nil), node.Children...)
	for i, child := range root.Children {
		if child == cipherData {
			ref := newElement(Namespace, child.Prefix, "CipherReference")
			setAttribute(ref, "URI", uri)

			copyData := *child
			copyData.Children = nil
			appendChild(&copyData, ref)
			root.Children[i] = &copyData
		}
	}

	result, handle, err := replaceElement(ctx, doc, node, &root)
	if err != nil {
		return nil, document.Element{}, nil, err
	}

	return result, handle, ciphertext, nil
}

func validCipherURI(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.Contains(value, "\\") {
		return false
	}

	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}

	u, err := url.Parse(value)

	return err == nil && u.IsAbs() && u.User == nil && !strings.Contains(value, "#")
}

func normalizeExternal(p ExternalCipherReference, maxCiphertext int) (ExternalCipherReference, error) {
	if nilcheck.IsNil(p.Resolver) || !validCipherURI(p.URI) {
		return ExternalCipherReference{}, ErrPolicy
	}

	if p.MaxBytes == 0 {
		p.MaxBytes = base64.StdEncoding.EncodedLen(maxCiphertext) + 4096
	}

	if p.MaxBytes < 1 || p.MaxBytes > 64<<20 {
		return ExternalCipherReference{}, ErrPolicy
	}

	return p, nil
}

func decodeCipherData(ctx context.Context, data document.Element, maxBytes int, external *ExternalCipherReference) ([]byte, error) {
	if !exactAttributes(data) || len(data.Children()) != 1 {
		return nil, ErrFormat
	}

	child := data.Children()[0]
	if child.Name() == elementName(Namespace, "CipherValue") {
		return decodeCipherValue(ctx, data, maxBytes)
	}

	if _, err := childElements(data, elementName(Namespace, "CipherReference")); err != nil || !exactAttributes(child, "URI") {
		return nil, ErrFormat
	}

	if external == nil || attributeValue(child, "URI") != external.URI {
		return nil, ErrPolicy
	}

	base64Transform := false

	if len(child.Children()) == 0 {
		if !xmlSpace(child.Text()) {
			return nil, ErrFormat
		}
	} else {
		children, err := childElements(child, elementName(Namespace, lexicon.DSigElementTransforms))
		if err != nil || !exactAttributes(children[0]) {
			return nil, ErrFormat
		}

		transforms, err := childElements(children[0], elementName(SignatureNamespace, lexicon.DSigElementTransform))
		if err != nil || !matchesMethod(transforms[0], SignatureNamespace+"base64", true) {
			return nil, ErrFormat
		}

		base64Transform = true
	}
	// Validate the complete transform structure before invoking application I/O.
	limit := external.MaxBytes
	if !base64Transform && limit > maxBytes {
		limit = maxBytes
	}

	return readCipherResource(ctx, external, limit, maxBytes, base64Transform)
}

func readCipherResource(ctx context.Context, p *ExternalCipherReference, limit, maximum int, decode bool) (out []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := p.Resolver.Resolve(ctx, p.URI)
	if !nilcheck.IsNil(r) {
		defer func() {
			if closeErr := r.Close(); closeErr != nil {
				out, err = nil, errors.Join(ErrResource, err, closeErr)
			}
		}()
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if err != nil || nilcheck.IsNil(r) {
		return nil, errors.Join(ErrResource, err)
	}

	source := &streamio.Reader{Context: ctx, Source: r, Limit: int64(limit), LimitError: ErrPolicy}

	var decoded io.Reader = source
	if decode {
		decoded = streamio.NewBase64Decoder(base64.StdEncoding.Strict(), &streamio.XMLWhitespaceReader{Source: source})
	}

	size := int64(-1)
	if sized, ok := r.(resource.SizedReader); ok && !decode {
		size = sized.Size()
	}

	if size >= 0 {
		out, err = readSizedCiphertext(ctx, decoded, min(maximum, limit), size)
	} else {
		out, err = readCiphertext(ctx, decoded, maximum)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if err != nil {
		return nil, errors.Join(ErrResource, err)
	}

	return out, nil
}

// Decryption consumes contiguous bounded ciphertext. Unknown-length resources are collected in
// fixed chunks and joined once, without repeatedly copying growing prefixes.
func readCiphertext(ctx context.Context, source io.Reader, maximum int) ([]byte, error) {
	reader := &streamio.Reader{Context: ctx, Source: source, Limit: int64(maximum), LimitError: ErrPolicy}

	var chunks [][]byte

	total := 0
	for {
		chunk := make([]byte, min(32<<10, maximum-total+1))

		n, err := io.ReadFull(reader, chunk)
		if n > 0 {
			chunks = append(chunks, chunk[:n])
			total += n
		}

		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				return nil, err
			}

			break
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(chunks) == 1 {
		return chunks[0], nil
	}

	output := make([]byte, total)
	offset := 0

	for _, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		offset += copy(output[offset:], chunk)
	}

	return output, ctx.Err()
}

// readSizedCiphertext allocates one authenticated-cipher input buffer, while
// verifying the untrusted transport size against actual bytes and terminal EOF.
func readSizedCiphertext(ctx context.Context, source io.Reader, maximum int, size int64) ([]byte, error) {
	if size < 0 || size > int64(maximum) {
		return nil, ErrPolicy
	}

	reader := &streamio.Reader{Context: ctx, Source: source, Limit: size, LimitError: ErrPolicy}

	out := make([]byte, int(size))
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}

	var probe [1]byte
	for {
		_, err := reader.Read(probe[:])
		if err != nil {
			if err == io.EOF { //nolint:errorlint // Joined EOF can carry a late read failure and must remain an error.
				return out, ctx.Err()
			}

			return nil, err
		}
	}
}
