// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package unparsedtext implements the text resource loading pipeline for
// XPath 3.1 fn:unparsed-text, fn:unparsed-text-available, fn:unparsed-text-lines,
// and the document retrieval that backs fn:doc / fn:json-doc.
//
// Resource loading is opt-in: without a URIResolver every retrieval fails.
// Network and filesystem access belong to explicit adapters from the public
// resource package; this pipeline owns decoding, read policy and byte limits.
package unparsedtext

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/encoding"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"

	"golang.org/x/text/transform"
)

// DefaultMaxBytes is the default per-resource read cap applied when
// Config.MaxBytes is 0. It guards against a hostile or pathological resource
// (an effectively unbounded HTTP body or a "/dev/zero"-style stream) exhausting
// process memory through an unbounded io.ReadAll.
const DefaultMaxBytes int64 = 10 << 20 // 10 MiB

const (
	encodingUTF8    = "utf-8"
	encodingUTF16BE = "utf-16be"
	encodingUTF16LE = "utf-16le"
)

// Error codes defined by the XPath 3.1 specification for unparsed-text functions.
const (
	// ErrCodeRetrieval is FOUT1170: the resource cannot be retrieved.
	ErrCodeRetrieval = "FOUT1170"
	// ErrCodeEncoding is FOUT1190: encoding mismatch or decode failure.
	ErrCodeEncoding = "FOUT1190"
)

var errLineLimit = errors.New("text line limit exceeded")

// ErrImplicitUTF8 identifies malformed octets after selecting the default UTF-8
// fallback, without an explicit encoding, BOM, XML media type or charset hint.
// Legacy XSLT hosts distinguish this failure from a specified-encoding failure.
var ErrImplicitUTF8 = errors.New("text is not UTF-8 and no encoding was inferred")

// URIResolver resolves a URI to a readable stream.
type URIResolver = xdm.URIResolver

// Config holds the external dependencies needed by the loading pipeline.
type Config struct {
	// BaseURI resolves relative resource references before invoking URIResolver.
	BaseURI string

	// URIResolver opens explicitly authorized resources. Nil disables retrieval.
	URIResolver URIResolver
	// ReadPolicy applies host invocation checks before access and records successful
	// resource opens.
	ReadPolicy xdm.ResourceReadPolicy
	// MaxBytes bounds the number of bytes read from a single resolver-backed resource. Reads larger than MaxBytes fail with an
	// ErrCodeRetrieval error before an unbounded body is buffered. A value
	// of 0 selects DefaultMaxBytes; a negative value disables the bound.
	MaxBytes int64
	// CheckBytes charges decoded text before retaining it. Nil applies only
	// MaxBytes, which also caps the decoded UTF-8 representation.
	CheckBytes func(int) error
	// ReadBytes observes encoded bytes consumed from the resource, without
	// retaining them or charging decoded output storage.
	ReadBytes func(int)
	// DecodedBytes observes the Unicode representation before json-doc escapes
	// non-XML characters into its internal JSON source representation.
	DecodedBytes func(int)
	// ControlFailure preserves host work and cancellation failures in availability
	// probes, which otherwise convert ordinary retrieval failures to false.
	ControlFailure func(context.Context, error) error
}

// Error represents a typed error from the unparsed-text pipeline.
type Error struct {
	Cause error // xmlsec: retain resource/limit/cancellation errors.
	// Code is the XPath text retrieval or encoding error code.
	Code string
	// Message describes the failed retrieval or decoding operation.
	Message string
}

// Unwrap preserves the original resource failure.
func (e *Error) Unwrap() error { return e.Cause }

// Error formats the pipeline code and message.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// LoadText resolves href, retrieves its content, decodes it, validates
// XML characters, and returns the result as a string.
func LoadText(ctx context.Context, cfg *Config, href, encoding string) (string, error) {
	var text strings.Builder

	err := loadText(ctx, cfg, href, encoding, func(chunk []byte) error {
		if text.Cap()-text.Len() < len(chunk) {
			text.Grow(max(len(chunk), text.Cap()))
		}

		_, err := text.Write(chunk)

		return err
	})
	if err != nil {
		return "", err
	}

	return text.String(), nil
}

// ReadText validates and decodes incrementally, allowing a consumer to stop
// before reading the remainder or retain only a bounded portion of the text.
func ReadText(ctx context.Context, cfg *Config, href, encoding string, consume func([]byte) error) error {
	return loadText(ctx, cfg, href, encoding, consume)
}

// LoadTextLines reads and validates text incrementally, retaining only the
// returned lines rather than a second complete source or normalized string.
func LoadTextLines(ctx context.Context, cfg *Config, href, encoding string) ([]string, error) {
	lines, _, err := LoadTextLinesBounded(ctx, cfg, href, encoding, 0)
	return lines, err
}

// LoadTextLinesBounded stops reading once limit+1 lines are available. A nonpositive
// limit leaves the line count unbounded; byte limits and cancellation still apply.
func LoadTextLinesBounded(ctx context.Context, cfg *Config, href, encoding string, limit int) ([]string, bool, error) {
	lines := lineCollector{limit: limit}

	err := loadText(ctx, cfg, href, encoding, lines.write)
	if err == nil && lines.current.Len() > 0 {
		err = lines.emit()
	}

	// Only the exact stop signal is successful truncation. A joined error
	// also carries a close or cancellation failure that must reach the caller.
	if err == errLineLimit { //nolint:errorlint // Only the exact stop sentinel is success; joined close or cancellation failures must propagate.
		return lines.lines, true, nil
	}

	if err != nil {
		return nil, false, err
	}

	return lines.lines, false, nil
}

// IsAvailable validates the resource without retaining decoded text. Byte caps
// apply, but no output storage is charged through CheckBytes.
func IsAvailable(ctx context.Context, cfg *Config, href, encoding string) bool {
	available, _ := CheckAvailability(ctx, cfg, href, encoding)
	return available
}

// CheckAvailability validates without retaining the content. Retrieval failures
// mean unavailable; a host resource-access failure remains an error.
func CheckAvailability(ctx context.Context, cfg *Config, href, encoding string) (bool, error) {
	if cfg != nil {
		policy := *cfg
		policy.CheckBytes = nil
		cfg = &policy
	}

	err := loadText(ctx, cfg, href, encoding, func([]byte) error { return nil })
	if cfg != nil && cfg.ControlFailure != nil {
		if failure := cfg.ControlFailure(ctx, err); failure != nil {
			return false, failure
		}
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, tree.ErrLimit) {
		return false, err
	}

	if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
		return false, err
	}

	return err == nil, nil
}

// ResolveURI validates and resolves an href against the base URI in cfg.
func ResolveURI(_ context.Context, cfg *Config, href string) (string, error) {
	if strings.Contains(href, "#") {
		return "", &Error{Code: ErrCodeRetrieval, Message: "URI must not contain a fragment identifier"}
	}

	if href == "" {
		if cfg != nil && cfg.BaseURI != "" {
			// An empty href resolves to the base URI verbatim; the base URI
			// must not carry a fragment identifier either.
			if strings.Contains(cfg.BaseURI, "#") {
				return "", &Error{Code: ErrCodeRetrieval, Message: "base URI must not contain a fragment identifier"}
			}

			return cfg.BaseURI, nil
		}

		return "", &Error{Code: ErrCodeRetrieval, Message: "empty href and no base URI available"}
	}

	parsed, err := parseURIReference(href)
	if err != nil {
		return "", &Error{Code: ErrCodeRetrieval, Message: fmt.Sprintf("invalid URI: %s", href)}
	}

	if parsed.Scheme == "" && strings.HasPrefix(href, ":/") {
		return "", &Error{Code: ErrCodeRetrieval, Message: fmt.Sprintf("invalid URI: %s", href)}
	}

	if isWindowsDriveScheme(parsed) {
		return "", &Error{Code: ErrCodeRetrieval, Message: fmt.Sprintf("unsupported URI scheme: %s", href)}
	}

	if parsed.Scheme != "" {
		if !isSupportedScheme(parsed.Scheme) && (cfg == nil || cfg.URIResolver == nil) {
			return "", &Error{Code: ErrCodeRetrieval, Message: fmt.Sprintf("unsupported URI scheme: %s", parsed.Scheme)}
		}

		return href, nil
	}

	if cfg != nil && cfg.BaseURI != "" {
		resolved, err := resolveReference(cfg.BaseURI, href)
		if err == nil {
			return resolved, nil
		}
	}

	return "", &Error{Code: ErrCodeRetrieval, Message: fmt.Sprintf("cannot resolve relative URI without base URI: %s", href)}
}

// ReadURI returns the resource as a string without an intermediate byte slice.
// Decoding and JSON character rules belong to the consuming parser.
func ReadURI(ctx context.Context, cfg *Config, uri string) (text string, err error) {
	rc, _, err := openURI(ctx, cfg, uri)
	if err != nil {
		return "", retrievalError(err)
	}
	defer func() {
		err = errors.Join(err, rc.Close(), ctx.Err())
		if err != nil {
			text = ""
		}
	}()

	var (
		out    strings.Builder
		buffer [32 << 10]byte
	)

	for {
		n, readErr := rc.Read(buffer[:])
		if n > 0 {
			if cfg != nil && cfg.CheckBytes != nil {
				if err := cfg.CheckBytes(n); err != nil {
					return "", err
				}
			}

			if out.Cap()-out.Len() < n {
				out.Grow(max(n, out.Cap()))
			}

			out.Write(buffer[:n])
		}

		if readErr != nil {
			// A wrapped/joined EOF can carry a resource failure and must not return success.
			if readErr == io.EOF {
				return out.String(), nil
			}

			return "", retrievalError(readErr)
		}
	}
}

// ReadJSONText applies json-doc's Unicode detection and escapes non-XML
// characters before parsing. compatible reports whether default unparsed-text
// would produce the same Unicode source with its narrower character rules.
func ReadJSONText(ctx context.Context, cfg *Config, uri string, consume func([]byte) error) (compatible bool, err error) {
	rc, hint, err := openURI(ctx, cfg, uri)
	if err != nil {
		return false, retrievalError(err)
	}
	defer func() {
		if final := errors.Join(rc.Close(), ctx.Err()); final != nil {
			err = errors.Join(err, retrievalError(final))
		}
	}()

	reader, compatible, err := decodedJSONReader(rc, hint)
	if err != nil {
		return false, err
	}

	err = readDecodedText(ctx, reader, effectiveMaxBytes(cfg), false, func(chunk []byte) error {
		if cfg != nil && cfg.DecodedBytes != nil {
			cfg.DecodedBytes(len(chunk))
		}

		converted, changed, err := jsonCharacterChunk(cfg, chunk)
		if err != nil {
			return err
		}

		compatible = compatible && !changed

		return consume(converted)
	})

	return compatible, err
}

// DecodeText decodes raw bytes to a string, handling BOM detection,
// XML declaration sniffing, and encoding conversion. encoding is the
// user-specified encoding (from the function argument); transportHints
// are optional transport-level charset names or MIME Content-Type values.
// External charset information takes precedence over the function argument;
// a conflicting BOM raises FOUT1190.
// If all are empty, defaults to UTF-8.
func DecodeText(data []byte, encoding string, transportHints ...string) (string, error) {
	metadata := ""

	for _, hint := range transportHints {
		if hint != "" {
			metadata = hint
			if !strings.Contains(hint, "/") {
				metadata = mime.FormatMediaType("text/plain", map[string]string{"charset": hint})
			}

			break
		}
	}

	reader, err := decodedReader(bytes.NewReader(data), encoding, metadata)
	if err != nil {
		return "", err
	}

	var text strings.Builder

	err = readText(context.Background(), reader, -1, func(chunk []byte) error { _, err := text.Write(chunk); return err })
	if err != nil {
		return "", err
	}

	return text.String(), nil
}

// SplitLines splits text into lines per the XPath spec. Line endings are
// normalized: CR+LF -> LF, CR -> LF. A trailing newline does not produce
// an extra empty line.
func SplitLines(text string) []string {
	lines, _ := SplitLinesBounded(text, 0)
	return lines
}

// SplitLinesBounded returns borrowed line substrings without making a full
// normalized copy. A positive limit stops collection after limit+1 lines.
func SplitLinesBounded(text string, limit int) ([]string, bool) {
	var lines []string

	start := 0

	for i := 0; i < len(text); i++ {
		if text[i] != '\r' && text[i] != '\n' {
			continue
		}

		lines = append(lines, text[start:i])
		if limit > 0 && len(lines) > limit {
			return lines, true
		}

		if text[i] == '\r' && i+1 < len(text) && text[i+1] == '\n' {
			i++
		}

		start = i + 1
	}

	if start < len(text) {
		lines = append(lines, text[start:])
	}

	return lines, limit > 0 && len(lines) > limit
}

// ValidateXMLChars checks that the string contains only valid XML 1.0
// characters: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF].
func ValidateXMLChars(s string) error {
	for i, r := range s {
		if !IsValidXMLChar(r) {
			return &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("non-XML character U+%04X at position %d", r, i)}
		}
	}

	return nil
}

// IsValidXMLChar reports whether r is a valid XML 1.0 character.
func IsValidXMLChar(r rune) bool {
	if r == 0x9 || r == 0xA || r == 0xD {
		return true
	}

	if r >= 0x20 && r <= 0xD7FF {
		return true
	}

	if r >= 0xE000 && r <= 0xFFFD {
		return true
	}

	return r >= 0x10000 && r <= 0x10FFFF
}

// EncodingsCompatible checks if a user-specified encoding is compatible
// with a BOM-detected encoding.
func EncodingsCompatible(specified, detected string) bool {
	s := normalizeEncodingName(specified)
	d := normalizeEncodingName(detected)

	if s == d {
		return true
	}

	if s == "utf16" && (d == "utf16le" || d == "utf16be") {
		return true
	}

	return false
}

// ValidatePercentEncoding verifies that every '%' in uri is followed by two
// hexadecimal digits, returning a descriptive error otherwise.
func ValidatePercentEncoding(uri string) error {
	return uripath.ValidatePercentEncoding(uri)
}

// OpenURI opens an explicitly configured XML resource without buffering it.
// The caller owns the returned stream and must enforce its XML construction
// policy and check Close. Text-returning functions share the same resource path.
func OpenURI(ctx context.Context, cfg *Config, uri string) (io.ReadCloser, error) {
	reader, _, err := openURI(ctx, cfg, uri)
	return reader, err
}

func parseURIReference(raw string) (*url.URL, error) {
	if err := ValidatePercentEncoding(raw); err != nil {
		return nil, err
	}

	return url.Parse(raw)
}

func isWindowsDriveScheme(parsed *url.URL) bool {
	if len(parsed.Scheme) != 1 {
		return false
	}

	b := parsed.Scheme[0]

	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isSupportedScheme(scheme string) bool {
	switch scheme {
	case "file", "http", "https":
		return true
	default:
		return false
	}
}

func resolveReference(base, ref string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}

	return baseURL.ResolveReference(refURL).String(), nil
}

func jsonCharacterChunk(cfg *Config, chunk []byte) ([]byte, bool, error) {
	size := len(chunk)
	for offset := 0; offset < len(chunk); {
		value, width := utf8.DecodeRune(chunk[offset:])
		if !IsValidXMLChar(value) {
			size += 6 - width
		}

		offset += width
	}

	if cfg != nil && cfg.CheckBytes != nil {
		if err := cfg.CheckBytes(size); err != nil {
			return nil, false, err
		}
	}

	if size == len(chunk) {
		return chunk, false, nil
	}

	const hex = "0123456789ABCDEF"

	converted := make([]byte, 0, size)

	for len(chunk) > 0 {
		value, width := utf8.DecodeRune(chunk)
		if IsValidXMLChar(value) {
			converted = append(converted, chunk[:width]...)
		} else {
			converted = append(converted, '\\', 'u', hex[value>>12&15], hex[value>>8&15], hex[value>>4&15], hex[value&15])
		}

		chunk = chunk[width:]
	}

	return converted, true, nil
}

func decodedJSONReader(src io.Reader, contentType string) (io.Reader, bool, error) {
	charset, _, err := textMediaType(contentType)
	if err != nil {
		return nil, false, err
	}

	reader := bufio.NewReaderSize(src, 4096)

	prefix, err := reader.Peek(4)
	// Only bare EOF permits a short encoding prefix; joined source errors remain fatal.
	if err != nil && err != io.EOF { //nolint:errorlint // Only bare EOF is completion; wrapped or joined failures must propagate.
		return nil, false, err
	}

	detected, skip := jsonBOMEncoding(prefix)

	effective, compatible := "", false
	if charset != "" {
		effective = resolveEncoding(charset, detected)
		if normalizeEncodingName(charset) == "utf32" && strings.HasPrefix(detected, "utf-32") {
			effective = detected
		}

		compatible = !strings.HasPrefix(detected, "utf-32")
	} else if detected != "" {
		effective = detected
		compatible = !strings.HasPrefix(detected, "utf-32")
	} else {
		effective = jsonInitialEncoding(prefix)
		compatible = effective == encodingUTF8
	}

	if effective == "" {
		return nil, false, &Error{Code: ErrCodeEncoding, Message: "JSON transport encoding conflicts with byte order mark"}
	}

	if skip > 0 {
		if _, err := reader.Discard(skip); err != nil {
			return nil, false, err
		}
	}

	decoded, err := encodingReader(reader, effective)

	return decoded, compatible, err
}

func jsonBOMEncoding(prefix []byte) (string, int) {
	if bytes.HasPrefix(prefix, []byte{0, 0, 0xfe, 0xff}) {
		return "utf-32be", 4
	}

	if bytes.HasPrefix(prefix, []byte{0xff, 0xfe, 0, 0}) {
		return "utf-32le", 4
	}

	encoding, clean := detectBOM(prefix)

	return encoding, len(prefix) - len(clean)
}

func jsonInitialEncoding(prefix []byte) string {
	if len(prefix) >= 4 {
		switch {
		case prefix[0] == 0 && prefix[1] == 0 && prefix[2] == 0:
			return "utf-32be"
		case prefix[1] == 0 && prefix[2] == 0 && prefix[3] == 0:
			return "utf-32le"
		case prefix[0] == 0 && prefix[2] == 0:
			return encodingUTF16BE
		case prefix[1] == 0 && prefix[3] == 0:
			return encodingUTF16LE
		}
	}

	if len(prefix) == 2 {
		if prefix[0] == 0 {
			return encodingUTF16BE
		}

		if prefix[1] == 0 {
			return encodingUTF16LE
		}
	}

	return encodingUTF8
}

// effectiveMaxBytes resolves the configured cap to the value actually enforced:
// 0 selects DefaultMaxBytes and a negative value disables the bound.
func effectiveMaxBytes(cfg *Config) int64 {
	if cfg == nil || cfg.MaxBytes == 0 {
		return DefaultMaxBytes
	}

	return cfg.MaxBytes
}

func loadText(ctx context.Context, cfg *Config, href, encoding string, emit func([]byte) error) (err error) {
	resolved, err := ResolveURI(ctx, cfg, href)
	if err != nil {
		return err
	}

	rc, hint, err := openURI(ctx, cfg, resolved)
	if err != nil {
		return retrievalError(err)
	}
	defer func() {
		if final := errors.Join(rc.Close(), ctx.Err()); final != nil {
			err = errors.Join(err, retrievalError(final))
		}
	}()

	maximum := effectiveMaxBytes(cfg)

	reader, err := decodedReader(rc, encoding, hint)
	if err != nil {
		return err
	}

	return readText(ctx, reader, maximum, func(chunk []byte) error {
		if cfg != nil && cfg.CheckBytes != nil {
			if err := cfg.CheckBytes(len(chunk)); err != nil {
				return err
			}
		}

		return emit(chunk)
	})
}

type resourceReader struct {
	io.Reader
	io.Closer
}

// openURI applies byte limits to actual reads without collecting the resource.
func openURI(ctx context.Context, cfg *Config, uri string) (io.ReadCloser, string, error) {
	if ctx == nil {
		return nil, "", errors.New("nil context")
	}

	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	_, err := url.Parse(uri)
	if err != nil {
		return nil, "", err
	}

	if cfg != nil && cfg.ReadPolicy != nil {
		if err := cfg.ReadPolicy.CheckRead(ctx, uri); err != nil {
			return nil, "", &xdm.ResourceAccessError{Cause: err}
		}
	}

	var rc io.ReadCloser

	hint := ""

	if cfg == nil || cfg.URIResolver == nil {
		return nil, "", fmt.Errorf("retrieval of %q requires an explicit resolver or HTTP client", uri)
	}

	rc, err = cfg.URIResolver.Resolve(ctx, uri)
	if err != nil {
		if !nilcheck.IsNil(rc) {
			err = errors.Join(err, rc.Close())
		}

		return nil, "", err
	}

	if nilcheck.IsNil(rc) {
		return nil, "", errors.New("resolver returned a nil reader")
	}

	if cfg.ReadPolicy != nil {
		if err := cfg.ReadPolicy.RecordRead(ctx, uri); err != nil {
			return nil, "", errors.Join(&xdm.ResourceAccessError{Cause: err}, rc.Close())
		}
	}

	// The resolver already supplies io.ReadCloser. Consume only the optional
	// metadata method here, without depending on concrete resource adapters.
	if typed, ok := rc.(interface{ MediaType() string }); ok {
		hint = typed.MediaType()
	}

	if err := ctx.Err(); err != nil {
		return nil, "", errors.Join(err, rc.Close())
	}

	maximum := effectiveMaxBytes(cfg)
	if maximum < 0 {
		maximum = math.MaxInt64
	}

	observe := cfg.ReadBytes

	limited := &streamio.Reader{Context: ctx, Source: &retrievalReader{Reader: rc, observe: observe}, Limit: maximum, LimitError: textLimitError()}

	return &resourceReader{Reader: limited, Closer: rc}, hint, nil
}

type retrievalReader struct {
	io.Reader
	observe func(int)
}

func (r *retrievalReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 && r.observe != nil {
		r.observe(n)
	}

	// Keep wrapped/joined EOF failures classified as retrieval errors.
	if err != nil && err != io.EOF { //nolint:errorlint // Only bare EOF is completion; wrapped or joined failures must propagate.
		err = retrievalError(err)
	}

	return n, err
}

func retrievalError(err error) error {
	if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
		return err
	}

	if _, ok := errors.AsType[*Error](err); ok {
		return err
	}

	return &Error{Code: ErrCodeRetrieval, Message: fmt.Sprintf("cannot retrieve resource: %v", err), Cause: err}
}

func textLimitError() error {
	return &Error{Code: ErrCodeRetrieval, Message: "resource exceeds maximum allowed byte size", Cause: tree.ErrLimit}
}

func textMediaType(contentType string) (string, bool, error) {
	if contentType == "" {
		return "", false, nil
	}

	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false, &Error{Code: ErrCodeEncoding, Message: "invalid resource media type", Cause: err}
	}

	xml := mediaType == "text/xml" || mediaType == "application/xml" ||
		(strings.HasPrefix(mediaType, "text/") || strings.HasPrefix(mediaType, "application/")) && strings.HasSuffix(mediaType, "+xml")

	return parameters["charset"], xml, nil
}

// detectBOM checks for a byte-order mark and returns the detected encoding
// name and data with the BOM stripped.
func detectBOM(data []byte) (string, []byte) {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return encodingUTF8, data[3:]
	}

	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return encodingUTF16LE, data[2:]
	}

	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return encodingUTF16BE, data[2:]
	}

	return "", data
}

// detectXMLDeclEncoding looks for an XML declaration at the beginning of
// data and extracts the encoding attribute value if present.
// It works on raw bytes assuming the declaration is in ASCII-compatible encoding.
func detectXMLDeclEncoding(data []byte) string {
	// XML declaration must start at the very beginning.
	if !bytes.HasPrefix(data, []byte("<?xml")) {
		return ""
	}

	end := bytes.Index(data, []byte("?>"))
	if end < 0 || end > 200 {
		return ""
	}

	decl := data[:end]
	// Look for encoding="..." or encoding='...'.
	_, rest, found := bytes.Cut(decl, []byte("encoding"))
	if !found {
		return ""
	}

	rest = bytes.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != '=' {
		return ""
	}

	rest = rest[1:]

	rest = bytes.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 {
		return ""
	}

	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return ""
	}

	valueEnd := bytes.IndexByte(rest[1:], quote)
	if valueEnd < 0 {
		return ""
	}

	return string(rest[1 : valueEnd+1])
}

// resolveEncoding determines the effective encoding from the user-specified
// encoding and BOM-detected encoding. Returns "" if they conflict.
func resolveEncoding(specified, detected string) string {
	if specified != "" {
		if detected != "" && !EncodingsCompatible(specified, detected) {
			return ""
		}
		// The BOM has already been stripped from the data by this point, so a
		// generic "utf-16" decoder can no longer recover the endianness and
		// would fall back to its little-endian default. When the BOM told us
		// the concrete endianness, prefer the detected endian-specific
		// encoding so a big-endian payload is decoded as big-endian.
		if detected != "" && normalizeEncodingName(specified) == "utf16" {
			return detected
		}

		return specified
	}

	if detected != "" {
		return detected
	}

	return encodingUTF8
}

// decodedReader sniffs only the bounded declaration prefix, then keeps one
// stateful decoder across chunks. XML declarations beyond 200 bytes are ignored.
func decodedReader(src io.Reader, specified, contentType string) (io.Reader, error) {
	if specified != "" && encoding.Load(specified) == nil {
		return nil, &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("unsupported encoding: %s", specified)}
	}

	hint, xmlMediaType, err := textMediaType(contentType)
	if err != nil {
		return nil, err
	}
	// F&O 2.0/3.0/3.1: external encoding precedes XML media type rules,
	// which precede the function argument and implementation-defined heuristics.
	if hint != "" {
		specified = hint
	} else if xmlMediaType {
		specified = ""
	}

	reader := bufio.NewReaderSize(src, 4096)

	// These prefix probes tolerate only bare EOF, never a joined resource failure.
	prefix, err := reader.Peek(4)
	if err != nil && err != io.EOF { //nolint:errorlint // Only bare EOF is completion; wrapped or joined failures must propagate.
		return nil, err
	}

	detected, clean := detectBOM(prefix)
	if skipped := len(prefix) - len(clean); skipped > 0 {
		if _, err := reader.Discard(skipped); err != nil {
			return nil, err
		}
	}

	if detected == "" && specified == "" {
		prefix, err = reader.Peek(5)
		if err != nil && err != io.EOF { //nolint:errorlint // Only bare EOF is completion; wrapped or joined failures must propagate.
			return nil, err
		}

		if bytes.Equal(prefix, []byte("<?xml")) {
			prefix, err = reader.Peek(202)
			if err != nil && err != io.EOF { //nolint:errorlint // Only bare EOF is completion; wrapped or joined failures must propagate.
				return nil, err
			}

			detected = detectXMLDeclEncoding(prefix)
		}
	}

	effective := resolveEncoding(specified, detected)
	if effective == "" {
		return nil, &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("specified encoding %s conflicts with BOM (%s)", specified, detected)}
	}

	decoded, err := encodingReader(reader, effective)
	if err == nil && specified == "" && detected == "" && !xmlMediaType {
		decoded = &implicitUTF8Reader{Reader: decoded}
	}

	return decoded, err
}

type implicitUTF8Reader struct{ io.Reader }

func encodingReader(src io.Reader, name string) (io.Reader, error) {
	if normalizeEncodingName(name) == "utf8" || name == "" {
		return src, nil
	}

	codec := encoding.Load(name)
	if codec == nil {
		return nil, &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("unsupported encoding: %s", name)}
	}

	return transform.NewReader(src, codec.NewDecoder()), nil
}

// readText validates UTF-8/XML characters across chunk boundaries before
// retaining output. The decoded byte cap is checked before calling emit.
func readText(ctx context.Context, reader io.Reader, maximum int64, emit func([]byte) error) error {
	return readDecodedText(ctx, reader, maximum, true, emit)
}

func readDecodedText(ctx context.Context, reader io.Reader, maximum int64, xmlOnly bool, emit func([]byte) error) error {
	var buffer [32<<10 + utf8.UTFMax]byte

	pending, used := 0, int64(0)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := reader.Read(buffer[pending : 32<<10])
		end := pending + n

		valid := 0
		for valid < end {
			if !utf8.FullRune(buffer[valid:end]) && err == nil {
				break
			}

			r, size := utf8.DecodeRune(buffer[valid:end])
			if failure := decodedRuneError(reader, r, size, xmlOnly); failure != nil {
				return failure
			}

			valid += size
		}

		if maximum >= 0 && int64(valid) > maximum-used {
			return textLimitError()
		}

		used += int64(valid)
		if valid > 0 {
			if failure := emit(buffer[:valid]); failure != nil {
				return failure
			}
		}

		if err != nil {
			// Only bare EOF completes decoding; joined read/close failures must survive.
			if err == io.EOF {
				return ctx.Err()
			}

			if _, ok := errors.AsType[*Error](err); ok {
				return err
			}

			return &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("decode error: %v", err), Cause: err}
		}

		pending = copy(buffer[:], buffer[valid:end])
	}
}

func decodedRuneError(reader io.Reader, r rune, size int, xmlOnly bool) error {
	if r == utf8.RuneError && size == 1 {
		var cause error
		if _, implicit := reader.(*implicitUTF8Reader); implicit {
			cause = ErrImplicitUTF8
		}

		return &Error{Code: ErrCodeEncoding, Message: "invalid UTF-8 in text resource", Cause: cause}
	}

	if xmlOnly && !IsValidXMLChar(r) {
		return &Error{Code: ErrCodeEncoding, Message: "invalid UTF-8 or XML character in text resource"}
	}

	return nil
}

type lineCollector struct {
	lines   []string
	current strings.Builder
	limit   int
	skipLF  bool
}

func (c *lineCollector) emit() error {
	c.lines = append(c.lines, c.current.String())
	c.current.Reset()

	if c.limit > 0 && len(c.lines) > c.limit {
		return errLineLimit
	}

	return nil
}

func (c *lineCollector) write(chunk []byte) error {
	start := 0

	for i, char := range chunk {
		if c.skipLF {
			c.skipLF = false

			if char == '\n' {
				start = i + 1
				continue
			}
		}

		if char != '\r' && char != '\n' {
			continue
		}

		c.append(chunk[start:i])

		if err := c.emit(); err != nil {
			return err
		}

		c.skipLF = char == '\r'
		start = i + 1
	}

	c.append(chunk[start:])

	return nil
}

func (c *lineCollector) append(chunk []byte) {
	if c.current.Cap()-c.current.Len() < len(chunk) {
		c.current.Grow(max(len(chunk), c.current.Cap()))
	}

	c.current.Write(chunk)
}

func normalizeEncodingName(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), "_", ""))
}
