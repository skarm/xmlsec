// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

// Package unparsedtext implements the text resource loading pipeline for
// XPath 3.1 fn:unparsed-text, fn:unparsed-text-available, fn:unparsed-text-lines,
// and the document retrieval that backs fn:doc / fn:json-doc.
//
// Resource loading is opt-in. With no URIResolver and no HTTPClient supplied,
// every retrieval attempt fails with ErrCodeRetrieval — there is no implicit
// network access and no implicit filesystem access. Callers who want network
// access must either pass an explicit *http.Client via Config.HTTPClient
// (caller owns the transport, timeouts, and redirect policy) or supply a
// URIResolver that accepts http(s) schemes. Callers who want filesystem
// access must supply a URIResolver from the public resource package.
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
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/transform/internal/xdm"

	"golang.org/x/text/transform"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/resource"
	iencoding "github.com/skarm/xmlsec/transform/internal/xdm/encoding"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
)

// DefaultMaxBytes is the default per-resource read cap applied when
// Config.MaxBytes is 0. It guards against a hostile or pathological resource
// (an effectively unbounded HTTP body or a "/dev/zero"-style stream) exhausting
// process memory through an unbounded io.ReadAll.
const DefaultMaxBytes int64 = 10 << 20 // 10 MiB

// Error codes defined by the XPath 3.1 specification for unparsed-text functions.
const (
	// ErrCodeRetrieval is FOUT1170: the resource cannot be retrieved.
	ErrCodeRetrieval = "FOUT1170"
	// ErrCodeEncoding is FOUT1190: encoding mismatch or decode failure.
	ErrCodeEncoding = "FOUT1190"
)

var errLineLimit = errors.New("text line limit exceeded")

// URIResolver resolves a URI to a readable stream.
type URIResolver = xdm.URIResolver

// Config holds the external dependencies needed by the loading pipeline.
type Config struct {
	BaseURI     string
	HTTPClient  *http.Client
	URIResolver URIResolver
	ReadPolicy  xdm.ResourceReadPolicy
	// MaxBytes bounds the number of bytes read from a single resolver- or
	// HTTP-backed resource. Reads larger than MaxBytes fail with an
	// ErrCodeRetrieval error before an unbounded body is buffered. A value
	// of 0 selects DefaultMaxBytes; a negative value disables the bound.
	MaxBytes int64
	// CheckBytes charges decoded text before retaining it. Nil applies only
	// MaxBytes, which also caps the decoded UTF-8 representation.
	CheckBytes func(int) error
}

// Error represents a typed error from the unparsed-text pipeline.
type Error struct {
	Cause   error // xmlsec: retain resource/limit/cancellation errors.
	Code    string
	Message string
}

// Unwrap preserves the original resource failure.
func (e *Error) Unwrap() error { return e.Cause }

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

	if err == errLineLimit {
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

		if readErr == io.EOF {
			return out.String(), nil
		}

		if readErr != nil {
			return "", retrievalError(readErr)
		}
	}
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
			err = errors.Join(err, final)
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

	parsed, err := url.Parse(uri)
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

	switch {
	case (parsed.Scheme == lexicon.SchemeHTTP || parsed.Scheme == lexicon.SchemeHTTPS) && cfg != nil && cfg.HTTPClient != nil:
		rc, hint, err = openHTTP(ctx, cfg.HTTPClient, uri)
	case cfg != nil && cfg.URIResolver != nil:
		rc, err = cfg.URIResolver.Resolve(ctx, uri)
	default:
		return nil, "", fmt.Errorf("retrieval of %q requires an explicit resolver or HTTP client", uri)
	}

	if err != nil {
		if !nilcheck.IsNil(rc) {
			err = errors.Join(err, rc.Close())
		}

		return nil, "", err
	}

	if nilcheck.IsNil(rc) {
		return nil, "", errors.New("resolver returned a nil reader")
	}

	if cfg != nil && cfg.ReadPolicy != nil {
		if err := cfg.ReadPolicy.RecordRead(ctx, uri); err != nil {
			return nil, "", errors.Join(&xdm.ResourceAccessError{Cause: err}, rc.Close())
		}
	}

	if typed, ok := rc.(resource.TypedReader); ok {
		hint = typed.MediaType()
	}

	if err := ctx.Err(); err != nil {
		return nil, "", errors.Join(err, rc.Close())
	}

	maximum := effectiveMaxBytes(cfg)
	if maximum < 0 {
		maximum = math.MaxInt64
	}

	limited := &streamio.Reader{Context: ctx, Source: &retrievalReader{Reader: rc}, Limit: maximum, LimitError: textLimitError()}

	return &resourceReader{Reader: limited, Closer: rc}, hint, nil
}

type retrievalReader struct{ io.Reader }

func (r *retrievalReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
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

func openHTTP(ctx context.Context, client *http.Client, uri string) (io.ReadCloser, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.Join(fmt.Errorf("HTTP %d for %s", resp.StatusCode, uri), resp.Body.Close())
	}

	return resp.Body, resp.Header.Get("Content-Type"), nil
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
		return "utf-8", data[3:]
	}

	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return "utf-16le", data[2:]
	}

	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return "utf-16be", data[2:]
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

	return "utf-8"
}

// decodedReader sniffs only the bounded declaration prefix, then keeps one
// stateful decoder across chunks. XML declarations beyond 200 bytes are ignored.
func decodedReader(src io.Reader, specified, contentType string) (io.Reader, error) {
	if specified != "" && iencoding.Load(specified) == nil {
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

	prefix, err := reader.Peek(4)
	if err != nil && err != io.EOF {
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
		if err != nil && err != io.EOF {
			return nil, err
		}

		if bytes.Equal(prefix, []byte("<?xml")) {
			prefix, err = reader.Peek(202)
			if err != nil && err != io.EOF {
				return nil, err
			}

			detected = detectXMLDeclEncoding(prefix)
		}
	}

	effective := resolveEncoding(specified, detected)
	if effective == "" {
		return nil, &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("specified encoding %s conflicts with BOM (%s)", specified, detected)}
	}

	return encodingReader(reader, effective)
}

func encodingReader(src io.Reader, name string) (io.Reader, error) {
	if normalizeEncodingName(name) == "utf8" || name == "" {
		return src, nil
	}

	codec := iencoding.Load(name)
	if codec == nil {
		return nil, &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("unsupported encoding: %s", name)}
	}

	return transform.NewReader(src, codec.NewDecoder()), nil
}

// readText validates UTF-8/XML characters across chunk boundaries before
// retaining output. The decoded byte cap is checked before calling emit.
func readText(ctx context.Context, reader io.Reader, maximum int64, emit func([]byte) error) error {
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
			if r == utf8.RuneError && size == 1 || !IsValidXMLChar(r) {
				return &Error{Code: ErrCodeEncoding, Message: "invalid UTF-8 or XML character in text resource"}
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

		if err == io.EOF {
			return ctx.Err()
		}

		if err != nil {
			if _, ok := errors.AsType[*Error](err); ok {
				return err
			}

			return &Error{Code: ErrCodeEncoding, Message: fmt.Sprintf("decode error: %v", err), Cause: err}
		}

		pending = copy(buffer[:], buffer[valid:end])
	}
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
