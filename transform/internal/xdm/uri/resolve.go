// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package uripath

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

// IRI resource escaping percent-encodes bytes at or below space and above ASCII tilde.
const (
	iriEscapedASCIIEnd   = 0x20
	iriUnescapedASCIIEnd = 0x7E
)

// These excluded ASCII punctuation bytes are percent-encoded in resource references.
const iriExcludedPunctuation = "\"<>{}|\\^`"

// ResolveSchemaURI resolves a schema-location reference ref against a base
// (the FULL location of the schema that contains the reference) and returns
// the canonical name to hand to the configured loader.
//
// It is the single canonical URI-resolution helper shared by the xsd nested
// xs:include/xs:import/xs:redefine path and by xslt's schema loader, so the
// two layers cannot drift apart again. Resolution branches on ref/base type:
//
//   - An ABSOLUTE-URI ref (it has its own scheme — with or without a "//"
//     authority, e.g. "https://cdn/part.xsd", "mem:/schemas/s.xsd",
//     "urn:schemas:s", "file:/tmp/s") addresses its own location and is
//     returned UNCHANGED, regardless of base. It must never be filepath.Join'ed
//     onto a base — doing so collapses the "//" authority separator (dropping
//     the host) or produces a bogus "/work/mem:/schemas/s".
//
//   - A relative ref against a URI base (the base has a scheme) is resolved
//     with RFC 3986 [url.URL.ResolveReference] semantics. The base's last path
//     segment is treated as the document and replaced, so a sibling "part.xsd"
//     against "mem:/schemas/main.xsd" resolves to "mem:/schemas/part.xsd". The
//     base authority is preserved, so a root-relative "/p" keeps scheme+host
//     and "../" applies dot-segment rules — never filepath collapsing. The
//     base's OmitHost flag is re-applied when the base had no authority (e.g.
//     "mem:/..." stays "mem:/...", never "mem:///...") while canonical
//     empty-authority bases like "file:///..." keep their "///".
//
//   - Otherwise (a genuine local filesystem base and ref) the historical
//     [filepath] join + ".."-escape guard is used unchanged: ref is joined onto
//     base and a result that ascends above base via ".." is rejected with
//     [ErrInvalidURI]. The base here is a DIRECTORY (the containing dir of
//     the schema), matching the xsd compiler's BaseDir convention.
//
// The escape guard mirrors the defense-in-depth path normalization in xinclude
// (#420/#425); the configured loader may further constrain, but catching the
// escape here gives consistent behavior across loaders.
func ResolveSchemaURI(ref, base string) (string, error) {
	// Absolute-URI ref: address its own location verbatim.
	if URIScheme(ref) != "" {
		return ref, nil
	}
	// Relative ref against a URI base: resolve per RFC 3986.
	if URIScheme(base) != "" {
		return ResolveIRIReference(ref, base)
	}
	// Local filesystem base + ref. Resolve in FORWARD-SLASH space so the
	// returned name — used as a key into the configured fs.FS, whose contract
	// mandates '/' (io/fs.ValidPath) — never gains backslashes on Windows, where
	// filepath.Join/Rel/Separator would otherwise produce "schemas\\x" and miss
	// every MapFS / os.DirFS key. The shape-based detection and slash math are
	// GOOS-independent, so the escape guard is exercised identically on POSIX.
	slashRef := ToSlash(ref)
	if base == "" {
		return path.Clean(slashRef), nil
	}

	slashBase := ToSlash(base)
	p := path.Join(slashBase, slashRef)

	rel, err := filepath.Rel(slashBase, p)
	if err != nil {
		// Rel only fails when one is absolute and the other isn't;
		// nothing actionable here — accept and let the loader decide.
		return p, nil //nolint:nilerr // A mixed absolute/relative filesystem base is delegated to the configured loader.
	}

	rel = ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%w: %q", ErrInvalidURI, ref)
	}

	return p, nil
}

// EscapeResourceReference applies XLink/RFC 3986 escaping when an IRI is
// used to access an external resource. Existing percent escapes and URI
// delimiters are retained; namespace names, collations, XML Base values and
// fn:resolve-uri results must not be changed merely for being IRIs.
func EscapeResourceReference(reference string) string {
	var encoded strings.Builder

	for index := 0; index < len(reference); index++ {
		value := reference[index]
		if value > iriUnescapedASCIIEnd || value <= iriEscapedASCIIEnd || strings.ContainsRune(iriExcludedPunctuation, rune(value)) {
			if encoded.Len() == 0 {
				encoded.Grow(len(reference))
				encoded.WriteString(reference[:index])
			}

			const hex = "0123456789ABCDEF"

			encoded.WriteByte('%')
			encoded.WriteByte(hex[value>>4])
			encoded.WriteByte(hex[value&0xf])
		} else if encoded.Len() != 0 {
			encoded.WriteByte(value)
		}
	}

	if encoded.Len() == 0 {
		return reference
	}

	return encoded.String()
}

// ResolveIRIReference implements RFC 3986 section 5.2 without escaping Unicode
// or discarding empty query/fragment delimiters. It is shared by XML base,
// schema/module resources and XPath URI functions.
func ResolveIRIReference(ref, base string) (string, error) {
	parsedBase, err := ParseIRIReference(base)
	if err != nil {
		return "", err
	}

	parsedRef, err := ParseIRIReference(ref)
	if err != nil {
		return "", err
	}

	return parsedRef.ResolveAgainst(parsedBase), nil
}

// ParseIRIReference preserves IRI spelling, including host forms that are
// syntactically valid even when net/url cannot use them as a network address.
func ParseIRIReference(raw string) (IRIReference, error) {
	if err := ValidatePercentEncoding(raw); err != nil {
		return IRIReference{}, err
	}

	reference := splitIRIReference(raw)
	if _, err := url.Parse(raw); err != nil {
		if !reference.hasAuthority {
			return IRIReference{}, err
		}

		authority, ok := genericAuthority(reference.authority)
		if !ok {
			return IRIReference{}, err
		}

		validation := reference
		validation.authority = authority

		if _, validationErr := url.Parse(validation.String()); validationErr != nil {
			return IRIReference{}, validationErr
		}
	}

	return reference, nil
}

func genericAuthority(authority string) (string, bool) {
	hostPort := authority
	if userinfo, rest, found := strings.Cut(authority, "@"); found {
		if strings.ContainsRune(rest, '@') || strings.ContainsFunc(userinfo, func(value rune) bool {
			return !isIRINameChar(value) && value != ':' && value != '%'
		}) {
			return "", false
		}

		hostPort = rest
	}

	if strings.HasPrefix(hostPort, "[") {
		host, port, closed := strings.Cut(hostPort[1:], "]")
		if !closed || !validIRIPortSuffix(port) {
			return "", false
		}

		if isIPvFuture(host) {
			return "host" + port, true
		}

		_, err := url.Parse("iri://" + hostPort)

		return hostPort, err == nil
	}

	host, port, hasPort := strings.Cut(hostPort, ":")
	if strings.ContainsFunc(host, func(value rune) bool {
		return !isIRINameChar(value) && value != '%'
	}) {
		return "", false
	}

	if hasPort {
		if !asciiDigits(port) {
			return "", false
		}

		return "host:" + port, true
	}

	return "host", true
}

func isIPvFuture(host string) bool {
	if host == "" || host[0] != 'v' && host[0] != 'V' {
		return false
	}

	version, address, found := strings.Cut(host[1:], ".")

	return found && version != "" && address != "" &&
		!strings.ContainsFunc(version, func(value rune) bool {
			return !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F')
		}) &&
		!strings.ContainsFunc(address, func(value rune) bool { return !isIRINameASCII(value) && value != ':' })
}

func validIRIPortSuffix(suffix string) bool {
	return suffix == "" || suffix[0] == ':' && asciiDigits(suffix[1:])
}

func asciiDigits(value string) bool {
	return !strings.ContainsFunc(value, func(ch rune) bool { return ch < '0' || ch > '9' })
}

func isIRINameASCII(value rune) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || strings.ContainsRune("-._~!$&'()*+,;=", value)
}

func isIRINameChar(value rune) bool {
	return isIRINameASCII(value) || value >= 0xA0 && value <= 0xD7FF ||
		value >= 0xF900 && value <= 0xFDCF || value >= 0xFDF0 && value <= 0xFFEF ||
		(value >= 0x10000 && value <= 0xDFFFD || value >= 0xE1000 && value <= 0xEFFFD) && value&0xFFFF <= 0xFFFD
}

// IsAbsolute reports whether the reference has a scheme.
func (r IRIReference) IsAbsolute() bool { return r.scheme != "" }

// IsHierarchical reports whether the reference has a hierarchical form.
func (r IRIReference) IsHierarchical() bool {
	return !r.IsAbsolute() || r.hasAuthority || r.path == "" || strings.HasPrefix(r.path, "/")
}

// ResolveAgainst applies RFC 3986 section 5.2 to the original IRI components.
func (r IRIReference) ResolveAgainst(b IRIReference) string {
	// RFC 3986 section 5.2, applied directly to IRI components. Serializing
	// through net/url would escape Unicode and lose an empty fragment; decoding
	// that result would also rewrite pre-existing percent escapes (F&O 6.1).
	t := r
	if r.scheme != "" {
		t.path = removeIRIDotSegments(r.path)
	} else {
		t.scheme = b.scheme
		if r.hasAuthority {
			t.path = removeIRIDotSegments(r.path)
		} else {
			t.authority, t.hasAuthority = b.authority, b.hasAuthority
			if r.path == "" {
				t.path = b.path
				if !r.hasQuery {
					t.query, t.hasQuery = b.query, b.hasQuery
				}
			} else if strings.HasPrefix(r.path, "/") {
				t.path = removeIRIDotSegments(r.path)
			} else {
				prefix := ""
				if b.hasAuthority && b.path == "" {
					prefix = "/"
				} else if slash := strings.LastIndexByte(b.path, '/'); slash >= 0 {
					prefix = b.path[:slash+1]
				}

				t.path = removeIRIDotSegments(prefix + r.path)
			}
		}
	}

	return t.String()
}

// IRIReference holds the original spelling of a parsed reference.
type IRIReference struct {
	scheme       string
	authority    string
	path         string
	query        string
	fragment     string
	hasAuthority bool
	hasQuery     bool
	hasFragment  bool
}

func (r IRIReference) String() string {
	var b strings.Builder
	if r.scheme != "" {
		b.WriteString(r.scheme)
		b.WriteByte(':')
	}

	if r.hasAuthority {
		b.WriteString("//")
		b.WriteString(r.authority)
	}

	b.WriteString(r.path)

	if r.hasQuery {
		b.WriteByte('?')
		b.WriteString(r.query)
	}

	if r.hasFragment {
		b.WriteByte('#')
		b.WriteString(r.fragment)
	}

	return b.String()
}

// ValidatePercentEncoding checks every percent escape, including query and fragment.
func ValidatePercentEncoding(uri string) error {
	for i := 0; i < len(uri); i++ {
		if uri[i] == '%' {
			if i+2 >= len(uri) {
				return fmt.Errorf("incomplete percent-encoding at position %d", i)
			}

			if !xmlchar.IsHexDigit(uri[i+1]) || !xmlchar.IsHexDigit(uri[i+2]) {
				return fmt.Errorf("invalid percent-encoding %%%c%c", uri[i+1], uri[i+2])
			}

			i += 2
		}
	}

	return nil
}

func splitIRIReference(raw string) IRIReference {
	r := IRIReference{}
	raw, r.fragment, r.hasFragment = strings.Cut(raw, "#")

	raw, r.query, r.hasQuery = strings.Cut(raw, "?")
	if colon := indexScheme(raw); colon > 0 {
		r.scheme, raw = raw[:colon], raw[colon+1:]
	}

	if strings.HasPrefix(raw, "//") {
		r.hasAuthority = true

		raw = raw[2:]
		if slash := strings.IndexByte(raw, '/'); slash >= 0 {
			r.authority, raw = raw[:slash], raw[slash:]
		} else {
			r.authority, raw = raw, ""
		}
	}

	r.path = raw

	return r
}

func removeIRIDotSegments(input string) string {
	output := make([]byte, 0, len(input))
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"), input == "/..":
			if input == "/.." {
				input = "/"
			} else {
				input = input[3:]
			}

			if slash := bytes.LastIndexByte(output, '/'); slash >= 0 {
				output = output[:slash]
			} else {
				output = output[:0]
			}
		case input == ".", input == "..":
			input = ""
		default:
			end := strings.IndexByte(input[1:], '/')
			if end < 0 {
				end = len(input)
			} else {
				end++
			}

			output = append(output, input[:end]...)
			input = input[end:]
		}
	}

	return string(output)
}

func indexScheme(raw string) int {
	for i := range len(raw) {
		switch raw[i] {
		case ':':
			return i
		case '/', '?', '#':
			return -1
		}
	}

	return -1
}
