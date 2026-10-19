// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"bytes"
	"context"
	"net/url"
	"strings"

	unparsedtext "github.com/skarm/xmlsec/transform/internal/xpath/text"
)

func baseURIFromContext(ctx context.Context) string {
	if ec := getFnContext(ctx); ec != nil {
		return ec.baseURI
	}

	return ""
}

func parseURIReference(raw string) (*url.URL, error) {
	if err := unparsedtext.ValidatePercentEncoding(raw); err != nil {
		return nil, err
	}

	return url.Parse(raw)
}

func isSupportedResourceScheme(scheme string) bool {
	switch scheme {
	case "file", "http", "https":
		return true
	default:
		return false
	}
}

func resolveURIReference(base, ref string) (string, error) {
	b, err := splitIRIReference(base)
	if err != nil {
		return "", err
	}

	r, err := splitIRIReference(ref)
	if err != nil {
		return "", err
	}

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

	return t.String(), nil
}

type iriReference struct {
	scheme, authority, path, query, fragment string
	hasAuthority, hasQuery, hasFragment      bool
}

func (r iriReference) String() string {
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

func splitIRIReference(raw string) (iriReference, error) {
	if _, err := parseURIReference(raw); err != nil {
		return iriReference{}, err
	}

	r := iriReference{}
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

	return r, nil
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
