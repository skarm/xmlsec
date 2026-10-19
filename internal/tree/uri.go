package tree

import (
	"fmt"
	"net/url"
	"strings"
)

// uriReference preserves the original representation of components (including
// escape casing). url.URL.ResolveReference/path.Clean are NOT suitable for the
// C14N 1.1 modifications: leading ../ must survive and paths remain relative.
type uriReference struct {
	scheme, authority, path, query string
	hasAuthority, hasQuery         bool
}

func (r uriReference) String() string {
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

	return b.String()
}

func parseURIReference(s string) (uriReference, error) {
	// Validate URI syntax without serializing it back through net/url, which
	// can rewrite escaping. Fragment is deliberately not retained (§2.4).
	if _, err := url.Parse(s); err != nil {
		return uriReference{}, fmt.Errorf("%w: xml:base URI: %w", ErrMalformed, err)
	}

	if strings.ContainsAny(s, " \t\n\r") {
		return uriReference{}, fmt.Errorf("%w: whitespace in xml:base URI", ErrUnsupported)
	}

	r := uriReference{}
	s, _, _ = strings.Cut(s, "#")

	s, r.query, r.hasQuery = strings.Cut(s, "?")
	if colon := strings.IndexByte(s, ':'); colon >= 0 {
		slash := strings.IndexByte(s, '/')
		if slash < 0 || colon < slash {
			r.scheme = s[:colon]
			s = s[colon+1:]
		}
	}

	if strings.HasPrefix(s, "//") {
		r.hasAuthority = true

		s = s[2:]
		if slash := strings.IndexByte(s, '/'); slash >= 0 {
			r.authority = s[:slash]
			s = s[slash:]
		} else {
			r.authority = s
			s = ""
		}
	}

	r.path = s

	return r, nil
}

// joinURIReferences implements RFC 3986 §5.2 with the C14N 1.1 §2.4 changes.
func joinURIReferences(base, reference string) (string, error) {
	b, err := parseURIReference(base)
	if err != nil {
		return "", err
	}

	r, err := parseURIReference(reference)
	if err != nil {
		return "", err
	}

	if b.path == ".." || strings.HasSuffix(b.path, "/..") {
		b.path += "/"
	}

	var t uriReference
	if r.scheme != "" {
		t = r
		t.path = removeDotSegments(r.path)
	} else {
		t.scheme = b.scheme
		if r.hasAuthority {
			t.authority, t.hasAuthority = r.authority, true
			t.path = removeDotSegments(r.path)
			t.query, t.hasQuery = r.query, r.hasQuery
		} else {
			t.authority, t.hasAuthority = b.authority, b.hasAuthority
			if r.path == "" {
				t.path = b.path
				if r.hasQuery {
					t.query, t.hasQuery = r.query, true
				} else {
					t.query, t.hasQuery = b.query, b.hasQuery
				}
			} else {
				path := r.path
				if !strings.HasPrefix(path, "/") {
					if b.hasAuthority && b.path == "" {
						path = "/" + path
					} else if slash := strings.LastIndexByte(b.path, '/'); slash >= 0 {
						path = b.path[:slash+1] + path
					}
				}

				t.path = removeDotSegments(path)
				t.query, t.hasQuery = r.query, r.hasQuery
			}
		}
	}

	return t.String(), nil
}

func removeDotSegments(path string) string {
	absolute := strings.HasPrefix(path, "/")
	trailing := strings.HasSuffix(path, "/") || path == "." || path == ".." || strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..")

	segments := make([]string, 0, strings.Count(path, "/")+1)
	for part := range strings.SplitSeq(path, "/") {
		switch part {
		case "", ".":
		case "..":
			if len(segments) > 0 && segments[len(segments)-1] != ".." {
				segments = segments[:len(segments)-1]
			} else if !absolute {
				segments = append(segments, "..")
			}
		default:
			segments = append(segments, part)
		}
	}

	out := strings.Join(segments, "/")
	if absolute {
		out = "/" + out
	}

	if trailing && out != "" && !strings.HasSuffix(out, "/") {
		out += "/"
	}

	return out
}
