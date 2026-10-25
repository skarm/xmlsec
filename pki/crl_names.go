package pki

import (
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
)

const (
	crlSchemeFTP  = "ftp"
	crlSchemeLDAP = "ldap"
)

// crlURIKey performs RFC5280§7.4's local comparison preparation. The original
// signed URI remains untouched. Reserved escapes, query delimiters, path case
// and fragments are significant; only unreserved escapes are decoded.
func crlURIKey(raw string) string {
	raw = normalizeCRLPercent(raw)

	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() {
		return raw
	}

	scheme, tail, _ := strings.Cut(raw, ":")
	scheme = strings.ToLower(scheme)
	authority := ""

	if strings.HasPrefix(tail, "//") {
		tail = tail[2:]

		stop := strings.IndexAny(tail, "/?#")
		if stop < 0 {
			stop = len(tail)
		}

		authority, tail = tail[:stop], tail[stop:]

		prefix, host, found := strings.Cut(authority, "@")
		if !found {
			host = prefix
			prefix = ""
		} else {
			prefix += "@"
		}

		host = strings.ToLower(host)
		port := ""

		switch scheme {
		case lexicon.SchemeHTTP:
			port = "80"
		case lexicon.SchemeHTTPS:
			port = "443"
		case crlSchemeFTP:
			port = "21"
		case crlSchemeLDAP:
			port = "389"
		}

		if port != "" {
			host = strings.TrimSuffix(host, ":"+port)
			host = strings.TrimSuffix(host, ":")
		}

		authority = "//" + prefix + host
	}

	stop := strings.IndexAny(tail, "?#")
	if stop < 0 {
		stop = len(tail)
	}

	path, suffix := removeCRLDotSegments(tail[:stop]), tail[stop:]
	if path == "" && authority != "" {
		switch scheme {
		case lexicon.SchemeHTTP, lexicon.SchemeHTTPS, crlSchemeFTP, crlSchemeLDAP:
			path = "/"
		}
	}

	return scheme + ":" + authority + path + suffix
}

func normalizeCRLPercent(value string) string {
	const hex = "0123456789ABCDEF"

	out := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '%' || index+2 >= len(value) {
			out = append(out, value[index])
			continue
		}

		a, b := crlHex(value[index+1]), crlHex(value[index+2])
		if a < 0 || b < 0 {
			out = append(out, value[index])
			continue
		}

		c := byte(a&15)*16 + byte(b&15)
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c)) {
			out = append(out, c)
		} else {
			out = append(out, '%', hex[c>>4], hex[c&15])
		}

		index += 2
	}

	return string(out)
}

func crlHex(value byte) int {
	switch {
	case value >= '0' && value <= '9':
		return int(value - '0')
	case value >= 'a' && value <= 'f':
		return int(value - 'a' + 10)
	case value >= 'A' && value <= 'F':
		return int(value - 'A' + 10)
	}

	return -1
}

func removeCRLDotSegments(input string) string {
	out := make([]byte, 0, len(input))
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
		case strings.HasPrefix(input, "/../") || input == "/..":
			input = strings.TrimPrefix(input, "/..")
			if input == "" {
				input = "/"
			}

			if index := strings.LastIndexByte(string(out), '/'); index >= 0 {
				out = out[:index]
			} else {
				out = out[:0]
			}
		case input == "." || input == "..":
			input = ""
		default:
			start := 0
			if input[0] == '/' {
				start = 1
			}

			index := strings.IndexByte(input[start:], '/')
			if index < 0 {
				out = append(out, input...)
				input = ""
			} else {
				index += start
				out = append(out, input[:index]...)
				input = input[index:]
			}
		}
	}

	return string(out)
}

func equalCRLMailbox(a, b string) bool {
	localA, hostA, okA := strings.Cut(a, "@")
	localB, hostB, okB := strings.Cut(b, "@")

	return okA && okB && localA == localB && strings.EqualFold(hostA, hostB)
}

// A stored GeneralName URI uses RFC3986 ASCII syntax, not net/url's permissive
// browser-oriented parser. In particular, an absolute URI needs a nonempty
// scheme-specific part and an authority, when present, needs a host.
func validCRLURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() {
		return false
	}

	_, tail, _ := strings.Cut(raw, ":")
	if tail == "" {
		return false
	}

	for index := 0; index < len(raw); index++ {
		c := raw[index]
		if c == '%' {
			if index+2 >= len(raw) || crlHex(raw[index+1]) < 0 || crlHex(raw[index+2]) < 0 {
				return false
			}

			index += 2

			continue
		}

		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~:/?#[]@!$&'()*+,;=", rune(c))) {
			return false
		}
	}

	authority := strings.HasPrefix(tail, "//")
	if authority {
		if parsed.Hostname() == "" {
			return false
		}

		tail = tail[2:]
		if end := strings.IndexAny(tail, "/?#"); end >= 0 {
			tail = tail[end:]
		} else {
			tail = ""
		}
	}

	if strings.ContainsAny(tail, "[]") || strings.Count(tail, "#") > 1 {
		return false
	}

	switch strings.ToLower(parsed.Scheme) {
	case lexicon.SchemeHTTP, lexicon.SchemeHTTPS, crlSchemeFTP, crlSchemeLDAP:
		return authority
	}

	return true
}
