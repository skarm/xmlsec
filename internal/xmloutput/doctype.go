// Package xmloutput supplies XML output rules shared by the language serializers.
package xmloutput

import (
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/xmlchar"
)

// ValidPublicID reports whether value consists of XML PubidChars.
func ValidPublicID(value string) bool {
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" \r\n-'()+,./:=?;!*#@$_%", r)) {
			return false
		}
	}

	return utf8.ValidString(value)
}

// ValidSystemID reports whether value can be represented as an XML SystemLiteral.
func ValidSystemID(value string) bool {
	if !utf8.ValidString(value) || strings.ContainsRune(value, '\'') && strings.ContainsRune(value, '"') {
		return false
	}

	for _, r := range value {
		if !xmlchar.IsChar(r) {
			return false
		}
	}

	return true
}

// Quote chooses an enclosing quote. The caller must first validate the literal.
func Quote(value string, preferred byte) byte {
	if preferred != '\'' {
		preferred = '"'
	}

	if strings.ContainsRune(value, rune(preferred)) {
		if preferred == '"' {
			return '\''
		}

		return '"'
	}

	return preferred
}

// WriteDoctype validates and writes output metadata, without an internal subset.
func WriteDoctype(dst io.Writer, name, publicID, systemID string) error {
	return writeDoctype(dst, name, publicID, systemID, false)
}

// WriteHTMLDoctype also permits a PUBLIC identifier without a SYSTEM identifier.
func WriteHTMLDoctype(dst io.Writer, name, publicID, systemID string) error {
	return writeDoctype(dst, name, publicID, systemID, true)
}

func writeDoctype(dst io.Writer, name, publicID, systemID string, publicOnly bool) error {
	if dst == nil || !xmlchar.IsValidName(name) || !ValidPublicID(publicID) || !ValidSystemID(systemID) || !publicOnly && publicID != "" && systemID == "" {
		return errors.New("invalid XML doctype")
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE ")
	b.WriteString(name)

	if publicID != "" {
		b.WriteString(" PUBLIC ")
		writeLiteral(&b, publicID)
	} else if systemID != "" {
		b.WriteString(" SYSTEM")
	}

	if systemID != "" {
		b.WriteByte(' ')
		writeLiteral(&b, systemID)
	}

	b.WriteByte('>')
	value := b.String()

	n, err := io.WriteString(dst, value)
	if err == nil && n != len(value) {
		return io.ErrShortWrite
	}

	return err
}

func writeLiteral(b *strings.Builder, value string) {
	quote := Quote(value, '"')
	b.WriteByte(quote)
	b.WriteString(value)
	b.WriteByte(quote)
}
