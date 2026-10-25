// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/lexicon"
	norm "github.com/skarm/xmlsec/internal/normalization"
	"github.com/skarm/xmlsec/transform/internal/xdm"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/unicode"
)

const (
	normalizationFormNFC  = "NFC"
	normalizationFormNone = "NONE"
	encodingASCII         = "us-ascii"
)

// resolveNormForm returns the norm.Form for the given normalization form name.
// Returns (form, true) on success or (0, false) for unknown/NONE forms.
func resolveNormForm(form string) (norm.Form, bool) {
	switch form {
	case normalizationFormNFC, lexicon.NormFullyNormalized:
		return norm.NFC, true
	case "NFD":
		return norm.NFD, true
	case "NFKC":
		return norm.NFKC, true
	case "NFKD":
		return norm.NFKD, true
	default:
		return 0, false
	}
}

// applyUnicodeNormalization applies the specified Unicode normalization form
// to text content and attribute values in serialized XML/HTML output, while
// leaving element/attribute names and markup untouched (per XSLT 3.0 spec).
func applyUnicodeNormalization(data []byte, form string) []byte {
	nf, ok := resolveNormForm(form)
	if !ok {
		return data
	}

	return normalizeXMLContent(data, nf)
}

// normalizeXMLContent applies Unicode normalization to text content and
// attribute values in serialized XML, preserving element/attribute names
// and other markup verbatim.
func normalizeXMLContent(data []byte, nf norm.Form) []byte {
	var out bytes.Buffer
	out.Grow(len(data))

	i := 0
	for i < len(data) {
		if data[i] == '<' {
			if next, handled := normalizeSpecialMarkup(&out, data, i, nf); handled {
				i = next
				continue
			}

			// Regular tag: copy tag name verbatim, normalize attribute values
			normalizeTag(&out, data, &i, nf)

			continue
		}
		// Text content outside tags — normalize it
		j := bytes.IndexByte(data[i:], '<')
		if j < 0 {
			out.Write(nf.Bytes(data[i:]))
			i = len(data)
		} else {
			out.Write(nf.Bytes(data[i : i+j]))
			i += j
		}
	}

	return out.Bytes()
}

// normalizeTag copies an XML tag, normalizing only attribute values.
func normalizeTag(out *bytes.Buffer, data []byte, pos *int, nf norm.Form) {
	i := *pos

	out.WriteByte('<')

	i++ // skip '<'

	for i < len(data) && data[i] != '>' && data[i] != ' ' && data[i] != '\t' && data[i] != '\n' && data[i] != '\r' && data[i] != '/' {
		out.WriteByte(data[i])
		i++
	}

	for i < len(data) && data[i] != '>' {
		if data[i] == '/' {
			out.WriteByte(data[i])
			i++

			continue
		}

		if data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r' {
			// Whitespace — copy verbatim
			out.WriteByte(data[i])
			i++

			continue
		}

		if data[i] == '"' || data[i] == '\'' {
			// Attribute value — normalize content
			quote := data[i]
			out.WriteByte(quote)

			i++

			start := i
			for i < len(data) && data[i] != quote {
				i++
			}

			out.Write(nf.Bytes(data[start:i]))

			if i < len(data) {
				out.WriteByte(quote)

				i++
			}

			continue
		}
		// Attribute name or '=' — copy verbatim
		out.WriteByte(data[i])
		i++
	}

	if i < len(data) {
		out.WriteByte('>') // closing '>'

		i++
	}

	*pos = i
}

// transcodeToUTF16 converts UTF-8 bytes to UTF-16 big-endian (without BOM;
// the BOM is emitted separately by the caller).
func transcodeToUTF16(w io.Writer, utf8Data []byte) error {
	enc := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)

	encoded, err := enc.NewEncoder().Bytes(utf8Data)
	if err != nil {
		return writeFullBytes(w, utf8Data)
	}

	return writeFullBytes(w, encoded)
}

// transcodeToEncoding converts UTF-8 bytes to the target encoding,
// replacing characters that cannot be represented with XML character references.
func transcodeToEncoding(w io.Writer, utf8Data []byte, encName string) error {
	codec, err := htmlindex.Get(encName)
	if err != nil {
		// Unknown encoding — fall back to writing UTF-8
		return writeFullBytes(w, utf8Data)
	}

	encoder := codec.NewEncoder()

	// Process character by character: try to encode each rune,
	// and if it fails, output a character reference instead.
	for len(utf8Data) > 0 {
		r, size := utf8.DecodeRune(utf8Data)
		if r == utf8.RuneError && size <= 1 {
			utf8Data = utf8Data[1:]
			continue
		}

		encoded, err := encoder.Bytes(utf8Data[:size])
		if err != nil {
			// Character cannot be encoded — use character reference
			ref := fmt.Sprintf("&#x%X;", r)
			if werr := writeFullString(w, ref); werr != nil {
				return werr
			}

			encoder = codec.NewEncoder()
		} else {
			if werr := writeFullBytes(w, encoded); werr != nil {
				return werr
			}
		}

		utf8Data = utf8Data[size:]
	}

	return nil
}

// normalizeText applies the requested normalization form to text. An absent
// or unsupported form leaves the text unchanged; parameter validation reports
// unsupported forms before serialization begins.
func normalizeText(text, form string) string {
	nf, ok := resolveNormForm(form)
	if !ok {
		return text
	}

	return nf.String(text)
}

// hasDOEMarkers checks if the document contains any disable-output-escaping markers.
func hasDOEMarkers(doc xdm.Node) bool {
	found := false
	// The result tree is freshly built via guarded AddChild, so it is acyclic
	// and Walk cannot return ErrWalkCycle here; the error is safely ignored.
	_ = xdm.Walk(doc, xdm.NodeWalkerFunc(func(n xdm.Node) error {
		if n.Type() == xdm.ProcessingInstructionNode && n.Name() == nameDisableOutputEscaping {
			found = true
		}

		return nil
	}))

	return found
}

// resolveCharacterMaps builds a merged character map from a list of map names.
func resolveCharacterMaps(ss *Stylesheet, names []string) map[rune]string {
	if len(names) == 0 || ss == nil || len(ss.characterMaps) == 0 {
		return nil
	}

	merged := make(map[rune]string)
	visited := make(map[string]struct{})

	var resolve func(name string)

	resolve = func(name string) {
		if _, ok := visited[name]; ok {
			return
		}

		visited[name] = struct{}{}

		cm := ss.characterMaps[name]
		if cm == nil {
			return
		}
		// Resolve referenced maps first (lower priority)
		for _, ref := range cm.UseCharacterMaps {
			resolve(ref)
		}
		// This map's entries override
		maps.Copy(merged, cm.Mappings)
	}
	for _, name := range names {
		resolve(name)
	}

	if len(merged) == 0 {
		return nil
	}

	return merged
}

func normalizeSpecialMarkup(out *bytes.Buffer, data []byte, start int, nf norm.Form) (int, bool) {
	next := start + 1
	if next >= len(data) {
		return start, false
	}

	if data[next] == '!' {
		if next+1 < len(data) && data[next+1] == '-' {
			return copyMarkup(out, data, start, "-->"), true
		}

		if bytes.HasPrefix(data[start:], []byte("<![CDATA[")) {
			return normalizeCDATASection(out, data, start, nf), true
		}
	}

	if data[next] == '?' {
		return copyMarkup(out, data, start, "?>"), true
	}

	return start, false
}

func copyMarkup(out *bytes.Buffer, data []byte, start int, closing string) int {
	end := bytes.Index(data[start:], []byte(closing))
	if end < 0 {
		out.Write(data[start:])
		return len(data)
	}

	next := start + end + len(closing)
	out.Write(data[start:next])

	return next
}

func normalizeCDATASection(out *bytes.Buffer, data []byte, start int, nf norm.Form) int {
	end := bytes.Index(data[start:], []byte("]]>"))
	if end < 0 {
		out.Write(data[start:])
		return len(data)
	}

	contentStart := start + 9
	out.Write(data[start:contentStart])
	out.Write(nf.Bytes(data[contentStart : start+end]))
	out.WriteString("]]>")

	return start + end + 3
}
