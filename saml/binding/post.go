package binding

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"net/url"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// ErrBinding reports invalid SAML POST binding.
var ErrBinding = errors.New("invalid SAML POST binding")

// Parameter identifies a SAMLRequest or SAMLResponse POST form field.
type Parameter = Kind

// POSTLimits bounds form decoding and XML parsing. A POST message carries XML
// signatures; decoding alone authenticates nothing.
type POSTLimits struct {
	// MaxFormBytes bounds the encoded form; zero selects 2 MiB, with a 16 MiB maximum.
	MaxFormBytes int
	// MaxXMLBytes bounds decoded XML; zero selects 1 MiB, with an 8 MiB maximum.
	MaxXMLBytes int
	// XMLLimits bounds parsing and is intersected with MaxXMLBytes.
	// Zero selects document.DefaultLimits.
	XMLLimits document.Limits
}

// POSTMessage holds decoded, unauthenticated POST data. Protocol verification is required
// before accepting it.
type POSTMessage struct {
	doc       *document.Document
	parameter Parameter
	relay     string
	hasRelay  bool
}

// DecodePOST decodes an unambiguous bounded form through DecodePOSTReader.
func DecodePOST(ctx context.Context, form []byte, expected Parameter, limits POSTLimits) (*POSTMessage, error) {
	return DecodePOSTReader(ctx, bytes.NewReader(form), expected, limits)
}

// UnverifiedDocument returns the immutable decoded document; it has not been
// authenticated.
func (p *POSTMessage) UnverifiedDocument() *document.Document {
	if p == nil {
		return nil
	}

	return p.doc
}

// Parameter returns the POST form field name.
func (p *POSTMessage) Parameter() Parameter {
	if p == nil {
		return ""
	}

	return p.parameter
}

// RelayState returns the opaque relay state, with a separate presence flag where
// applicable.
func (p *POSTMessage) RelayState() (string, bool) {
	if p == nil {
		return "", false
	}

	return p.relay, p.hasRelay
}

// EncodePOST returns a complete URL-encoded POST form by collecting WritePOST.
func EncodePOST(ctx context.Context, doc *document.Document, p Parameter, relay *string, limits POSTLimits) ([]byte, error) {
	var out bytes.Buffer
	if _, err := WritePOST(ctx, &out, doc, p, relay, limits); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// WritePOST serializes XML through Base64 and URL escaping directly into dst.
// It retains the input tree and serialization/encoding state, without collecting
// the complete form unless dst does. It leaves dst open; errors can leave a
// partial form that the caller must discard.
func WritePOST(ctx context.Context, dst io.Writer, doc *document.Document, p Parameter, relay *string, limits POSTLimits) (int64, error) {
	l, err := postLimits(limits)
	if err != nil {
		return 0, err
	}

	if err := postArguments(ctx, dst, doc, p, relay); err != nil {
		return 0, err
	}

	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: int64(l.MaxFormBytes), LimitError: ErrBinding}
	if relay != nil {
		if _, err := writer.WriteString("RelayState=" + url.QueryEscape(*relay) + "&"); err != nil {
			return writer.Written, err
		}
	}

	if _, err := writer.WriteString(string(p) + "="); err != nil {
		return writer.Written, err
	}

	err = writePOSTXML(ctx, &queryBase64Writer{dst: writer}, doc, l.MaxXMLBytes)

	return writer.Written, errors.Join(err, ctx.Err())
}

// RenderPOSTForm collects WritePOSTForm into complete HTML bytes. It contains
// no inline scripts or automatic navigation; endpoint must be application-trusted.
func RenderPOSTForm(ctx context.Context, endpoint string, doc *document.Document, p Parameter, relay *string, limits POSTLimits) ([]byte, error) {
	var out bytes.Buffer
	if _, err := WritePOSTForm(ctx, &out, endpoint, doc, p, relay, limits); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// WritePOSTForm writes HTML and serializes XML through Base64 directly into its
// hidden field, without intermediate XML or encoded-message buffers. It leaves
// dst open; errors may leave partial output which must be discarded.
func WritePOSTForm(ctx context.Context, dst io.Writer, endpoint string, doc *document.Document, p Parameter, relay *string, limits POSTLimits) (int64, error) {
	if !profile.Endpoint(endpoint, false) {
		return 0, ErrBinding
	}

	if relay != nil {
		if !utf8.ValidString(*relay) {
			return 0, ErrBinding
		}

		for _, r := range *relay {
			if r < 32 || r == 127 {
				return 0, ErrBinding
			}
		}
	}

	l, err := postLimits(limits)
	if err != nil {
		return 0, err
	}

	if err := postArguments(ctx, dst, doc, p, relay); err != nil {
		return 0, err
	}

	writer := &streamio.Writer{Context: ctx, Target: dst, Limit: int64(l.MaxFormBytes), LimitError: ErrBinding}

	prefix := `<!doctype html><html><head><meta charset="utf-8"><title>SAML message</title></head><body><form method="post" action="` + html.EscapeString(endpoint) + `"><input type="hidden" name="` + string(p) + `" value="`
	if _, err := writer.WriteString(prefix); err != nil {
		return writer.Written, err
	}

	if err := writePOSTXML(ctx, writer, doc, l.MaxXMLBytes); err != nil {
		return writer.Written, err
	}

	suffix := `">`
	if relay != nil {
		suffix += `<input type="hidden" name="RelayState" value="` + html.EscapeString(*relay) + `">`
	}

	suffix += `<button type="submit">Continue</button></form></body></html>`
	_, err = writer.WriteString(suffix)

	return writer.Written, errors.Join(err, ctx.Err())
}

func postLimits(l POSTLimits) (POSTLimits, error) {
	if l.MaxFormBytes == 0 {
		l.MaxFormBytes = 2 << 20
	}

	if l.MaxXMLBytes == 0 {
		l.MaxXMLBytes = 1 << 20
	}

	if l.MaxFormBytes < 1 || l.MaxFormBytes > 16<<20 || l.MaxXMLBytes < 1 || l.MaxXMLBytes > 8<<20 {
		return l, ErrBinding
	}

	l.XMLLimits = xmlutil.XMLLimits(l.XMLLimits, l.MaxXMLBytes)

	return l, nil
}

func postArguments(ctx context.Context, dst io.Writer, doc *document.Document, p Parameter, relay *string) error {
	if ctx == nil || nilcheck.IsNil(dst) || doc == nil || p != Request && p != Response || relay != nil && len(*relay) > 80 {
		return ErrBinding
	}

	return ctx.Err()
}

func writePOSTXML(ctx context.Context, dst io.Writer, doc *document.Document, maximum int) error {
	encoder := base64.NewEncoder(base64.StdEncoding, dst)
	if _, err := doc.WriteXML(ctx, encoder, maximum); err != nil {
		if errors.Is(err, document.ErrLimit) {
			return errors.Join(ErrBinding, err)
		}

		return err
	}

	return errors.Join(encoder.Close(), ctx.Err())
}

// queryBase64Writer URL-escapes the Base64 alphabet in fixed storage.
type queryBase64Writer struct {
	dst    io.Writer
	buffer [4096]byte
}

func (w *queryBase64Writer) Write(source []byte) (int, error) {
	consumed := 0

	for len(source) > 0 {
		used, n := 0, 0
		for n < len(source) && used+3 <= len(w.buffer) {
			var escape string

			switch source[n] {
			case '+':
				escape = "%2B"
			case '/':
				escape = "%2F"
			case '=':
				escape = "%3D"
			}

			if escape != "" {
				used += copy(w.buffer[used:], escape)
			} else {
				w.buffer[used] = source[n]
				used++
			}

			n++
		}

		written, err := w.dst.Write(w.buffer[:used])
		if err == nil && written != used {
			err = io.ErrShortWrite
		}

		if err != nil {
			return consumed, err
		}

		consumed += n
		source = source[n:]
	}

	return consumed, nil
}
