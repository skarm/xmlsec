package tree

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

// XML serializes the snapshot without pretty-printing or changing prefixes.
// This is normal serialization, not canonicalization. The XML declaration is
// omitted; the document is always UTF-8. Returned bytes do not alias the tree.
// It collects the complete output without a separate output-byte budget.
// Use WriteXML with an explicit budget to write incrementally.
func (d *Document) XML(ctx context.Context) ([]byte, error) {
	if d == nil || d.root == nil {
		return nil, fmt.Errorf("%w: nil document", ErrMalformed)
	}

	var b bytes.Buffer
	if _, err := WriteXMLFragment(ctx, &b, d.children, int(^uint(0)>>1)); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

type xmlEscaper struct{ buffer [4096]byte }

// write replaces bytes into reusable bounded storage. The destination checks
// cancellation and limits on every flush, including within one large text node.
func (e *xmlEscaper) write(dst io.Writer, value string, replacement func(byte) string) error {
	used := 0
	flush := func() error {
		n, err := dst.Write(e.buffer[:used])
		if err == nil && n != used {
			err = io.ErrShortWrite
		}

		used = 0

		return err
	}

	for i := range len(value) {
		s := replacement(value[i])
		if s == "" {
			if used == len(e.buffer) {
				if err := flush(); err != nil {
					return err
				}
			}

			e.buffer[used] = value[i]
			used++

			continue
		}

		if len(s) > len(e.buffer)-used {
			if err := flush(); err != nil {
				return err
			}
		}

		used += copy(e.buffer[used:], s)
	}

	if used > 0 {
		return flush()
	}

	return nil
}

func xmlEscape(c byte, attribute bool) string {
	switch c {
	case '&':
		return "&amp;"
	case '<':
		return "&lt;"
	case '>':
		if !attribute {
			return "&gt;"
		}
	case '\r':
		return "&#xD;"
	case '"':
		if attribute {
			return "&quot;"
		}
	case '\t':
		if attribute {
			return "&#x9;"
		}
	case '\n':
		if attribute {
			return "&#xA;"
		}
	}

	return ""
}
