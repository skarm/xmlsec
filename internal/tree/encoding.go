package tree

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/streamio"
)

// EncodeBase64 encodes a resident blob into one string allocation, checking ctx
// between fixed-size chunks. It never modifies data.
func EncodeBase64(ctx context.Context, data []byte) (string, error) {
	if ctx == nil {
		return "", ErrMalformed
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	var output strings.Builder

	size := base64.StdEncoding.EncodedLen(len(data))
	output.Grow(size)
	writer := &streamio.Writer{Context: ctx, Target: &output, Limit: int64(size), LimitError: ErrLimit}
	encoder := base64.NewEncoder(base64.StdEncoding, writer)

	for len(data) > 0 {
		chunk := data[:min(len(data), 32<<10)]
		if _, err := encoder.Write(chunk); err != nil {
			return "", err
		}

		data = data[len(chunk):]
	}

	if err := errors.Join(encoder.Close(), ctx.Err()); err != nil {
		return "", err
	}

	return output.String(), nil
}

// DecodeBase64 decodes direct text nodes without joining or filtering a full
// encoded string. Only XML whitespace is skipped; comments/PIs are ignored and
// child elements are rejected. A zero textLimit leaves whitespace input bounded
// by the source document; decodedLimit always applies before allocation.
func DecodeBase64(ctx context.Context, node *Node, textLimit, decodedLimit int) ([]byte, error) {
	if ctx == nil || node == nil || textLimit < 0 || decodedLimit < 0 {
		return nil, ErrMalformed
	}

	encoded, padding, err := base64TextSize(ctx, node.Children, textLimit)
	if err != nil {
		return nil, err
	}

	if encoded > base64.StdEncoding.EncodedLen(decodedLimit) {
		return nil, ErrLimit
	}

	size := base64.StdEncoding.DecodedLen(encoded)
	if encoded%4 == 0 {
		size -= min(padding, 2)
	}

	if size > decodedLimit {
		return nil, ErrLimit
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	output := make([]byte, size)

	decoder := base64.NewDecoder(base64.StdEncoding.Strict(), &base64NodeReader{ctx: ctx, nodes: node.Children})
	if _, err := io.ReadFull(decoder, output); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var extra [1]byte
	if n, err := decoder.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, errors.Join(ErrMalformed, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return output, nil
}

func base64TextSize(ctx context.Context, nodes []*Node, textLimit int) (int, int, error) {
	text, encoded, padding := 0, 0, 0

	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}

		if node.Kind == CommentNode || node.Kind == PINode {
			continue
		}

		if node.Kind != TextNode {
			return 0, 0, ErrMalformed
		}

		if textLimit > 0 && len(node.Data) > textLimit-text {
			return 0, 0, ErrLimit
		}

		text += len(node.Data)
		for i := range len(node.Data) {
			if i&4095 == 0 {
				if err := ctx.Err(); err != nil {
					return 0, 0, err
				}
			}

			c := node.Data[i]
			if base64Space(c) {
				continue
			}

			encoded++

			if c == '=' {
				padding++
			} else if padding > 0 {
				return 0, 0, ErrMalformed
			}
		}
	}

	if encoded%4 != 0 || padding > 2 {
		return 0, 0, ErrMalformed
	}

	return encoded, padding, nil
}

type sourceEncoding struct {
	name string
	bom  bool
}

func (e sourceEncoding) accepts(label string) bool {
	if strings.EqualFold(label, e.name) {
		return true
	}

	return e.bom && e.name != nameUTF8 && strings.EqualFold(label, "UTF-16")
}

func base64Space(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

type base64NodeReader struct {
	ctx   context.Context
	nodes []*Node
	text  string
}

func (r *base64NodeReader) Read(dst []byte) (int, error) {
	used := 0
	for used < len(dst) {
		if err := r.ctx.Err(); err != nil {
			return used, err
		}

		for r.text == "" {
			if len(r.nodes) == 0 {
				if used > 0 {
					return used, nil
				}

				return 0, io.EOF
			}

			node := r.nodes[0]

			r.nodes = r.nodes[1:]
			if node.Kind == TextNode {
				r.text = node.Data
			}
		}

		span := r.text[:min(len(r.text), 4096)]

		taken := 0
		for taken < len(span) && used < len(dst) {
			c := span[taken]
			taken++

			if !base64Space(c) {
				dst[used] = c
				used++
			}
		}

		r.text = r.text[taken:]
	}

	return used, nil
}
