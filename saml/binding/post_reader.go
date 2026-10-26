package binding

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/url"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// DecodePOSTReader decodes form fields, URL escaping, Base64 and XML directly
// from src. It retains the resulting XML snapshot and at most 80 RelayState
// bytes. Every field is checked before returning an unauthenticated message.
// It leaves src open; blocking readers must honor ctx themselves.
func DecodePOSTReader(ctx context.Context, src io.Reader, expected Parameter, limits POSTLimits) (*POSTMessage, error) {
	l, err := postLimits(limits)
	if err != nil {
		return nil, err
	}

	if ctx == nil || nilcheck.IsNil(src) || expected != Request && expected != Response {
		return nil, ErrBinding
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input := bufio.NewReader(&streamio.Reader{Context: ctx, Source: src, Limit: int64(l.MaxFormBytes), LimitError: ErrBinding})
	message := &POSTMessage{parameter: expected}
	seen := make(map[string]struct{}, 2)

	for {
		if _, err := input.Peek(1); err != nil {
			// A wrapped/joined EOF can carry a source failure; only bare EOF ends the form.
			if err == io.EOF {
				break
			}

			return nil, err
		}

		key, hasValue, err := postFieldKey(input)
		if err != nil {
			return nil, err
		}

		if key == "" && !hasValue {
			continue
		}

		if _, exists := seen[key]; exists || key != string(expected) && key != fieldRelayState {
			return nil, ErrBinding
		}

		seen[key] = struct{}{}

		value := &postValueReader{input: input, done: !hasValue}
		if key == fieldRelayState {
			if err := readPOSTRelay(message, value); err != nil {
				return nil, err
			}

			continue
		}

		decoded := streamio.NewBase64Decoder(base64.StdEncoding.Strict(), value)
		bounded := &streamio.Reader{Context: ctx, Source: decoded, Limit: int64(l.MaxXMLBytes), LimitError: ErrBinding}

		message.doc, err = document.ParseReader(ctx, bounded, l.XMLLimits)
		if err != nil {
			return nil, err
		}
	}

	if message.doc == nil {
		return nil, ErrBinding
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return message, nil
}

func readPOSTRelay(message *POSTMessage, value io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(value, 81))
	if err != nil {
		return err
	}

	if len(raw) > 80 {
		return ErrBinding
	}

	message.hasRelay = true
	message.relay = string(raw)

	return nil
}

func postFieldKey(input *bufio.Reader) (string, bool, error) {
	var encoded [64]byte

	used := 0

	for {
		c, err := input.ReadByte()
		if err != nil {
			// Preserve a source failure accompanying EOF instead of accepting a partial key.
			if err != io.EOF {
				return "", false, err
			}

			key, err := url.QueryUnescape(string(encoded[:used]))
			if err != nil {
				return "", false, ErrBinding
			}

			return key, false, nil
		}

		if c == '=' || c == '&' {
			key, err := url.QueryUnescape(string(encoded[:used]))
			if err != nil {
				return "", false, ErrBinding
			}

			return key, c == '=', nil
		}

		if c == ';' || used == len(encoded) {
			return "", false, ErrBinding
		}

		encoded[used] = c
		used++
	}
}

type postValueReader struct {
	input *bufio.Reader
	done  bool
}

func (r *postValueReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	if r.done {
		return 0, io.EOF
	}

	used := 0
	for used < len(dst) {
		c, err := r.input.ReadByte()
		if err != nil {
			// Only bare EOF marks the field complete; joined errors must reach the decoder.
			if err == io.EOF {
				r.done = true
			}

			return used, err
		}

		switch c {
		case '&':
			r.done = true
			return used, io.EOF
		case ';':
			return used, ErrBinding
		case '+':
			c = ' '
		case '%':
			high, err := r.input.ReadByte()
			if err != nil {
				return used, errors.Join(ErrBinding, err)
			}

			low, err := r.input.ReadByte()
			if err != nil {
				return used, errors.Join(ErrBinding, err)
			}

			h, l := formHex(high), formHex(low)
			if h < 0 || l < 0 {
				return used, ErrBinding
			}

			c = byte((h*16 + l) & 255)
		}

		dst[used] = c
		used++
	}

	return used, nil
}

func formHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}

	return -1
}
