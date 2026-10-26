package streamio

import (
	"encoding/base64"
	"errors"
	"io"
)

// NewBase64Decoder validates padding across source reads before decoding. The
// standard decoder can accept another encoded value after a padded read. Source
// must remove any permitted whitespace other than CR/LF, which base64 ignores.
func NewBase64Decoder(encoding *base64.Encoding, source io.Reader) io.Reader {
	return base64.NewDecoder(encoding, &base64PaddingReader{source: source})
}

type base64PaddingReader struct {
	source  io.Reader
	offset  int64
	padding int
}

func (r *base64PaddingReader) Read(dst []byte) (int, error) {
	n, err := r.source.Read(dst)
	if n < 0 || n > len(dst) {
		return 0, errors.Join(io.ErrShortBuffer, err)
	}

	invalid := -1

	for i, c := range dst[:n] {
		if c == '\r' || c == '\n' {
			continue
		}

		if c == '=' {
			r.padding++
		} else if r.padding != 0 {
			invalid = i
			break
		}

		if r.padding > 2 {
			invalid = i
			break
		}
	}

	if invalid >= 0 {
		// Ordinary terminal EOF must not disguise corruption as completion.
		if err == io.EOF {
			err = nil
		}

		return 0, errors.Join(base64.CorruptInputError(r.offset+int64(invalid)), err)
	}

	r.offset += int64(n)

	return n, err
}
