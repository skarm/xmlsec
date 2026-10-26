package encoding //nolint:testpackage // Checks consumed-byte and carry-state contracts of private transformers.

import (
	"bytes"
	"errors"
	"testing"

	enc "golang.org/x/text/encoding"
	"golang.org/x/text/transform"
)

// A Transformer may retain state after atEOF until Reset starts a new stream.
// Unlike codecs that reset their shift mode at EOF, this probe makes omitting
// the repertoire closure's reset observable on its second call.
type singleScalarEncoder struct{ dirty bool }

func (e *singleScalarEncoder) Reset() { e.dirty = false }
func (e *singleScalarEncoder) Transform(dst, src []byte, _ bool) (int, int, error) {
	if e.dirty {
		return 0, 0, ErrInvalidEncodedChar
	}
	if len(dst) < len(src) {
		return 0, 0, transform.ErrShortDst
	}
	e.dirty = true
	return copy(dst, src), len(src), nil
}

func TestRepertoireStartsEachProbeAsAnIndependentStream(t *testing.T) {
	t.Parallel()

	encoder := &singleScalarEncoder{}
	probe := Repertoire(&enc.Encoder{Transformer: encoder})
	if !probe('A') || !probe('B') || !probe('C') {
		t.Fatal("repertoire did not reset encoder state between independent scalar probes")
	}
}

func TestStrictValidatorCarriesBOMAndSurrogatesAcrossChunks(t *testing.T) {
	t.Parallel()

	validator := strictDecoderTransformer{base: transform.Nop, width: 2, order: orderLE2, useBOM: true}
	for _, chunk := range [][]byte{{0xfe}, {0xff, 0xd8}, {0}, {0xdc}, {0}} {
		if err := validator.validate(chunk, false); err != nil {
			t.Fatalf("valid split BOM/surrogate %x: %v", chunk, err)
		}
	}
	if err := validator.validate(nil, true); err != nil {
		t.Fatal("complete pair rejected at EOF", err)
	}
	validator.Reset()
	if err := validator.validate([]byte{0xd8, 0}, true); err != nil {
		t.Fatal("Reset did not restore default LE order", err)
	}
	for _, partial := range [][]byte{{0xfe}, {0xff, 0xfe, 0, 0xd8}} {
		validator.Reset()
		if err := validator.validate(partial, false); err != nil {
			t.Fatal("partial unit should wait for more input", err)
		}
		validator.Reset()
		if err := validator.validate([]byte{0xd8, 0}, true); err != nil {
			t.Fatal("Reset retained an incomplete unit", partial, err)
		}
	}
	for _, test := range []struct {
		name      string
		chunks    [][]byte
		malformed bool
	}{
		{"incomplete BOM", [][]byte{{0xfe}}, true},
		{"unpaired high surrogate", [][]byte{{0xff, 0xfe, 0, 0xd8}}, true},
		{"high then non-low", [][]byte{{0xff, 0xfe, 0, 0xd8}, {0x41, 0}}, true},
		{"unpaired low", [][]byte{{0xff, 0xfe}, {0, 0xdc}}, true},
		{"odd trailing byte", [][]byte{{0xff, 0xfe, 0x41}}, true},
		{"empty", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator := strictDecoderTransformer{base: transform.Nop, width: 2, order: orderLE2, useBOM: true}
			var err error
			for _, chunk := range test.chunks {
				if err = validator.validate(chunk, false); err != nil {
					break
				}
			}
			if err == nil {
				err = validator.validate(nil, true)
			}
			if test.malformed && !errors.Is(err, ErrInvalidEncodedChar) || !test.malformed && err != nil {
				t.Fatalf("validate = %v; malformed=%v", err, test.malformed)
			}
		})
	}
}

func TestTransformShortBuffersPreserveConsumedCounts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name             string
		transformer      transform.Transformer
		src              []byte
		size, nDst, nSrc int
		want             []byte
		err              error
	}{
		{"ASCII destination", asciiDecoder{}, []byte("AB"), 1, 1, 1, []byte("A"), transform.ErrShortDst},
		{"ASCII invalid after prefix", asciiDecoder{}, []byte{'A', 0x80}, 4, 1, 1, []byte("A"), ErrInvalidASCII},
		{"C1 decoder multibyte output", Load("iso-8859-1").NewDecoder(), []byte{'A', 0xe9}, 2, 1, 1, []byte("A"), transform.ErrShortDst},
		{"C1 encoder destination", Load("iso-8859-1").NewEncoder(), []byte("A\u0081"), 1, 1, 1, []byte("A"), transform.ErrShortDst},
		{"C1 encoder incomplete UTF8", Load("iso-8859-1").NewEncoder(), []byte{0xc2}, 2, 0, 0, nil, transform.ErrShortSrc},
		{"EBCDIC destination", Load("ibm1141").NewEncoder(), []byte("A€"), 1, 1, 1, []byte{0xc1}, transform.ErrShortDst},
		{"EBCDIC incomplete UTF8", Load("ibm1141").NewEncoder(), []byte{0xe2, 0x82}, 2, 0, 0, nil, transform.ErrShortSrc},
		{"EBCDIC decoder UTF8 destination", Load("ibm1141").NewDecoder(), []byte{0xc1, 0x9f}, 2, 1, 1, []byte("A"), transform.ErrShortDst},
		{"UCS4 swap destination", &ucs4SwapTransformer{swap: swap2143}, []byte{1, 2, 3, 4}, 3, 0, 0, nil, transform.ErrShortDst},
		{"UCS4 swap source", &ucs4SwapTransformer{swap: swap3412}, []byte{1, 2, 3}, 4, 0, 0, nil, transform.ErrShortSrc},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dst := make([]byte, test.size)
			nd, ns, err := test.transformer.Transform(dst, test.src, false)
			if nd != test.nDst || ns != test.nSrc || !errors.Is(err, test.err) || !bytes.Equal(dst[:nd], test.want) {
				t.Fatalf("Transform = %x (%d,%d), %v; want %x (%d,%d), %v", dst[:nd], nd, ns, err, test.want, test.nDst, test.nSrc, test.err)
			}
		})
	}
	text := []byte("123456789abcdefgé\u0081")
	got, err := Load("iso-8859-1").NewEncoder().Bytes(text)
	if err != nil || !bytes.Equal(got, append([]byte("123456789abcdefg"), 0xe9, 0x81)) {
		t.Fatalf("C1 bulk encoding %x: %v", got, err)
	}
	decoded, err := Load("iso-8859-1").NewDecoder().Bytes(got)
	if err != nil || !bytes.Equal(decoded, text) {
		t.Fatalf("C1 bulk decoder %x: %v", decoded, err)
	}
	if _, err := Load("iso-8859-1").NewEncoder().Bytes([]byte("中")); err == nil {
		t.Fatal("unrepresentable non-C1 character accepted")
	}
}
