package streamio_test

import (
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/streamio"
)

func TestBase64DecoderPaddingBoundaries(t *testing.T) {
	for _, text := range []string{"TQ==", "TWE=", "TWFu", "TQ==\r\n", "TQ=\n="} {
		want, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		for split := 0; split <= len(text); split++ {
			source := io.MultiReader(strings.NewReader(text[:split]), strings.NewReader(text[split:]))
			got, err := io.ReadAll(streamio.NewBase64Decoder(base64.StdEncoding.Strict(), source))
			if err != nil || string(got) != string(want) {
				t.Fatalf("%q split %d: got=%q err=%v", text, split, got, err)
			}
		}
	}

	for _, text := range []string{"TQ==AAAA", "TWE=AAAA", "TQ===", "TQ==\r\nTQ==", "TQ==!"} {
		for split := 0; split <= len(text); split++ {
			source := io.MultiReader(strings.NewReader(text[:split]), strings.NewReader(text[split:]))
			_, err := io.ReadAll(streamio.NewBase64Decoder(base64.StdEncoding.Strict(), source))
			if _, ok := errors.AsType[base64.CorruptInputError](err); !ok {
				t.Fatalf("%q split %d accepted: %v", text, split, err)
			}
		}
	}
}

func TestBase64DecoderCorruptionIsNotEOF(t *testing.T) {
	source := inputFunc(func(dst []byte) (int, error) { return copy(dst, "TQ==AAAA"), io.EOF })
	_, err := io.ReadAll(streamio.NewBase64Decoder(base64.StdEncoding.Strict(), source))
	var corrupt base64.CorruptInputError
	if !errors.As(err, &corrupt) || errors.Is(err, io.EOF) {
		t.Fatalf("corruption must not look like successful EOF: %v", err)
	}
}
