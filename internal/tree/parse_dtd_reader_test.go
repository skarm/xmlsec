package tree_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestParseDTDReaderDecodesAndNormalizesPhysicalEntity(t *testing.T) {
	t.Parallel()

	const xml = "<?xml version='1.0' encoding='UTF-16'?><!DOCTYPE r><r>é\r\nβ\r終&#13;</r>"
	units := utf16.Encode([]rune(xml))
	encoded := make([]byte, 0, 2+2*len(units))
	encoded = append(encoded, 0xff, 0xfe)
	for _, unit := range units {
		encoded = append(encoded, byte(unit), byte(unit>>8))
	}
	options := treepkg.ParseOptions{Limits: treepkg.DefaultLimits(), AllowDTD: true}
	doc, err := options.ParseReader(t.Context(), iotest.OneByteReader(bytes.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := doc.Root().Text(), "é\nβ\n終\r"; got != want {
		t.Errorf("root text = %q, want %q", got, want)
	}
	if dtd, ok := doc.DTD(); !ok || dtd.Name != "r" {
		t.Errorf("document type = %+v, %v, want r", dtd, ok)
	}
}

func TestParseDTDReaderLoadsConditionalDeclarations(t *testing.T) {
	t.Parallel()

	const subset = `<?xml encoding="UTF-8"?>
		<![INCLUDE[
			<!ELEMENT r EMPTY>
			<!ATTLIST r label CDATA "catalog">
			<?index ready ?>
			<![IGNORE[<!ATTLIST r ignored CDATA "pass"> <![nested]]>]]>
			<!NOTATION png SYSTEM "image/png">
		]]>`
	const base, subsetBase = "urn:example:document", "urn:example:subset"
	var calls int
	stream := &dtdReaderFixture{Reader: iotest.OneByteReader(strings.NewReader(subset))}
	options := treepkg.ParseOptions{
		Limits:   treepkg.DefaultLimits(),
		AllowDTD: true,
		BaseURI:  base,
		DTDResolver: func(_ context.Context, systemID, retrievalBase string) (io.ReadCloser, string, error) {
			calls++
			if systemID != "catalog.dtd" || retrievalBase != base {
				t.Errorf("resolver identifiers = %q, %q, want catalog.dtd and %q", systemID, retrievalBase, base)
			}
			return stream, subsetBase, nil
		},
	}
	const input = `<!DOCTYPE r PUBLIC " -//Example   Catalog//EN " "catalog.dtd"><r/>`
	doc, err := options.ParseReader(t.Context(), iotest.OneByteReader(strings.NewReader(input)))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || stream.closed != 1 {
		t.Errorf("resolver calls = %d, closes = %d, want one of each", calls, stream.closed)
	}
	wantAttrs := []treepkg.Attribute{{Name: treepkg.Name{Local: "label"}, Value: "catalog"}}
	if got := treepkg.Root(doc).Attrs; !slices.Equal(got, wantAttrs) {
		t.Errorf("root attributes = %+v, want %+v", got, wantAttrs)
	}
	dtd, ok := doc.DTD()
	if !ok || dtd.SystemID != "catalog.dtd" || dtd.PublicID != "-//Example Catalog//EN" {
		t.Fatalf("DTD = %+v, %v, want normalized public and system identifiers", dtd, ok)
	}
	wantNotation := treepkg.Notation{SystemID: "image/png", BaseURI: subsetBase}
	if got := dtd.Notations["png"]; got != wantNotation {
		t.Errorf("png notation = %+v, want %+v", got, wantNotation)
	}
	wantInstructions := []treepkg.ProcessingInstruction{{Target: "index", Data: "ready ", BaseURI: subsetBase}}
	if !slices.Equal(dtd.ProcessingInstructions, wantInstructions) {
		t.Errorf("DTD instructions = %+v, want %+v", dtd.ProcessingInstructions, wantInstructions)
	}
}

func TestParseDTDReaderChecksSubsetResultAndClosesStream(t *testing.T) {
	t.Parallel()

	readErr := errors.New("fixture read failure")
	closeErr := errors.New("fixture close failure")
	for _, tc := range []struct {
		name    string
		source  func() io.Reader
		onClose error
		want    error
	}{
		{"invalid-conditional-keyword", func() io.Reader { return strings.NewReader(`<![UNKNOWN[<!ELEMENT r EMPTY>]]>`) }, nil, treepkg.ErrMalformed},
		{"unterminated-ignore", func() io.Reader { return strings.NewReader(`<![IGNORE[unused`) }, nil, treepkg.ErrMalformed},
		{"reader-failure", func() io.Reader { return iotest.ErrReader(readErr) }, closeErr, readErr},
		{"close-failure", func() io.Reader { return strings.NewReader(`<!ELEMENT r EMPTY>`) }, closeErr, closeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stream := &dtdReaderFixture{Reader: tc.source(), closeErr: tc.onClose}
			options := treepkg.ParseOptions{
				Limits: treepkg.DefaultLimits(), AllowDTD: true,
				DTDResolver: func(context.Context, string, string) (io.ReadCloser, string, error) {
					return stream, "urn:example:subset", nil
				},
			}
			doc, err := options.ParseReader(t.Context(), strings.NewReader(`<!DOCTYPE r SYSTEM "catalog.dtd"><r/>`))
			if doc != nil || !errors.Is(err, tc.want) {
				t.Errorf("ParseReader result = %v, %v, want nil document and %v", doc, err, tc.want)
			}
			if tc.onClose != nil && !errors.Is(err, tc.onClose) {
				t.Errorf("ParseReader error = %v, want close error %v", err, tc.onClose)
			}
			if stream.closed != 1 {
				t.Errorf("stream closes = %d, want 1", stream.closed)
			}
		})
	}
}

type dtdReaderFixture struct {
	io.Reader
	closeErr error
	closed   int
}

func (r *dtdReaderFixture) Close() error {
	r.closed++
	return r.closeErr
}
