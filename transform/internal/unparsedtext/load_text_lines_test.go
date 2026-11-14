package unparsedtext_test

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/unparsedtext"
)

func TestLoadTextLinesRecognizesXMLDeclaredEncoding(t *testing.T) {
	const declaration = `<?xml version="1.0" encoding='iso-8859-1'?>`
	body := mediaReader{
		trackedReader: &trackedReader{Reader: strings.NewReader(declaration + "\r\ncaf\xe9\rfin")},
		media:         "application/example+xml",
	}
	cfg := &unparsedtext.Config{URIResolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) { return body, nil })}
	lines, err := unparsedtext.LoadTextLines(t.Context(), cfg, textResourceURI, "")
	want := []string{declaration, "café", "fin"}
	if err != nil || !slices.Equal(lines, want) || !body.closed {
		t.Errorf("LoadTextLines = (%q, %v), closed=%t, want (%q, nil) and closed reader", lines, err, body.closed, want)
	}
}
