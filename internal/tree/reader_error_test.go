package tree_test

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestParseReaderPreservesSourceFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("entity source failed")
	for _, input := range []struct{ name, xml string }{
		{"complete root", `<r/>`},
		{"trailing whitespace", `<r/> `},
		{"unfinished comment", `<r><!--unfinished`},
		{"DTD entity", `<!DOCTYPE r [<!ENTITY e "value">]><r>&e;</r>`},
	} {
		for _, delivery := range []struct {
			name     string
			withData bool
		}{{"after final bytes", false}, {"with final bytes", true}} {
			for _, sourceError := range []struct {
				name string
				err  error
			}{{"source failure", failure}, {"EOF joined with source failure", errors.Join(io.EOF, failure)}} {
				t.Run(input.name+"/"+delivery.name+"/"+sourceError.name, func(t *testing.T) {
					t.Parallel()
					reader := io.MultiReader(strings.NewReader(input.xml), iotest.ErrReader(sourceError.err))
					if delivery.withData {
						reader = iotest.DataErrReader(reader)
					}
					doc, err := (tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}).ParseReader(t.Context(), reader)
					if doc != nil || !errors.Is(err, failure) {
						t.Fatalf("document=%v error=%v; want source failure", doc != nil, err)
					}
				})
			}
		}
	}
}
