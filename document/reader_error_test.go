package document_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
)

// A terminal error can accompany the final bytes or arrive on a subsequent
// read. Only the exact io.EOF value denotes successful stream completion.
func TestXMLReadersPreserveTerminalErrors(t *testing.T) {
	t.Parallel()
	failure := errors.New("source integrity check failed")
	for _, sourceError := range []struct {
		name string
		err  error
	}{{"source failure", failure}, {"EOF joined with source failure", errors.Join(io.EOF, failure)}} {
		for _, delivery := range []struct {
			name     string
			withData bool
		}{{"after final bytes", false}, {"with final bytes", true}} {
			t.Run(sourceError.name+"/"+delivery.name, func(t *testing.T) {
				t.Parallel()
				reader := &terminalXMLReader{data: "<r><item/></r>", terminalErr: sourceError.err, withData: delivery.withData}
				doc, err := document.ParseReader(t.Context(), reader, document.DefaultLimits())
				if doc != nil || !errors.Is(err, failure) {
					t.Fatalf("ParseReader returned document=%v error=%v; want source failure", doc != nil, err)
				}

				reader = &terminalXMLReader{data: "<r><item/></r>", terminalErr: sourceError.err, withData: delivery.withData}
				err = document.ReadRecords(t.Context(), reader, document.RecordOptions{
					Path: []document.Name{{Local: "r"}, {Local: "item"}},
				}, func(*document.Document) error { return nil })
				if !errors.Is(err, failure) {
					t.Fatalf("ReadRecords returned %v; want source failure", err)
				}
			})
		}
	}

	if _, err := document.ParseReader(t.Context(), strings.NewReader("<r/>"), document.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

type terminalXMLReader struct {
	data        string
	terminalErr error
	withData    bool
}

func (r *terminalXMLReader) Read(dst []byte) (int, error) {
	n := copy(dst, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 && (n == 0 || r.withData) {
		return n, r.terminalErr
	}
	return n, nil
}
