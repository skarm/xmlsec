package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
)

func TestRun(t *testing.T) {
	var output bytes.Buffer
	if err := run(t.Context(), strings.NewReader(`<feed><item id="1">a</item><item id="2">b</item></feed>`), &output); err != nil {
		t.Fatal(err)
	}

	if output.String() != `<record id="1">a</record>`+"\n"+`<record id="2">b</record>` {
		t.Fatal(output.String())
	}
}

func TestRunPartialOutput(t *testing.T) {
	first := `<feed><item id="1">a</item>`
	for _, tt := range []struct {
		name   string
		source string
		want   error
	}{
		{name: "invalid enclosing XML", source: first + `</broken>`, want: document.ErrMalformed},
		{name: "record byte limit", source: first + `<item>` + strings.Repeat("x", 1<<20) + `</item></feed>`, want: document.ErrLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(t.Context(), strings.NewReader(tt.source), &output); !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}

			if output.String() != `<record id="1">a</record>` {
				t.Fatalf("earlier output changed after later failure: %q", output.String())
			}
		})
	}
}
