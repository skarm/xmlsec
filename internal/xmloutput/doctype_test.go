package xmloutput_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/xmloutput"
)

const rootElement = "root"

func TestWriteDoctype(t *testing.T) {
	for _, tc := range []struct {
		name   string
		public string
		system string
		want   string
		html   bool
	}{
		{name: rootElement, want: "<!DOCTYPE root>"},
		{name: rootElement, system: "urn:test", want: `<!DOCTYPE root SYSTEM "urn:test">`},
		{name: "html", public: "-//W3C//DTD HTML 4.01//EN", system: "https://example.org/html.dtd", want: `<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "https://example.org/html.dtd">`},
		{name: rootElement, system: `urn:test:"quoted"`, want: `<!DOCTYPE root SYSTEM 'urn:test:"quoted"'>`},
		{name: "html", public: "legacy", html: true, want: `<!DOCTYPE html PUBLIC "legacy">`},
	} {
		t.Run(tc.want, func(t *testing.T) {
			var out strings.Builder

			write := xmloutput.WriteDoctype
			if tc.html {
				write = xmloutput.WriteHTMLDoctype
			}

			if err := write(&out, tc.name, tc.public, tc.system); err != nil {
				t.Fatal(err)
			}

			if out.String() != tc.want {
				t.Fatalf("got %q, want %q", out.String(), tc.want)
			}
		})
	}
}

func TestWriteDoctypeRejectsInvalidMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		public string
		system string
	}{
		{name: "bad name"},
		{name: rootElement, public: "PUBLIC without SYSTEM"},
		{name: rootElement, public: "tab\t", system: "urn:test"},
		{name: rootElement, system: `both'"quotes`},
		{name: rootElement, system: "nul\x00"},
		{name: rootElement, system: "\xff"},
	} {
		var out strings.Builder
		if err := xmloutput.WriteDoctype(&out, tc.name, tc.public, tc.system); err == nil || out.Len() != 0 {
			t.Fatalf("invalid metadata %+v produced %q, %v", tc, out.String(), err)
		}
	}
}

func TestWriteDoctypeWriterErrors(t *testing.T) {
	failure := errors.New("destination failed")
	for _, err := range []error{nil, failure} {
		want := err
		if want == nil {
			want = io.ErrShortWrite
		}

		if got := xmloutput.WriteDoctype(failedWriter{err}, rootElement, "", "urn:test"); !errors.Is(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }
