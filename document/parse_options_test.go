package document_test

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/document"
)

func TestNonValidatingXMLInternalSubset(t *testing.T) {
	input := `<!DOCTYPE r [
<!ENTITY % attributes '<!ATTLIST r tokens NMTOKENS " a   b " xmlns CDATA "urn:root">'>
%attributes;
<!ENTITY text "hello &#xD; world">
<!NOTATION image PUBLIC "urn:format:image">
<!ENTITY picture SYSTEM "picture.bin" NDATA image>
<?application retain this?>
]><r>&text;</r>`
	o := document.ParseOptions{NonValidating: true, BaseURI: "https://example.test/document.xml"}
	d, err := o.ParseReader(t.Context(), iotest.OneByteReader(strings.NewReader(input)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Root().Name().Space != "urn:root" || d.Root().Text() != "hello \r world" {
		t.Fatal("entity/default namespace", d.Root().Name(), d.Root().Text())
	}
	if value, ok := d.Root().Attribute(document.Name{Local: "tokens"}); !ok || value != "a b" {
		t.Fatal("tokenized default attribute", value, ok)
	}
	dtd, ok := d.DTD()
	if !ok || dtd.Name != "r" || dtd.Notations["image"].PublicID != "urn:format:image" || dtd.UnparsedEntities["picture"].Notation != "image" || len(dtd.ProcessingInstructions) != 1 || dtd.ProcessingInstructions[0].Target != "application" || dtd.ProcessingInstructions[0].Data != "retain this" {
		t.Fatal("DTD information was lost", dtd, ok)
	}
	delete(dtd.Notations, "image")
	delete(dtd.UnparsedEntities, "picture")
	dtd.ProcessingInstructions[0].Target = "changed"
	again, _ := d.DTD()
	if len(again.Notations) != 1 || len(again.UnparsedEntities) != 1 || again.ProcessingInstructions[0].Target != "application" {
		t.Fatal("DTD accessors expose mutable snapshot storage")
	}
	if _, err := (document.ParseOptions{}).ParseText(t.Context(), input); err == nil {
		t.Fatal("default parser enabled DTD processing")
	}
}

func TestNonValidatingXMLExternalEntities(t *testing.T) {
	base := "https://example.test/input/document.xml"
	resources := map[string]string{
		"https://example.test/input/declarations/root.dtd": `<!ENTITY % attrs SYSTEM "../attrs.ent">%attrs;<!ENTITY content SYSTEM "../content.xml"><!NOTATION last SYSTEM "format">`,
		"https://example.test/input/attrs.ent":             `<!ATTLIST r value NMTOKENS " one  two ">`,
		"https://example.test/input/content.xml":           `<?xml encoding="UTF-8"?><child>external</child>`,
	}
	var opened, closed int
	o := document.ParseOptions{NonValidating: true, BaseURI: base, EntityResolver: func(ctx context.Context, system, parent string) (io.ReadCloser, string, error) {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		b, err := url.Parse(parent)
		if err != nil {
			return nil, "", err
		}
		u, err := b.Parse(system)
		if err != nil {
			return nil, "", err
		}
		text, exists := resources[u.String()]
		if !exists {
			return nil, "", errors.New("resource is not authorized")
		}
		opened++
		return &entityReader{Reader: strings.NewReader(text), closed: &closed}, u.String(), nil
	}}
	d, err := o.ParseText(t.Context(), `<!DOCTYPE r SYSTEM "declarations/root.dtd"><r>&content;</r>`)
	if err != nil {
		t.Fatal(err)
	}
	if opened != 3 || closed != opened || d.Root().Text() != "external" {
		t.Fatal("entity processing/closure", opened, closed, d.Root().Text())
	}
	if value, _ := d.Root().Attribute(document.Name{Local: "value"}); value != "one two" {
		t.Fatal("external tokenized default", value)
	}
	dtd, _ := d.DTD()
	if dtd.SystemID != "declarations/root.dtd" || dtd.Notations["last"].BaseURI != "https://example.test/input/declarations/root.dtd" {
		t.Fatal("external declaration base", dtd)
	}
	if _, err := (document.ParseOptions{NonValidating: true}).ParseText(t.Context(), `<!DOCTYPE r SYSTEM "not-authorized"><r/>`); !errors.Is(err, document.ErrUnsupported) {
		t.Fatal("implicit external access", err)
	}
}

func TestNonValidatingXMLFailureContracts(t *testing.T) {
	for _, input := range []string{
		`<!DOCTYPE r [<!ENTITY a "&a;">]><r>&a;</r>`,
		`<!DOCTYPE r [<!ENTITY a "<open>">]><r>&a;</r>`,
		`<!DOCTYPE r [<!ATTLIST r x UNKNOWN #IMPLIED>]><r/>`,
		`<!DOCTYPE r [<!NOTATION n PUBLIC "invalid public character ^">]><r/>`,
	} {
		if d, err := (document.ParseOptions{NonValidating: true}).ParseText(t.Context(), input); d != nil || !errors.Is(err, document.ErrMalformed) {
			t.Fatal("accepted malformed DTD/entity", input, d, err)
		}
	}
	limits := document.DefaultLimits()
	limits.MaxBytes = 96
	if d, err := (document.ParseOptions{NonValidating: true, Limits: limits}).ParseText(t.Context(), `<!DOCTYPE r [<!ENTITY a "1234567890">]><r>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</r>`); d != nil || !errors.Is(err, document.ErrLimit) {
		t.Fatal("expanded input limit", d, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if d, err := (document.ParseOptions{NonValidating: true}).ParseText(ctx, `<!DOCTYPE r><r/>`); d != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", d, err)
	}
	readFailure := errors.New("read failed")
	closeFailure := errors.New("close failed")
	closed := 0
	o := document.ParseOptions{NonValidating: true, EntityResolver: func(context.Context, string, string) (io.ReadCloser, string, error) {
		return &entityReader{Reader: strings.NewReader(""), closed: &closed, closeErr: closeFailure}, "urn:entity", readFailure
	}}
	if d, err := o.ParseText(t.Context(), `<!DOCTYPE r SYSTEM "entity"><r/>`); d != nil || !errors.Is(err, readFailure) || !errors.Is(err, closeFailure) || closed != 1 {
		t.Fatal("resolver error/closure", d, err, closed)
	}
}

// XML 1.0 Fifth Edition 2.8 [28]/[28a] and 4.1 [68]: parameter
// entities cannot escape subset/declaration boundaries, and standalone entity
// references must resolve to declarations in the document entity itself.
func TestNonValidatingXMLWellFormedness(t *testing.T) {
	for _, tc := range []struct {
		name, input, external string
		valid                 bool
	}{
		{"PE after subset", `<!DOCTYPE r [<!ENTITY % e "">] %e;><r/>`, "", false},
		{"PE ends inside declaration", `<!DOCTYPE r SYSTEM "decl.dtd"><r/>`, `<!ENTITY % e "<!ELEMENT r ">%e;ANY>`, false},
		{"complete PE declaration", `<!DOCTYPE r SYSTEM "decl.dtd"><r/>`, `<!ENTITY % e "<!ELEMENT r ANY>">%e;`, true},
		{"PE within external declaration", `<!DOCTYPE r SYSTEM "decl.dtd"><r/>`, `<!ENTITY % e "ANY"><!ELEMENT r %e;>`, true},
		{"standalone external declaration text", `<?xml version="1.0" standalone="yes"?><!DOCTYPE r SYSTEM "decl.dtd"><r>&e;</r>`, `<!ENTITY e "text">`, false},
		{"standalone external declaration attribute", `<?xml version="1.0" standalone="yes"?><!DOCTYPE r SYSTEM "decl.dtd"><r a="&e;"/>`, `<!ENTITY e "text">`, false},
		{"standalone PE declaration", `<?xml version="1.0" standalone="yes"?><!DOCTYPE r [<!ENTITY % p '<!ENTITY e "text">'>%p;]><r>&e;</r>`, "", false},
		{"standalone local precedence", `<?xml version="1.0" standalone="yes"?><!DOCTYPE r SYSTEM "decl.dtd" [<!ENTITY e "local">]><r>&e;</r>`, `<!ENTITY e "external">`, true},
		{"not standalone", `<?xml version="1.0" standalone="no"?><!DOCTYPE r SYSTEM "decl.dtd"><r>&e;</r>`, `<!ENTITY e "text">`, true},
		{"external VersionNum", `<!DOCTYPE r [<!ENTITY e SYSTEM "decl.dtd">]><r>&e;</r>`, `<?xml version="1.7" encoding="UTF-8"?>text`, true},
		{"second TextDecl", `<!DOCTYPE r [<!ENTITY e SYSTEM "decl.dtd">]><r>&e;</r>`, `<?xml encoding="UTF-8"?><?xml encoding="UTF-8"?>text`, false},
		{"short PI before DTD", `<?A?><!DOCTYPE r><r/>`, "", true},
		{"short PI before malformed DTD", `<?A?><!DOCTYPE`, "", false},
		{"short PI in external entity", `<!DOCTYPE r [<!ENTITY e SYSTEM "decl.dtd">]><r>&e;</r>`, `<?A?>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := document.ParseOptions{NonValidating: true, EntityResolver: func(context.Context, string, string) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader(tc.external)), "urn:test:declarations", nil
			}}
			for _, fromBytes := range []bool{true, false} {
				var d *document.Document
				var err error
				if fromBytes {
					d, err = options.Parse(t.Context(), []byte(tc.input))
				} else {
					d, err = options.ParseText(t.Context(), tc.input)
				}
				if tc.valid && (d == nil || err != nil) || !tc.valid && (d != nil || !errors.Is(err, document.ErrMalformed)) {
					t.Fatalf("bytes=%v valid=%v result=%v error=%v", fromBytes, tc.valid, d, err)
				}
			}
		})
	}
}

func TestNonValidatingXMLVersionNum(t *testing.T) {
	for _, version := range []string{"1.0", "1.1", "1.7", "1.123"} {
		input := `<?xml version="` + version + `"?><r>text</r>`
		options := document.ParseOptions{NonValidating: true}
		for _, text := range []bool{false, true} {
			var d *document.Document
			var err error
			if text {
				d, err = options.ParseText(t.Context(), input)
			} else {
				d, err = options.Parse(t.Context(), []byte(input))
			}
			if err != nil || d == nil || d.Root().Text() != "text" {
				t.Fatalf("XML 1.0 [26] VersionNum %s (text %v): %v", version, text, err)
			}
		}
	}
	if d, err := (document.ParseOptions{NonValidating: true}).ParseText(t.Context(), `<?xml version="1.1"?><r>&#x1;</r>`); d != nil || err == nil {
		t.Fatal("version compatibility enabled XML 1.1 control characters")
	}
	if _, err := document.Parse(t.Context(), []byte(`<?xml version="1.7"?><r/>`), document.DefaultLimits()); err == nil {
		t.Fatal("default security parser unexpectedly changed version policy")
	}
}

func FuzzNonValidatingXML(f *testing.F) {
	for _, input := range []string{
		`<r/>`,
		`<!DOCTYPE r [<!ENTITY e "value">]><r>&e;</r>`,
		`<!DOCTYPE r [<!ENTITY % a '<!ATTLIST r a CDATA "default">'>%a;]><r/>`,
		`<!DOCTYPE r [<!ENTITY e "&#13;">]><r a="&e;">&e;</r>`,
		`<!DOCTYPE r [<!ENTITY a "&a;">]><r>&a;</r>`,
		`<!DOCTYPE r SYSTEM "external.dtd"><r/>`,
		`<?xml version="1.7"?><!DOCTYPE r><r/>`,
		`<!DOCTYPE r [<!ELEMENT r (a|)>]><r/>`,
	} {
		f.Add([]byte(input))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 16<<10 {
			t.Skip()
		}
		limits := document.DefaultLimits()
		limits.MaxBytes = 64 << 10
		limits.MaxNodes = 4096
		limits.MaxDepth = 64
		doc, err := (document.ParseOptions{NonValidating: true, Limits: limits}).Parse(t.Context(), input)
		if err != nil {
			return
		}
		output, err := doc.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		// The expanded snapshot must remain well formed. Use the same language
		// profile: relative namespace names are permitted by NonValidating.
		limits.MaxBytes = max(limits.MaxBytes, len(output))
		if _, err := (document.ParseOptions{NonValidating: true, Limits: limits}).Parse(t.Context(), output); err != nil {
			t.Fatalf("expanded serialization is not parseable: %q: %v", output, err)
		}
	})
}

type entityReader struct {
	io.Reader
	closed   *int
	closeErr error
}

func (r *entityReader) Close() error {
	*r.closed++
	return r.closeErr
}
