package transform_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

func TestXPathTransformResources(t *testing.T) {
	source := sheet(version30, `<xsl:template name="start"><xsl:value-of select="unparsed-text('urn:payload')"/></xsl:template>`)

	for _, maxResources := range []int{1, 2} {
		var readers []*lifecycleReader

		e := engine(t, transform.Config{Limits: transform.Limits{MaxResources: maxResources}, Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			body := source

			switch uri {
			case "mem://suite/styles/main.xsl":
			case "urn:payload":
				body = "payload"
			default:
				return nil, transform.ErrResource
			}

			r := &lifecycleReader{Reader: strings.NewReader(body)}
			readers = append(readers, r)

			return r, ctx.Err()
		})})

		program, err := e.CompileXPath(t.Context(), `transform(map{'stylesheet-location':'styles/main.xsl','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`, transform.XPathOptions{BaseURI: "mem://suite/query.xq"})
		if err != nil {
			t.Fatal(err)
		}

		result, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
		if maxResources == 1 {
			if !errors.Is(err, transform.ErrLimit) || result.Len() != 0 {
				t.Fatal("nested resource budget", result, err)
			}
		} else if err != nil || text(t, result) != "payload" {
			t.Fatal(result, err)
		}

		for _, reader := range readers {
			if !reader.closed {
				t.Fatal("resource reader was not closed")
			}
		}
	}

	failure := errors.New("stylesheet resolver failure")
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return nil, failure })})

	_, err := query(t, e, `transform(map{'stylesheet-location':'urn:missing'})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
	if !errors.Is(err, failure) || !errors.Is(err, transform.ErrResource) {
		t.Fatal("resolver cause was lost", err)
	}
}

func TestSingleByteXMLResources(t *testing.T) {
	var readers []*lifecycleReader

	e := engine(t, transform.Config{AllowSingleByteEncodings: true, Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		var source string

		switch uri {
		case "urn:latin-document":
			source = `<?xml version="1.0" encoding="ISO-8859-1"?><r>caf` + "\xe9" + `</r>`
		case "urn:latin-stylesheet":
			source = `<?xml version="1.0" encoding="ISO-8859-1"?>` + sheet(version30, `<xsl:template name="latin"><xsl:text>caf`+"\xe9"+`</xsl:text></xsl:template>`)
		default:
			return nil, transform.ErrResource
		}

		reader := &lifecycleReader{Reader: strings.NewReader(source)}
		readers = append(readers, reader)

		return reader, ctx.Err()
	})})

	if value := text(t, evaluate(t, e, `string(doc('urn:latin-document')/r)`, transform.XPath31)); value != xmlLatinText {
		t.Fatal(value)
	}

	source := `<?xml version="1.0" encoding="US-ASCII"?>` + sheet(version30, `<xsl:include href="urn:latin-stylesheet"/><xsl:template name="start"><xsl:call-template name="latin"/><xsl:text>:</xsl:text><xsl:value-of select="doc('urn:latin-document')/r"/></xsl:template>`)

	compiled, err := e.CompileXSLTReader(t.Context(), strings.NewReader(source), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(result.Primary) != "café:café" {
		t.Fatal(result, err)
	}

	for _, reader := range readers {
		if !reader.closed {
			t.Fatal("encoded XML resource was not closed")
		}
	}

	unicodeStylesheet := `<?xml version="1.0" encoding="ISO-8859-1"?>` + sheet(version30, `<xsl:template name="start"><xsl:text>café 中</xsl:text></xsl:template>`)
	for _, configured := range []*transform.Engine{e, engine(t, transform.Config{})} {
		value, err := query(t, configured, `transform(map{'stylesheet-text':$source,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(unicodeStylesheet))}})
		if err != nil || text(t, value) != xmlCharacters {
			t.Fatal("stylesheet text was reinterpreted as bytes", value, err)
		}

		bad := strings.Replace(unicodeStylesheet, `encoding="ISO-8859-1"`, `encoding="1bad"`, 1)
		_, err = query(t, configured, `transform(map{'stylesheet-text':$source,'initial-template':QName('', 'start')})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(bad))}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FOXT0003" {
			t.Fatal("malformed stylesheet declaration accepted", err)
		}
	}
}

func TestDocumentResourceURIValidation(t *testing.T) {
	var calls int

	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return nil, transform.ErrResource
	})})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, uri := range []string{":/", "http://[", "http://example.org/%zz", "relative.xml"} {
			want := "FODC0005"
			if uri == "relative.xml" {
				want = "FODC0002"
			}

			_, err := query(t, e, `doc($uri)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableURI}: transform.Values(transform.String(uri))}})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != want {
				t.Errorf("XPath %d doc(%q): %v; want %s", version, uri, err, want)
			}

			value, err := query(t, e, `doc-available($uri)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableURI}: transform.Values(transform.String(uri))}})
			if err != nil || text(t, value) != nameFalse {
				t.Fatal("doc-available did not suppress the retrieval error", uri, value, err)
			}
		}
	}

	if calls != 0 {
		t.Fatal("invalid or unresolved URI reached the resolver", calls)
	}
}

const (
	textLatinMediaType = "text/plain; charset=iso-8859-1"
	textUTF8Encoding   = "utf-8"
	textEncodingError  = "FOUT1190"
)

func TestTextResourceMediaType(t *testing.T) {
	for _, tc := range []struct {
		name, input, mediaType, encoding, want, code string
	}{
		{"transport", "\xe9", textLatinMediaType, "", "é", ""},
		{"transport-before-argument", "\xe9", textLatinMediaType, textUTF8Encoding, "é", ""},
		{"transport-with-bom", "\xfe\xff\x00x", "text/plain; charset=utf-16", "ascii", "x", ""},
		{"xml-before-argument", "<?xml version='1.0' encoding='iso-8859-1'?><r>\xe9</r>", "application/example+xml", textUTF8Encoding, "<?xml version='1.0' encoding='iso-8859-1'?><r>é</r>", ""},
		{"plain-argument", "<?xml version='1.0' encoding='iso-8859-1'?><r>\xe9</r>", "text/plain", textUTF8Encoding, "", textEncodingError},
		{"unknown-transport", "x", "text/plain; charset=unknown-codec", "", "", textEncodingError},
		{"malformed-utf16", "\xd8\x00", "text/plain; charset=utf-16be", "", "", textEncodingError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
				reader := &typedTextReader{Reader: strings.NewReader(tc.input), mediaType: tc.mediaType}
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return reader, nil })})

				expression := `unparsed-text('urn:text')`
				if tc.encoding != "" {
					expression = `unparsed-text('urn:text', '` + tc.encoding + `')`
				}

				value, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})
				if !reader.closed {
					t.Fatal("text stream not closed")
				}

				if tc.code == "" {
					if err != nil || text(t, value) != tc.want {
						t.Fatal(version, value, err)
					}
				} else {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != tc.code || value.Len() != 0 {
						t.Fatal(version, value, err)
					}
				}
			}
		})
	}
}

func TestXSLTTextResourceMediaType(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		reader := &typedTextReader{Reader: strings.NewReader("\xe9"), mediaType: textLatinMediaType}
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return reader, nil })})
		source := sheet(version30, `<xsl:template name="start"><xsl:sequence select="unparsed-text('urn:text', 'utf-8')"/></xsl:template>`)

		var (
			value transform.Sequence
			err   error
		)
		if dynamic {
			value, err = query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('','start'),'delivery-format':'raw'})?output`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
		} else {
			result, runErr := stylesheet(t, e, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			err = runErr

			if result != nil {
				value = result.Primary()
			}
		}

		if err != nil || text(t, value) != "é" || !reader.closed {
			t.Fatal("XSLT text metadata", dynamic, value, err, reader.closed)
		}
	}
}

type typedTextReader struct {
	lifecycleReader
	mediaType string
}

func (r *typedTextReader) MediaType() string { return r.mediaType }

func TestXPathTransformProgramBudget(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxProgramBytes: 512}})

	source := sheet(version30, `<xsl:template name="start"><xsl:text>`+strings.Repeat("x", 600)+`</xsl:text></xsl:template>`)
	for _, expression := range []string{
		transformSerializedQuery,
		`transform(map{'stylesheet-node':parse-xml($stylesheet),'initial-template':QName('', 'start')})`,
	} {
		result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: variableStylesheet}: transform.Values(transform.String(source)),
		}})
		if !errors.Is(err, transform.ErrLimit) || result.Len() != 0 {
			t.Fatal("dynamic stylesheet program budget", result, err)
		}
	}
}

func TestJSONDocResourceErrorCodes(t *testing.T) {
	for _, uri := range []string{"urn:missing", "https://invalid.example/%gg", "urn:json#fragment"} {
		e := engine(t, transform.Config{})
		_, err := query(t, e, `json-doc($uri)`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableURI}: transform.Values(transform.String(uri))}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FOUT1170" {
			t.Errorf("%s: %v", uri, err)
		}
	}

	for _, test := range []struct{ body, code string }{{`{"value":7}`, ""}, {`{`, "FOJS0001"}} {
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(test.body)), ctx.Err()
		})})

		result, err := query(t, e, `json-doc('urn:json')?value`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		if test.code == "" {
			if err != nil || text(t, result) != "7" {
				t.Fatal(result, err)
			}
		} else {
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != test.code || result.Len() != 0 {
				t.Fatal("JSON parse error was reclassified", result, err)
			}
		}
	}

	e := engine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: 8}, Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"value":123456789}`)), ctx.Err()
	})})

	result, err := query(t, e, `json-doc('urn:json')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrLimit) || result.Len() != 0 {
		t.Fatal("resource budget lost", result, err)
	}
}

func TestResolverClosesReaderOnFailure(t *testing.T) {
	failure := errors.New("resolver failed after opening resource")
	r := &lifecycleReader{Reader: strings.NewReader("untrusted")}

	e, err := transform.NewEngine(transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return r, failure
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `doc('urn:failed')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Evaluate(context.Background(), nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrResource) || !errors.Is(err, failure) || !r.closed {
		t.Fatalf("closed=%v, error=%v", r.closed, err)
	}
}

func TestResolverTypedNilReader(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("typed-nil reader caused panic: %v", p)
		}
	}()

	var r *lifecycleReader

	e, err := transform.NewEngine(transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return r, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `doc('urn:nil')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := q.Evaluate(context.Background(), nil, transform.XPathContext{}); !errors.Is(err, transform.ErrResource) {
		t.Fatalf("error=%v", err)
	}
}

func TestNilResolverFunction(t *testing.T) {
	var resolver transform.ResolverFunc
	if _, err := resolver.Resolve(context.Background(), "urn:nil"); !errors.Is(err, transform.ErrResource) {
		t.Fatal(err)
	}

	e, err := transform.NewEngine(transform.Config{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `doc('urn:nil')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := q.Evaluate(context.Background(), nil, transform.XPathContext{}); err == nil {
		t.Fatal("nil resolver allowed a resource lookup")
	}
}

func TestResolverStopsReadingAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &cancelReadResource{Reader: strings.NewReader(`<r/>`), cancel: cancel}

	e, err := transform.NewEngine(transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return r, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(ctx, `doc('urn:cancel')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Evaluate(ctx, nil, transform.XPathContext{})
	if !errors.Is(err, context.Canceled) || r.reads != 1 || !r.closed {
		t.Fatalf("reads=%d closed=%v error=%v", r.reads, r.closed, err)
	}
}

func TestMaximumInputBudgetDoesNotOverflowResourceRead(t *testing.T) {
	e, err := transform.NewEngine(transform.Config{Limits: transform.Limits{MaxInputBytes: int(^uint(0) >> 1)}, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r/>`)), nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `count(doc('urn:small')/r)`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out, err := q.Evaluate(context.Background(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	if got, err := out.Text(); err != nil || got != "1" {
		t.Fatalf("got %q: %v", got, err)
	}
}

func TestImportedModulesAndResourceLimits(t *testing.T) {
	ctx := context.Background()
	closed := false
	included := sheet(version20, `<xsl:template name="included"><xsl:text>included</xsl:text></xsl:template>`)
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if uri != "https://example.invalid/module.xsl" {
			return nil, errors.New("unexpected URI")
		}

		return trackedReader{Reader: strings.NewReader(included), closed: &closed}, ctx.Err()
	})})
	main := sheet(version30, `<xsl:include href="module.xsl"/><xsl:template name="start"><xsl:call-template name="included"/></xsl:template>`)

	s, err := e.CompileXSLT(ctx, []byte(main), transform.XSLTOptions{BaseURI: "https://example.invalid/main.xsl"})
	if err != nil || !closed {
		t.Fatal(closed, err)
	}

	out, err := s.Transform(ctx, nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "included" {
		t.Fatal(out, err)
	}

	closed = false
	capped := engine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: 32}, Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return trackedReader{Reader: strings.NewReader(`<r>` + strings.Repeat("x", 100) + `</r>`), closed: &closed}, ctx.Err()
	})})

	_, err = query(t, capped, `doc('urn:large')`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrLimit) || !closed {
		t.Fatal(closed, err)
	}
}

func TestXSLTProcessorVersionModules(t *testing.T) {
	for _, kind := range []string{nameInclude, "import"} {
		t.Run(kind, func(t *testing.T) {
			closed := false
			module := sheet(version20, `<xsl:template name="included"><xsl:value-of select="map{'value':42}?value"/></xsl:template>`)
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if uri != "https://example.invalid/module.xsl" {
					return nil, transform.ErrResource
				}

				return trackedReader{Reader: strings.NewReader(module), closed: &closed}, ctx.Err()
			})})
			main := sheet(version20, `<xsl:`+kind+` href="module.xsl"/><xsl:output method="text"/><xsl:template name="start"><xsl:call-template name="included"/></xsl:template>`)

			s, err := e.CompileXSLT(t.Context(), []byte(main), transform.XSLTOptions{ProcessorVersion: transform.XSLT30, BaseURI: "https://example.invalid/main.xsl"})
			if err != nil || !closed {
				t.Fatal(closed, err)
			}

			out, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil || string(out.Primary) != "42" {
				t.Fatal(out, err)
			}
		})
	}
}

type lifecycleReader struct {
	io.Reader
	closed bool
}

func (r *lifecycleReader) Close() error {
	r.closed = true
	return nil
}

type cancelReadResource struct {
	lifecycleReader
	cancel context.CancelFunc
	reads  int
}

func (r *cancelReadResource) Read(p []byte) (int, error) {
	r.reads++
	n, err := r.Reader.Read(p)
	r.cancel()

	return n, err
}

type trackedReader struct {
	io.Reader
	closed *bool
}

func (r trackedReader) Close() error { *r.closed = true; return nil }

func TestXPathFunctionConversionBudgets(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 1000}})
	for _, expression := range []string{`function-arity(concat#1000000000)`, `function-arity(function-lookup(xs:QName('fn:concat'),1000000000))`} {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "1000000000" {
			t.Fatal("variadic function metadata was not compact", expression, got)
		}
	}

	for _, expression := range []string{
		`(1 to 10000) || 'a'`,
		`(function($x as xs:integer*) {true()})(1 to 10000)`,
		`codepoints-to-string(33 to 10033)`,
		`codepoints-to-string#1(33 to 10033)`,
		`function-lookup(xs:QName('fn:codepoints-to-string'),1)(33 to 10033)`,
	} {
		value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		if !errors.Is(err, transform.ErrLimit) || value.Len() != 0 {
			t.Fatal("function conversion ignored the operation budget", expression, value, err)
		}
	}
}

func TestTextResourceArgumentValidation(t *testing.T) {
	reads := 0
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		reads++
		return io.NopCloser(strings.NewReader("ok")), nil
	})})

	for _, name := range []string{functionUnparsedText, "unparsed-text-lines", "unparsed-text-available"} {
		for _, arguments := range []string{`'urn:text', ()`, `'urn:text', 1`, `(), ()`, `(), ('UTF-8','UTF-16')`} {
			_, err := query(t, e, name+"("+arguments+")", transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
				t.Fatal("text resource signature", name, arguments, err)
			}
		}
	}

	if reads != 0 {
		t.Fatal("invalid arguments reached the resource resolver", reads)
	}

	got := text(t, evaluate(t, e, `unparsed-text(xs:anyURI('urn:text'), xs:untypedAtomic('UTF-8'))`, transform.XPath31))
	if got != "ok" || reads != 1 {
		t.Fatal("valid function conversion did not reach the resource", got, reads)
	}
}
