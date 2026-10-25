package consumer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

var (
	_ func(context.Context, []byte, document.Limits) (*document.Document, error)    = document.Parse
	_ func(context.Context, io.Reader, document.Limits) (*document.Document, error) = document.ParseReader
	_ func(context.Context, io.Writer, *document.Document, c14n.Options) error      = c14n.WriteDocument
	_ func(*transform.Result, context.Context) io.WriterTo                          = (*transform.Result).WriterTo
)

var _ reference.ReaderExtensionProcessor = (*transform.Engine)(nil)

func TestDataOperationsUseCallerContext(t *testing.T) {
	doc, err := document.ParseReader(t.Context(), strings.NewReader(`<r b="2" a="1">text</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var canonical bytes.Buffer
	if err := c14n.WriteDocument(t.Context(), &canonical, doc, c14n.Options{}); err != nil {
		t.Fatal(err)
	}
	if canonical.String() != `<r a="1" b="2">text</r>` {
		t.Fatalf("canonical XML: %q", canonical.Bytes())
	}
	key := bytes.Repeat([]byte{7}, 32)
	encrypted, err := xmlenc.EncryptBytesWithKey(t.Context(), canonical.Bytes(), key, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := xmlenc.DecryptBytesWithKey(t.Context(), encrypted, key, xmlenc.SymmetricOptions{})
	if err != nil || !bytes.Equal(decrypted, canonical.Bytes()) {
		t.Fatalf("decryption: %q, %v", decrypted, err)
	}
	mac, err := xmldsig.ComputeHMAC(t.Context(), decrypted, key, xmldsig.HMACSHA256, 0, xmldsig.HMACPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := xmldsig.VerifyHMAC(t.Context(), decrypted, mac, key, xmldsig.HMACSHA256, 0, xmldsig.HMACPolicy()); err != nil {
		t.Fatal(err)
	}
	var copied bytes.Buffer
	if _, err := reference.WriteReader(t.Context(), &copied, bytes.NewReader(decrypted), nil, reference.Options{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied.Bytes(), decrypted) {
		t.Fatal("reference writer changed octets")
	}
}

func TestOperationsCancelAndApplyLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := document.ParseReader(ctx, strings.NewReader(`<r/>`), document.DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("parse cancellation: %v", err)
	}
	if _, err := cms.Parse(ctx, nil, cms.DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("CMS cancellation: %v", err)
	}
	limits := document.DefaultLimits()
	limits.MaxBytes = 3
	if _, err := document.ParseReader(t.Context(), strings.NewReader(`<r/>`), limits); !errors.Is(err, document.ErrLimit) {
		t.Fatalf("parse limit: %v", err)
	}
	doc, err := document.Parse(t.Context(), []byte(`<r/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.WriteXML(t.Context(), io.Discard, 3); !errors.Is(err, document.ErrLimit) {
		t.Fatalf("write limit: %v", err)
	}
	if err := c14n.WriteDocument(ctx, io.Discard, doc, c14n.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canonical cancellation: %v", err)
	}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"XML serialization", func() error { _, err := doc.XML(ctx); return err }},
		{"all nodes", func() error { _, err := doc.AllNodes(ctx); return err }},
		{"subtree", func() error { _, err := doc.Root().Subtree(ctx); return err }},
		{"POST encoding", func() error {
			_, err := binding.EncodePOST(ctx, doc, binding.Request, nil, binding.POSTLimits{})
			return err
		}},
		{"POST rendering", func() error {
			_, err := binding.RenderPOSTForm(ctx, "https://sp.example.test/acs", doc, binding.Request, nil, binding.POSTLimits{})
			return err
		}},
		{"timestamp response", func() error { _, err := timestamp.ParseResponse(ctx, nil); return err }},
		{"timestamp inspection", func() error { _, err := timestamp.InspectToken(ctx, nil); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
		})
	}
}

func TestResultWriterToUsesContext(t *testing.T) {
	e := newEngine(t, transform.Config{})
	d, err := e.ParseReader(t.Context(), strings.NewReader(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.CompileXSLT(t.Context(), []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out>text</out></xsl:template></xsl:stylesheet>`), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Execute(t.Context(), d, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	writer := result.WriterTo(ctx)
	n, err := writer.WriteTo(&out)
	if err != nil || out.String() != `<out>text</out>` || n != int64(out.Len()) {
		t.Fatalf("WriteTo: %q, %d, %v", out.Bytes(), n, err)
	}
	cancel()
	out.Reset()
	if n, err := writer.WriteTo(&out); !errors.Is(err, context.Canceled) || n != 0 || out.Len() != 0 {
		t.Fatalf("canceled WriteTo: %q, %d, %v", out.Bytes(), n, err)
	}
}

func TestSharedDynamicContextAndCollections(t *testing.T) {
	donor := newEngine(t, transform.Config{})
	d, err := donor.Parse(t.Context(), []byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(t, transform.Config{CollectionResolver: collection{values: transform.Values(d.Root())}})
	dynamic := transform.DynamicContext{CurrentTime: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), ImplicitTimezone: time.FixedZone("test", 5*60*60), DefaultLanguage: "ru"}
	expression := `concat(string(current-dateTime()),'|',default-language(),'|',count(collection()),'|',count(uri-collection()))`
	q, err := e.CompileXPath(t.Context(), expression, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	value, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Context: dynamic})
	if err != nil {
		t.Fatal(err)
	}
	text, err := value.Text()
	if err != nil || text != "2024-01-02T08:04:05+05:00|ru|1|2" {
		t.Fatal(text, err)
	}
	s := compileSheet(t, e, `<xsl:template name="start"><xsl:sequence select="`+expression+`"/></xsl:template>`)
	result, err := s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{Context: dynamic})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := result.Primary().Text()
	if err != nil || actual != text {
		t.Fatal(actual, err)
	}
}

func TestTraceErrorsAndLimits(t *testing.T) {
	e := newEngine(t, transform.Config{})
	q, err := e.CompileXPath(t.Context(), `trace(42,'answer')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{TraceWriter: &output}})
	if err != nil || !strings.Contains(output.String(), "answer: 42") {
		t.Fatal(output.String(), err)
	}
	failure := errors.New("trace failed")
	_, err = q.Evaluate(t.Context(), nil, transform.XPathContext{Context: transform.DynamicContext{TraceWriter: failingWriter{failure}}})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	s := compileSheet(t, e, `<xsl:template name="start"><xsl:sequence select="trace(42,'answer')"/></xsl:template>`)
	_, err = s.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{Context: transform.DynamicContext{TraceWriter: failingWriter{failure}}})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestDefaultCollation(t *testing.T) {
	e := newEngine(t, transform.Config{})
	q, err := e.CompileXPath(t.Context(), `'A' eq 'a'`, transform.XPathOptions{DefaultCollation: "http://www.w3.org/2005/xpath-functions/collation/html-ascii-case-insensitive"})
	if err != nil {
		t.Fatal(err)
	}
	value, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := value.Single()
	if err != nil {
		t.Fatal(err)
	}
	equal, err := result.Boolean()
	if err != nil || !equal {
		t.Fatal(equal, err)
	}
}

func TestApplicationFunctions(t *testing.T) {
	ctx := t.Context()
	failure := errors.New("application failure")
	e := newEngine(t, transform.Config{Functions: []transform.Function{
		{Name: document.Name{Space: "urn:app", Local: "double"}, Arity: 1, Call: func(ctx context.Context, args []transform.Sequence) (transform.Sequence, error) {
			v, err := args[0].Single()
			if err != nil {
				return transform.Sequence{}, err
			}
			n, err := v.Integer()
			if err != nil {
				return transform.Sequence{}, err
			}
			return transform.Values(transform.Integer(n.Int64() * 2)), ctx.Err()
		}},
		{Name: document.Name{Space: "urn:app", Local: "fail"}, Arity: 0, Call: func(context.Context, []transform.Sequence) (transform.Sequence, error) {
			return transform.Sequence{}, failure
		}},
	}})
	for _, expr := range []string{`Q{urn:app}double(21)`, `Q{urn:app}double#1(21)`, `function-lookup(QName('urn:app','double'),1)(21)`} {
		q, err := e.CompileXPath(ctx, expr, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				v, err := q.Evaluate(ctx, nil, transform.XPathContext{})
				if err != nil {
					t.Error(err)
					return
				}
				s, err := v.Text()
				if err != nil || s != "42" {
					t.Error(s, err)
				}
			})
		}
		wg.Wait()
	}
	var coded *transform.Error
	if _, err := e.CompileXPath(ctx, `Q{urn:app}double()`, transform.XPathOptions{}); !errors.As(err, &coded) || coded.Code != "XPST0017" {
		t.Fatal("invalid arity diagnostic", err)
	}
	q, err := e.CompileXPath(ctx, `Q{urn:app}fail()`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Evaluate(ctx, nil, transform.XPathContext{}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	s := compileSheet(t, e, `<xsl:template name="start"><xsl:sequence select="Q{urn:app}double(21)"/></xsl:template>`)
	r, err := s.CallTemplate(ctx, nil, document.Name{Local: "start"}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	text, err := r.Primary().Text()
	if err != nil || text != "42" {
		t.Fatal(text, err)
	}
}

func TestReferenceChainsStreamBeforeEndOfInput(t *testing.T) {
	plain := strings.Repeat("x", 1<<20)
	encoded := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(plain))))
	want := sha256.Sum256([]byte(plain))
	chain := []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: reference.Base64}}
	failure := errors.New("destination stopped")
	input := &streamingInput{source: strings.NewReader(encoded)}
	sink := &prefixFailure{remaining: 128, failure: failure}
	if report, err := reference.WriteReader(t.Context(), sink, input, chain, reference.Options{}); report != nil || !errors.Is(err, failure) {
		t.Fatal(report, err)
	}
	if input.bytes >= len(encoded)/2 {
		t.Fatalf("buffered input before first output: %d of %d bytes", input.bytes, len(encoded))
	}
	allocated := allocatedDuring(t, func() error {
		hash := sha256.New()
		report, err := reference.WriteReader(t.Context(), hash, strings.NewReader(encoded), chain, reference.Options{})
		if err != nil {
			return err
		}
		if !bytes.Equal(hash.Sum(nil), want[:]) || report.Size() != len(plain) {
			return errors.New("streamed chain changed output")
		}
		steps := report.Steps()
		if len(steps) != 2 || steps[0].InputSize != len(encoded) || steps[0].OutputSize != steps[1].InputSize || steps[1].OutputSize != len(plain) || report.ProducedBytes() != steps[0].OutputSize+steps[1].OutputSize {
			return errors.New("streamed chain lost accounting")
		}
		return nil
	})
	if allocated > 256<<10 {
		t.Fatalf("reader chain allocated %d bytes", allocated)
	}
}

func TestReferenceCanonicalIntermediateDoesNotBufferBytes(t *testing.T) {
	const size = 1 << 20
	doc, err := document.Parse(t.Context(), []byte(`<abcd>`+strings.Repeat("A", size+3)+"</abcd>"), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := doc.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	data, err := reference.Nodes(nodes)
	if err != nil {
		t.Fatal(err)
	}
	chain := []reference.Transform{{Algorithm: c14n.Exclusive}, {Algorithm: reference.Base64}}
	want, err := base64.StdEncoding.DecodeString("abcd" + strings.Repeat("A", size+3) + "/abcd")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(want)
	allocated := allocatedDuring(t, func() error {
		hash := sha256.New()
		report, err := reference.Write(t.Context(), hash, data, chain, reference.Options{})
		if err != nil {
			return err
		}
		if !bytes.Equal(hash.Sum(nil), digest[:]) || report.Size() != len(want) || report.ProducedBytes() != size+16+len(want) {
			return errors.New("canonicalization chain changed data/accounting")
		}
		return nil
	})
	if allocated > 256<<10 {
		t.Fatalf("canonical intermediate allocated %d bytes", allocated)
	}
}

func TestReferenceReaderExtensions(t *testing.T) {
	tr := reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"/></xsl:stylesheet>`)}
	options := reference.Options{Extension: bufferedReferenceExtension{}, AllowedTransforms: []string{reference.XSLT, reference.Base64}}
	input := &streamingInput{source: strings.NewReader("SGVsbG8=")}
	var buffered bytes.Buffer
	if report, err := reference.WriteReader(t.Context(), &buffered, input, []reference.Transform{tr}, options); err != nil || report.Size() != 8 || buffered.String() != "SGVsbG8=" || input.bytes != 8 {
		t.Fatal("buffered extension", report, err, input.bytes)
	}
	if output, err := reference.Process(t.Context(), reference.Octets([]byte("SGVsbG8=")), []reference.Transform{tr}, options); err != nil || string(output.Bytes()) != "SGVsbG8=" {
		t.Fatal(output, err)
	}
	cleaned := false
	options.Extension = readerReferenceExtension{cleaned: &cleaned}
	chain := []reference.Transform{tr, {Algorithm: reference.Base64}}
	var output bytes.Buffer
	if _, err := reference.WriteReader(t.Context(), &output, strings.NewReader("SGVsbG8="), chain, options); err != nil || output.String() != "Hello" || !cleaned {
		t.Fatal(output.String(), err, cleaned)
	}
	cleaned = false
	input = &streamingInput{source: strings.NewReader(strings.Repeat("AAAA", 1<<18))}
	failure := errors.New("stop chain")
	if report, err := reference.WriteReader(t.Context(), &prefixFailure{remaining: 128, failure: failure}, input, chain, options); report != nil || !errors.Is(err, failure) || !cleaned || input.bytes >= 1<<19 {
		t.Fatal("early stop failed to unwind producer", report, err, cleaned, input.bytes)
	}
}

func TestReferenceReaderValidatesTrailingInputAndBudgets(t *testing.T) {
	chain := []reference.Transform{{Algorithm: reference.Base64}}
	source := "QQ==" + strings.Repeat("!", 8192)
	input := &streamingInput{source: strings.NewReader(source)}
	var output bytes.Buffer
	report, err := reference.WriteReader(t.Context(), &output, input, chain, reference.Options{})
	if err != nil || output.String() != "A" || input.bytes != len(source) || report.Steps()[0].InputSize != len(source) {
		t.Fatal("trailing ignored octets were not accounted", input.bytes, report, err)
	}
	if report, err = reference.WriteReader(t.Context(), io.Discard, strings.NewReader(source), chain, reference.Options{MaxInputBytes: len(source) - 1}); report != nil || !errors.Is(err, reference.ErrLimit) {
		t.Fatal("trailing input escaped byte budget", report, err)
	}
	for _, raw := range []string{"QQ==QQ==", "QQ=", "Q"} {
		for depth := 1; depth <= 3; depth++ {
			input := raw
			transforms := append([]reference.Transform(nil), chain...)
			for i := 1; i < depth; i++ {
				input = base64.StdEncoding.EncodeToString([]byte(input))
				transforms = append(transforms, chain[0])
			}
			report, err := reference.WriteReader(t.Context(), io.Discard, strings.NewReader(input), transforms, reference.Options{})
			step, ok := errors.AsType[*reference.StepError](err)
			if report != nil || !errors.Is(err, reference.ErrInput) || !ok || step.Index != depth-1 {
				t.Fatalf("bad base64 %q depth %d: %v %v", raw, depth, report, err)
			}
		}
	}
	input = &streamingInput{source: strings.NewReader(base64.StdEncoding.EncodeToString([]byte("SGVsbG8=")))}
	transforms := []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: reference.Base64}}
	if report, err := reference.WriteReader(t.Context(), io.Discard, input, transforms, reference.Options{MaxProducedBytes: 12}); report != nil || !errors.Is(err, reference.ErrLimit) {
		t.Fatal("intermediate production not bounded", report, err)
	}
}

type collection struct{ values transform.Sequence }

func (c collection) ResolveCollection(ctx context.Context, uri string) (transform.Sequence, error) {
	return c.values, ctx.Err()
}

func (c collection) ResolveURICollection(ctx context.Context, uri string) ([]string, error) {
	return []string{"https://collection.test/a", "https://collection.test/b"}, ctx.Err()
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type bufferedReferenceExtension struct{}

func (bufferedReferenceExtension) Validate(context.Context, reference.Transform) error { return nil }

func (bufferedReferenceExtension) Apply(_ context.Context, _ reference.Transform, data reference.Data, _ reference.ExtensionContext) (reference.Data, error) {
	return data, nil
}

type readerReferenceExtension struct {
	bufferedReferenceExtension
	cleaned *bool
}

func (e readerReferenceExtension) WriteTransform(ctx context.Context, w io.Writer, r io.Reader, _ reference.Transform, _ reference.ExtensionContext) error {
	if e.cleaned != nil {
		defer func() { *e.cleaned = true }()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := io.Copy(w, r)
	return err
}
