package transform_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

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
