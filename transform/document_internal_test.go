package transform

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

func TestImportUsesProjectStorage(t *testing.T) {
	ctx := t.Context()

	source, err := document.Parse(ctx, []byte(`<r xmlns:p="urn:p" xml:id=" root "><p:item a="&amp;">text</p:item></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	e, err := NewEngine(Config{})
	if err != nil {
		t.Fatal(err)
	}

	a, err := e.Import(ctx, source)
	if err != nil {
		t.Fatal(err)
	}

	b, err := e.Import(ctx, source)
	if err != nil {
		t.Fatal(err)
	}

	if a.native.Snapshot() != source || a.native != b.native {
		t.Fatal("import copied the DOM or changed snapshot identity")
	}

	q, err := e.CompileXPath(ctx, `$a is $b and root($a/*) is $a`, XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	value, err := q.Evaluate(ctx, nil, XPathContext{Variables: Bindings{
		{Local: "a"}: Values(a.Root()), {Local: "b"}: Values(b.Root()),
	}})
	if err != nil {
		t.Fatal(err)
	}

	if text, err := value.Text(); err != nil || text != "true" {
		t.Fatal(text, err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				d, err := e.Import(ctx, source)
				if err != nil {
					t.Error(err)
					return
				}

				if d.native != a.native {
					t.Error("concurrent import changed identity")
				}
			}
		})
	}

	wg.Wait()
}

func TestImportAppliesConsumerLimits(t *testing.T) {
	xml := []byte(`<r><a/><a/></r>`)

	d, err := document.Parse(t.Context(), xml, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	for _, limits := range []Limits{{MaxInputBytes: len(xml) - 1}, {MaxNodes: 2}, {MaxDepth: 1}} {
		e, err := NewEngine(Config{Limits: limits})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := e.Import(t.Context(), d); !errors.Is(err, ErrLimit) {
			t.Fatal("import limit lost", limits, err)
		}
	}
	// Expanded names share a namespace URI; its bytes are not input bytes for
	// every element using that binding.
	xml = []byte(`<r xmlns="urn:` + strings.Repeat("x", 100) + `">` + strings.Repeat(`<a/>`, 80) + `</r>`)

	d, err = document.Parse(t.Context(), xml, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	e, err := NewEngine(Config{Limits: Limits{MaxInputBytes: len(xml)}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.Import(t.Context(), d); err != nil {
		t.Fatal("namespace expansion inflated input bytes", err)
	}
}

func TestParseUsesProjectParser(t *testing.T) {
	e, err := NewEngine(Config{})
	if err != nil {
		t.Fatal(err)
	}

	for _, xml := range []string{`<r xmlns="urn:r">a<![CDATA[b]]>&amp;c<!--note--><?pi v?></r>`, `<r p:a="1"/>`, `<!DOCTYPE r [<!ENTITY x "value">]><r>&x;</r>`, `<r a="1" a="2"/>`} {
		d, parseErr := document.Parse(t.Context(), []byte(xml), document.DefaultLimits())

		view, viewErr := e.Parse(t.Context(), []byte(xml))
		if parseErr != nil || viewErr != nil {
			if (parseErr == nil) != (viewErr == nil) {
				t.Fatalf("different XML parsing policy for %s: %v / %v", xml, parseErr, viewErr)
			}

			continue
		}
		if view == nil {
			t.Fatal("Parse returned no document without an error")
		}

		want, err := d.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		got, err := view.native.Snapshot().XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("different parser trees: %s / %s", got, want)
		}
	}
}

func TestInputPolicyCacheRemainsBoundedAndChecksStricterLimits(t *testing.T) {
	ctx := t.Context()

	e, err := NewEngine(Config{})
	if err != nil {
		t.Fatal(err)
	}

	d, err := e.Parse(ctx, []byte(`<r><n/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("Parse returned no document without an error")
	}

	limits := DefaultLimits()

	limits.MaxNodes = 2
	for i := range 256 {
		policy := limits

		policy.MaxNodes += i
		if err := checkInputDocument(ctx, d.native, policy); err != nil {
			t.Fatal(err)
		}
	}

	cached, ok := tree.LoadView(d.native.Snapshot(), inputLimitsKey{})
	if !ok || cached.(document.Limits).MaxNodes != 2 {
		t.Fatal("cache replaced its original successful policy", cached)
	}

	limits.MaxNodes = 1
	if err := checkInputDocument(ctx, d.native, limits); !errors.Is(err, document.ErrLimit) {
		t.Fatal("stricter consumer used a looser cached policy", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if err := checkInputDocument(canceled, d.native, DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestParserReaderMaximumByteLimit(t *testing.T) {
	e, err := NewEngine(Config{Limits: Limits{MaxInputBytes: int(^uint(0) >> 1)}})
	if err != nil {
		t.Fatal(err)
	}

	d, err := e.parseOptions().ParseReader(t.Context(), strings.NewReader(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	if root := d.DocumentElement(); root == nil || root.LocalName() != "r" {
		t.Fatal("reader lost the XML document")
	}
}

func TestInvocationContextLifetime(t *testing.T) {
	engine, err := NewEngine(Config{Limits: Limits{Timeout: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	type valueKey struct{}
	deadline := time.Now().Add(10 * time.Second)
	parent, stop := context.WithDeadline(context.WithValue(t.Context(), valueKey{}, "caller"), deadline)
	defer stop()
	ctx, cancel, err := engine.invocation(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if actual, ok := ctx.Deadline(); !ok || !actual.Equal(deadline) || ctx.Value(valueKey{}) != "caller" {
		t.Fatal("invocation lost the caller's deadline or values")
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) || parent.Err() != nil {
		t.Fatal("invocation cancellation affected its parent", ctx.Err(), parent.Err())
	}

	parent, stopCause := context.WithCancelCause(t.Context())
	ctx, cancel, err = engine.invocation(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	failure := errors.New("caller stopped")
	stopCause(failure)
	if !errors.Is(ctx.Err(), context.Canceled) || !errors.Is(context.Cause(ctx), failure) {
		t.Fatal("caller cancellation/cause lost", ctx.Err(), context.Cause(ctx))
	}
}

func TestXMLScopeLimitDefaultsAndValidation(t *testing.T) {
	defaults := DefaultLimits()
	if defaults.MaxAttributesPerElement != 128 || defaults.MaxInScopeNamespaces != 256 {
		t.Fatal("XML defaults changed", defaults)
	}
	engine, err := NewEngine(Config{Limits: Limits{MaxInputBytes: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Parse(t.Context(), []byte(`<r xmlns:p="urn:p" a="1" b="2"/>`)); err != nil {
		t.Fatal("old partial limits did not select XML defaults", err)
	}
	for _, limits := range []Limits{{MaxAttributesPerElement: -1}, {MaxInScopeNamespaces: -1}} {
		if engine, err := NewEngine(Config{Limits: limits}); engine != nil || !errors.Is(err, ErrInput) {
			t.Fatal("negative XML scope accepted", engine, err)
		}
	}
}

func TestXMLScopeLimitsAcrossSnapshotsAndPolicyCache(t *testing.T) {
	for _, tc := range []struct {
		name, xml string
		limits    Limits
		reject    bool
	}{
		{"attributes below", `<r a="1" b="2"/>`, Limits{MaxAttributesPerElement: 1}, true},
		{"attributes exact", `<r a="1" b="2"/>`, Limits{MaxAttributesPerElement: 2}, false},
		{"attributes raised", `<r a="1" b="2"/>`, Limits{MaxAttributesPerElement: 3}, false},
		{"namespaces below", `<r xmlns:p="urn:p" xmlns:q="urn:q"/>`, Limits{MaxInScopeNamespaces: 2}, true},
		{"namespaces exact", `<r xmlns:p="urn:p" xmlns:q="urn:q"/>`, Limits{MaxInScopeNamespaces: 3}, false},
		{"namespaces raised", `<r xmlns:p="urn:p" xmlns:q="urn:q"/>`, Limits{MaxInScopeNamespaces: 4}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			consumer, err := NewEngine(Config{Limits: tc.limits})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := document.Parse(ctx, []byte(tc.xml), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			for _, route := range []struct {
				name string
				read func() (*Document, error)
			}{
				{"bytes", func() (*Document, error) { return consumer.Parse(ctx, []byte(tc.xml)) }},
				{"reader", func() (*Document, error) { return consumer.ParseReader(ctx, strings.NewReader(tc.xml)) }},
				{"import", func() (*Document, error) { return consumer.Import(ctx, snapshot) }},
			} {
				t.Run(route.name, func(t *testing.T) {
					actual, err := route.read()
					if tc.reject {
						if actual != nil || !errors.Is(err, ErrLimit) || !errors.Is(err, document.ErrLimit) {
							t.Fatal("XML limit lost", actual, err)
						}
					} else if err != nil || actual == nil {
						t.Fatal(actual, err)
					} else if route.name == "import" && actual.native.Snapshot() != snapshot {
						t.Fatal("import copied the snapshot")
					}
				})
			}
			producer, err := NewEngine(Config{})
			if err != nil {
				t.Fatal(err)
			}
			source, err := producer.Parse(ctx, []byte(tc.xml))
			if err != nil {
				t.Fatal(err)
			}
			warm, err := producer.CompileXPath(ctx, `count(/*)`, XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := warm.Evaluate(ctx, source, XPathContext{}); err != nil || result.Len() != 1 {
				t.Fatal("cache warmup", result, err)
			}
			cached, ok := tree.LoadView(source.native.Snapshot(), inputLimitsKey{})
			if !ok {
				t.Fatal("policy not cached")
			}
			query, err := consumer.CompileXPath(ctx, `count(/*)`, XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := query.Evaluate(ctx, source, XPathContext{})
			if tc.reject {
				if result.Len() != 0 || !errors.Is(err, ErrLimit) || !errors.Is(err, document.ErrLimit) {
					t.Fatal("looser cached policy bypassed consumer", result, err)
				}
				after, ok := tree.LoadView(source.native.Snapshot(), inputLimitsKey{})
				if !ok || after != cached {
					t.Fatal("failed policy replaced successful cache", after, cached)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if value, err := result.Text(); err != nil || value != "1" {
				t.Fatal(value, err)
			}
			exported, exportErr := consumer.Export(ctx, source)
			if tc.reject {
				if exported != nil || !errors.Is(exportErr, ErrLimit) || !errors.Is(exportErr, document.ErrLimit) {
					t.Fatal("export lost consumer policy", exported, exportErr)
				}
			} else if exportErr != nil || exported != source.native.Snapshot() {
				t.Fatal("export changed identity", exportErr)
			}
			bound, err := consumer.CompileXPath(ctx, `$node`, XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			sequence, err := bound.Evaluate(ctx, nil, XPathContext{Variables: Bindings{{Local: "node"}: Values(source.Root())}})
			if tc.reject {
				if sequence.Len() != 0 || !errors.Is(err, ErrLimit) {
					t.Fatal("node binding bypassed consumer policy", sequence, err)
				}
			} else if err != nil || sequence.Len() != 1 {
				t.Fatal(sequence, err)
			}
		})
	}
}

func TestXMLScopeLimitsInLanguageParsers(t *testing.T) {
	for _, tc := range []struct {
		name, xml string
		limits    Limits
		reject    bool
	}{
		{"resource attributes below", `<r a="1" b="2" c="3"/>`, Limits{MaxAttributesPerElement: 2}, true},
		{"resource attributes exact", `<r a="1" b="2"/>`, Limits{MaxAttributesPerElement: 2}, false},
		{"resource namespaces below", `<r xmlns:p="urn:p" xmlns:q="urn:q"/>`, Limits{MaxInScopeNamespaces: 2}, true},
		{"resource namespaces exact", `<r xmlns:p="urn:p"/>`, Limits{MaxInScopeNamespaces: 2}, false},
	} {
		for _, expression := range []string{`count(doc('urn:scope-limits')/*)`, `count(parse-xml($xml)/*)`} {
			t.Run(tc.name+"/"+expression, func(t *testing.T) {
				engine, err := NewEngine(Config{Limits: tc.limits, Resolver: ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if uri != "urn:scope-limits" {
						return nil, ErrResource
					}
					return io.NopCloser(strings.NewReader(tc.xml)), nil
				})})
				if err != nil {
					t.Fatal(err)
				}
				query, err := engine.CompileXPath(t.Context(), expression, XPathOptions{})
				if err != nil {
					t.Fatal(err)
				}
				result, err := query.Evaluate(t.Context(), nil, XPathContext{Variables: Bindings{{Local: "xml"}: Values(String(tc.xml))}})
				if tc.reject {
					if result.Len() != 0 || !errors.Is(err, ErrLimit) {
						t.Fatal("language parser lost XML limits", result, err)
					}
				} else if err != nil {
					t.Fatal(err)
				} else if value, err := result.Text(); err != nil || value != "1" {
					t.Fatal(value, err)
				}
			})
		}
	}
	const stylesheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template match="/"><out/></xsl:template></xsl:stylesheet>`
	for _, tc := range []struct {
		name   string
		limits Limits
		reject bool
	}{
		{"stylesheet attributes below", Limits{MaxAttributesPerElement: 1}, true},
		{"stylesheet attributes exact", Limits{MaxAttributesPerElement: 2}, false},
		{"stylesheet attributes raised", Limits{MaxAttributesPerElement: 3}, false},
		{"stylesheet namespaces below", Limits{MaxInScopeNamespaces: 1}, true},
		{"stylesheet namespaces exact", Limits{MaxInScopeNamespaces: 2}, false},
		{"stylesheet namespaces raised", Limits{MaxInScopeNamespaces: 3}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := NewEngine(Config{Limits: tc.limits})
			if err != nil {
				t.Fatal(err)
			}
			sheet, err := engine.CompileXSLT(t.Context(), []byte(stylesheet), XSLTOptions{})
			if tc.reject {
				if sheet != nil || !errors.Is(err, ErrLimit) || !errors.Is(err, document.ErrLimit) {
					t.Fatal("stylesheet parser lost limits", sheet, err)
				}
			} else if err != nil || sheet == nil {
				t.Fatal(sheet, err)
			}
		})
	}
}

func TestApprovedCompilationDeadlineAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"runtime timeout below setup floor", time.Millisecond, 3 * time.Second},
		{"configured setup timeout", 5 * time.Second, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewEngine(Config{Limits: Limits{Timeout: tc.timeout}})
			if err != nil {
				t.Fatal(err)
			}

			before := time.Now()
			ctx, cancel := e.approvedCompilationContext()
			defer cancel()
			after := time.Now()
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(before.Add(tc.want)) || deadline.After(after.Add(tc.want)) {
				t.Fatalf("setup deadline=%v (present=%v), want duration %v", deadline, ok, tc.want)
			}

			cancel()
			select {
			case <-ctx.Done():
			default:
				t.Fatal("setup context remains active after cancellation")
			}
		})
	}
}
