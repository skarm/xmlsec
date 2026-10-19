package transform

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

func TestImportUsesProjectStorage(t *testing.T) {
	ctx := context.Background()

	source, err := document.Parse(ctx, []byte(`<r xmlns:p="urn:p" xml:id="root"><p:item a="&amp;">text</p:item></r>`), document.DefaultLimits())
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

		if _, err := e.Import(context.Background(), d); !errors.Is(err, ErrLimit) {
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

	if _, err := e.Import(context.Background(), d); err != nil {
		t.Fatal("namespace expansion inflated input bytes", err)
	}
}

func TestParseUsesProjectParser(t *testing.T) {
	e, err := NewEngine(Config{})
	if err != nil {
		t.Fatal(err)
	}

	for _, xml := range []string{`<r xmlns="urn:r">a<![CDATA[b]]>&amp;c<!--note--><?pi v?></r>`, `<r p:a="1"/>`, `<!DOCTYPE r [<!ENTITY x "value">]><r>&x;</r>`, `<r xmlns:p="relative"/>`, `<r a="1" a="2"/>`} {
		d, parseErr := document.Parse(t.Context(), []byte(xml), document.DefaultLimits())

		view, viewErr := e.Parse(context.Background(), []byte(xml))
		if (parseErr == nil) != (viewErr == nil) {
			t.Fatalf("different XML parsing policy for %s: %v / %v", xml, parseErr, viewErr)
		}

		if parseErr == nil {
			want, _ := d.XML(t.Context())

			got, _ := view.native.Snapshot().XML(t.Context())
			if !bytes.Equal(got, want) {
				t.Fatalf("different parser trees: %s / %s", got, want)
			}
		}
	}
}

func TestInputPolicyCacheRemainsBoundedAndChecksStricterLimits(t *testing.T) {
	ctx := context.Background()

	e, err := NewEngine(Config{})
	if err != nil {
		t.Fatal(err)
	}

	d, err := e.Parse(ctx, []byte(`<r><n/></r>`))
	if err != nil {
		t.Fatal(err)
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

	d, err := e.parseOptions().ParseReader(context.Background(), strings.NewReader(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}

	if root := d.DocumentElement(); root == nil || root.LocalName() != "r" {
		t.Fatal("reader lost the XML document")
	}
}
