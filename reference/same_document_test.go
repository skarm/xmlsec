package reference_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

func TestSameDocumentSemantics(t *testing.T) {
	d := parse(t, `<!--before--><?p before?><r ID="root"><x ID="foo">text<!--inside--></x></r><!--after--><?p after?>`)

	resolver, err := reference.NewSameDocumentResolver(context.Background(), d, document.Name{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		uri      string
		whole    bool
		comments bool
	}{
		{"", true, false},
		{"#foo", false, false},
		{"#f%6Fo", false, false},
		{"#xpointer(/)", true, true},
		{"#xpointer(id('foo'))", false, true},
		{`#xpointer(id("foo"))`, false, true},
		{"#xpointer%28id%28%27foo%27%29%29", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			resolved, err := resolver.Resolve(context.Background(), tc.uri)
			if err != nil {
				t.Fatal(err)
			}

			if resolved.URI() != tc.uri || resolved.WholeDocument() != tc.whole || resolved.RetainsComments() != tc.comments || resolved.Target().Valid() == tc.whole {
				t.Fatal("resolution metadata")
			}

			out := process(t, resolved.Data(), []reference.Transform{{Algorithm: c14n.ExclusiveWithComments}}, reference.Options{})

			raw := out.Bytes()
			if bytes.Contains(raw, []byte("<!--inside-->")) != tc.comments {
				t.Fatalf("%s", raw)
			}

			if bytes.Contains(raw, []byte("<?p before?>")) != tc.whole {
				t.Fatalf("document-level PI lost: %s", raw)
			}

			if bytes.Contains(raw, []byte("<!--before-->")) != (tc.whole && tc.comments) {
				t.Fatalf("wrong document comment: %s", raw)
			}
		})
	}

	for _, uri := range []string{"#", "#missing", "#%", "#%FF", "#f%256Fo", "#xpointer(id(foo))", "#xpointer(id('foo bar'))", "#xpointer(id('foo\"))", "#xpointer( / )", "#element(foo)", "file.xml", "https://example.invalid/xml#foo"} {
		t.Run("reject-"+uri, func(t *testing.T) {
			resolved, err := resolver.Resolve(context.Background(), uri)
			if err == nil || resolved.Data().Kind() != reference.Invalid {
				t.Fatal(resolved, err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := resolver.Resolve(ctx, "#foo"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	if _, err := resolver.Resolve(nil, "#foo"); err == nil {
		t.Fatal("nil context")
	}
}

func TestIDRules(t *testing.T) {
	for _, input := range []string{`<r ID="x"><c ID="x"/></r>`, `<r ID="1x"/>`, `<r ID=""/>`} {
		if _, err := reference.NewSameDocumentResolver(context.Background(), parse(t, input), document.Name{}); !errors.Is(err, reference.ErrInput) {
			t.Fatal(input, err)
		}
	}

	d := parse(t, `<r xmlns:w="urn:wsu" ID="root" w:Id="r"><c ID="child" w:Id="c"/></r>`)

	resolver, err := reference.NewSameDocumentResolver(context.Background(), d, document.Name{Space: "urn:wsu", Local: "Id"})
	if err != nil {
		t.Fatal(err)
	}

	r, err := resolver.Resolve(context.Background(), "#c")
	if err != nil || !r.Target().Same(d.Root().Children()[0]) {
		t.Fatal(r, err)
	}

	if _, err := resolver.Resolve(context.Background(), "#child"); err == nil {
		t.Fatal("guessed ID attribute")
	}

	for _, name := range []document.Name{{Local: "a:b"}, {Space: "http://www.w3.org/2000/xmlns/", Local: "ID"}} {
		if _, err := reference.NewSameDocumentResolver(context.Background(), d, name); !errors.Is(err, reference.ErrPolicy) {
			t.Fatal(err)
		}
	}

	if _, err := reference.NewSameDocumentResolver(nil, d, document.Name{}); err == nil {
		t.Fatal("nil context")
	}

	if _, err := reference.NewSameDocumentResolver(context.Background(), nil, document.Name{}); err == nil {
		t.Fatal("nil doc")
	}

	var zero *reference.SameDocumentResolver
	if _, err := zero.Resolve(context.Background(), ""); err == nil {
		t.Fatal("nil resolver")
	}
}

func TestScopedIDRules(t *testing.T) {
	ctx := context.Background()
	app := reference.IDAttributeRule{Attribute: document.Name{Local: "ID"}}
	scoped := reference.IDAttributeRule{Attribute: document.Name{Local: "Id"}, Elements: []document.Name{{Space: "urn:ds", Local: "Object"}}}

	for _, tc := range []struct {
		name  string
		xml   string
		valid bool
	}{
		{"scoped", `<r><x ID="app"/><d:Object xmlns:d="urn:ds" Id="object"/><x Id="object"/></r>`, true},
		{"collision", `<r><x ID="app"/><d:Object xmlns:d="urn:ds" Id="app"/></r>`, false},
		{"double-attribute", `<d:Object xmlns:d="urn:ds" ID="a" Id="b"/>`, false},
		{"same-value-double-attribute", `<d:Object xmlns:d="urn:ds" ID="a" Id="a"/>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := reference.NewSameDocumentResolverWithRules(ctx, parse(t, tc.xml), []reference.IDAttributeRule{app, scoped, scoped})
			if !tc.valid {
				if !errors.Is(e, reference.ErrInput) {
					t.Fatal(e)
				}

				return
			}

			if e != nil {
				t.Fatal(e)
			}

			for _, id := range []string{"#app", "#object"} {
				if _, e := r.Resolve(ctx, id); e != nil {
					t.Fatal(e)
				}
			}
		})
	}

	d := parse(t, `<r ID="not-indexed"/>`)

	r, e := reference.NewSameDocumentResolverWithRules(ctx, d, nil)
	if e != nil {
		t.Fatal(e)
	}

	if _, e := r.Resolve(ctx, "#not-indexed"); e == nil {
		t.Fatal("implicit ID typing")
	}

	if _, e := r.Resolve(ctx, ""); e != nil {
		t.Fatal(e)
	}

	for _, rules := range [][]reference.IDAttributeRule{
		{{Attribute: document.Name{Local: "bad name"}}},
		{{Attribute: document.Name{Local: "ID"}, Elements: []document.Name{{Local: "bad:name"}}}},
		make([]reference.IDAttributeRule, 33),
	} {
		if _, e := reference.NewSameDocumentResolverWithRules(ctx, d, rules); !errors.Is(e, reference.ErrPolicy) {
			t.Fatal(e)
		}
	}
}
