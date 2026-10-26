package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

const expressionFalse = "false()"

func TestExtensionBoundary(t *testing.T) {
	ctx := t.Context()
	d := parse(t, `<r><included/><excluded/></r>`)
	sparse, _ := document.NewNodeSet(d, d.Root().Children()[0].Node())
	input, _ := reference.Nodes(sparse)

	foreign := all(t, parse(t, `<r><included/><excluded/></r>`))
	for _, tt := range []struct {
		name   string
		output reference.Data
	}{
		{"foreign snapshot", foreign}, {"reintroduce excluded node", all(t, d)}, {"wrong kind", reference.Octets([]byte("not nodes"))}, {"zero data", reference.Data{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &extensionStub{apply: func(context.Context, reference.Transform, reference.Data, reference.ExtensionContext) (reference.Data, error) {
				return tt.output, nil
			}}

			out, e := reference.Process(ctx, input, []reference.Transform{xpathTrue()}, extensionOptions(p))
			if out != nil || !errors.Is(e, reference.ErrInput) {
				t.Fatalf("out=%v error=%v", out, e)
			}
		})
	}

	t.Run("whole chain approved before execution", func(t *testing.T) {
		calls := 0
		p := &extensionStub{validate: func(_ context.Context, tr reference.Transform) error {
			if tr.XPath[0].Expression == expressionFalse {
				return reference.ErrPolicy
			}

			return nil
		}, apply: func(_ context.Context, _ reference.Transform, d reference.Data, _ reference.ExtensionContext) (reference.Data, error) {
			calls++
			return d, nil
		}}
		last := xpathTrue()
		last.XPath[0].Expression = expressionFalse

		out, e := reference.Process(ctx, input, []reference.Transform{xpathTrue(), last}, extensionOptions(p))
		if out != nil || !errors.Is(e, reference.ErrPolicy) || calls != 0 {
			t.Fatal(out, e, calls)
		}
	})
	t.Run("no backend or typed nil", func(t *testing.T) {
		var ptr *extensionStub
		for _, backend := range []reference.ExtensionProcessor{nil, ptr} {
			if e := reference.PrepareTransforms(ctx, []reference.Transform{xpathTrue()}, extensionOptions(backend)); !errors.Is(e, reference.ErrPolicy) {
				t.Fatal(e)
			}
		}
	})
	t.Run("default policy does not opt in", func(t *testing.T) {
		o := reference.DefaultOptions()

		o.Extension = &extensionStub{}
		if e := reference.PrepareTransforms(ctx, []reference.Transform{xpathTrue()}, o); !errors.Is(e, reference.ErrPolicy) {
			t.Fatal(e)
		}
	})
	t.Run("cancel after callback", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		p := &extensionStub{apply: func(_ context.Context, _ reference.Transform, d reference.Data, _ reference.ExtensionContext) (reference.Data, error) {
			cancel()
			return d, nil
		}}

		out, e := reference.Process(ctx, input, []reference.Transform{xpathTrue()}, extensionOptions(p))
		if out != nil || !errors.Is(e, context.Canceled) {
			t.Fatal(out, e)
		}
	})

	style := reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"/>`)}

	t.Run("XSLT output budget", func(t *testing.T) {
		p := &extensionStub{apply: func(context.Context, reference.Transform, reference.Data, reference.ExtensionContext) (reference.Data, error) {
			return reference.Octets(make([]byte, 1025)), nil
		}}
		o := extensionOptions(p)
		o.MaxOutputBytes = 1024

		out, e := reference.Process(ctx, reference.Octets([]byte(`<r/>`)), []reference.Transform{style}, o)
		if out != nil || !errors.Is(e, reference.ErrLimit) {
			t.Fatal(out, e)
		}
	})
	t.Run("XSLT node output forbidden", func(t *testing.T) {
		p := &extensionStub{apply: func(context.Context, reference.Transform, reference.Data, reference.ExtensionContext) (reference.Data, error) {
			return input, nil
		}}

		out, e := reference.Process(ctx, reference.Octets([]byte(`<r/>`)), []reference.Transform{style}, extensionOptions(p))
		if out != nil || !errors.Is(e, reference.ErrInput) {
			t.Fatal(out, e)
		}
	})
}

func TestExtensionClone(t *testing.T) {
	d := parse(t, `<r/>`)
	tr := xpathTrue()
	tr.XPath[0].Namespaces = map[string]string{"p": "urn:one"}
	tr.XPath[0].Here = d.Root()
	tr.Stylesheet = []byte("data")
	snapshot := reference.CloneTransforms([]reference.Transform{tr})
	snapshot[0].XPath[0].Namespaces["p"] = "changed"
	snapshot[0].XPath[0].Expression = "changed"

	snapshot[0].Stylesheet[0] = 'X'
	if tr.XPath[0].Namespaces["p"] != "urn:one" || tr.XPath[0].Expression != nameTrue || string(tr.Stylesheet) != "data" || snapshot[0].XPath[0].Here != d.Root() {
		t.Fatal("mutable alias")
	}
}

func FuzzExtensionParameters(f *testing.F) {
	for _, s := range []string{nameTrue, "$v", "//*[", "here()"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 32<<10 {
			t.Skip()
		}

		tr := xpathTrue()
		tr.XPath[0].Expression = s
		_ = reference.ValidateTransformParameters(tr)
	})
}

func TestApprovalCannotMutateExecutedProgram(t *testing.T) {
	const originalNamespace = "urn:original"

	doc := parse(t, `<r>value</r>`)
	program := xpathTrue()
	program.XPath[0].Namespaces = map[string]string{"p": originalNamespace}
	processor := &extensionStub{
		validate: func(_ context.Context, tr reference.Transform) error {
			tr.XPath[0].Expression = expressionFalse
			tr.XPath[0].Namespaces["p"] = "urn:changed"

			return nil
		},
		apply: func(_ context.Context, tr reference.Transform, input reference.Data, _ reference.ExtensionContext) (reference.Data, error) {
			if tr.XPath[0].Expression != "true()" || tr.XPath[0].Namespaces["p"] != originalNamespace {
				return reference.Data{}, errors.New("approval mutated executed parameters")
			}

			return input, nil
		},
	}

	options := extensionOptions(processor)
	if err := reference.PrepareTransforms(t.Context(), []reference.Transform{program}, options); err != nil {
		t.Fatal(err)
	}

	output, err := reference.Process(t.Context(), all(t, doc), []reference.Transform{program}, options)
	if err != nil || string(output.Bytes()) != `<r>value</r>` || program.XPath[0].Expression != "true()" || program.XPath[0].Namespaces["p"] != originalNamespace {
		t.Fatal("parameter isolation changed", err)
	}
}

func TestProgramFingerprintMatchesJSONEncoding(t *testing.T) {
	for _, program := range []reference.Transform{
		{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: `@a = "<&"`, Namespaces: map[string]string{"p": "urn:p", "q": "urn:q"}}}},
		{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><!--ignored--><xsl:template match="/"><r a="&quot;">x&amp;y</r></xsl:template></xsl:stylesheet>`)},
	} {
		oracle := reference.CloneTransforms([]reference.Transform{program})[0]
		if oracle.Algorithm == reference.XSLT {
			doc, err := document.Parse(t.Context(), oracle.Stylesheet, document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			var canonical bytes.Buffer
			if err := c14n.WriteDocument(t.Context(), &canonical, doc, c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
				t.Fatal(err)
			}

			oracle.Stylesheet = canonical.Bytes()
		}

		for i := range oracle.XPath {
			oracle.XPath[i].Here = document.Element{}
			oracle.XPath[i].Namespaces["xml"] = document.XMLNamespace
		}

		wire, err := json.Marshal(oracle)
		if err != nil {
			t.Fatal(err)
		}

		want := sha256.Sum256(wire)

		got, err := reference.ProgramFingerprint(program)
		if err != nil || got != hex.EncodeToString(want[:]) {
			t.Fatal("allowlist fingerprint changed", got, err)
		}
	}
}

type extensionStub struct {
	validate func(context.Context, reference.Transform) error
	apply    func(context.Context, reference.Transform, reference.Data, reference.ExtensionContext) (reference.Data, error)
}

func (s *extensionStub) Validate(c context.Context, t reference.Transform) error {
	if s.validate != nil {
		return s.validate(c, t)
	}

	return nil
}

func (s *extensionStub) Apply(c context.Context, t reference.Transform, d reference.Data, e reference.ExtensionContext) (reference.Data, error) {
	if s.apply != nil {
		return s.apply(c, t, d, e)
	}

	return d, nil
}

func extensionOptions(p reference.ExtensionProcessor) reference.Options {
	o := reference.DefaultOptions()
	o.Extension = p
	o.AllowedTransforms = append(o.AllowedTransforms, reference.XPath, reference.XPathFilter2, reference.XSLT)

	return o
}

func xpathTrue() reference.Transform {
	return reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: nameTrue}}}
}

func TestCanonicalizedOutputRunsProgramOnce(t *testing.T) {
	calls := 0
	engine := &extensionStub{apply: func(_ context.Context, _ reference.Transform, input reference.Data, _ reference.ExtensionContext) (reference.Data, error) {
		calls++
		if calls > 1 {
			return reference.Data{}, errors.New("program replayed")
		}
		return input, nil
	}}
	var original, alternate bytes.Buffer
	source := `<r xmlns:u="urn:unused">text</r>`
	report, err := reference.WriteReaderAndCanonicalize(t.Context(), &original, &alternate, strings.NewReader(source), []reference.Transform{xpathTrue()}, reference.Transform{Algorithm: c14n.Exclusive}, extensionOptions(engine))
	if err != nil || report == nil || calls != 1 || original.String() != source || alternate.String() != `<r>text</r>` {
		t.Fatal(original.String(), alternate.String(), calls, err)
	}
}
