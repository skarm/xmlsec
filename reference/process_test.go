package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

const nameHello = "Hello"

func TestOctetsAndImplicitCanonicalization(t *testing.T) {
	t.Run("binary stays binary", func(t *testing.T) {
		raw := []byte{0, 255, 1, '<', 'x'}
		data := reference.Octets(raw)
		raw[0] = 20
		out := process(t, data, nil, reference.Options{})

		want := []byte{0, 255, 1, '<', 'x'}
		if !bytes.Equal(out.Bytes(), want) || out.Canonicalization() != "" || len(out.Steps()) != 0 || out.ProducedBytes() != len(want) {
			t.Fatalf("invalid raw output: %#v", out.Steps())
		}

		out.Bytes()[0] = 33

		b, ok := data.Bytes()
		if !ok {
			t.Fatal("no bytes")
		}

		b[0] = 15

		if out.Bytes()[0] != 0 {
			t.Fatal("mutable alias")
		}
	})
	t.Run("node set defaults to C14N 1.0", func(t *testing.T) {
		d := parse(t, `<r xmlns:u="urn:unused" z="2" a="1">text<!--c--></r>`)

		out := process(t, all(t, d), nil, reference.Options{})
		if string(out.Bytes()) != `<r xmlns:u="urn:unused" a="1" z="2">text</r>` {
			t.Fatal(string(out.Bytes()))
		}

		if out.Canonicalization() != c14n.Canonical10 || len(out.Steps()) != 1 || !out.Steps()[0].Implicit || out.InputKind() != reference.NodeSet {
			t.Fatal(out.Steps())
		}
	})
	t.Run("implicit conversion needs permission", func(t *testing.T) {
		out, err := reference.Process(t.Context(), all(t, parse(t, `<r/>`)), nil, reference.Options{AllowedTransforms: []string{c14n.Exclusive}})
		if out != nil || !errors.Is(err, reference.ErrPolicy) {
			t.Fatal(out, err)
		}

		var step *reference.StepError
		if !errors.As(err, &step) || step.Index != -1 || step.Algorithm != c14n.Canonical10 {
			t.Fatal(err)
		}
	})
	t.Run("empty data valid, zero data invalid", func(t *testing.T) {
		out := process(t, reference.Octets(nil), nil, reference.Options{})
		if out.Size() != 0 || out.ProducedBytes() != 0 {
			t.Fatal("not empty")
		}

		if out, err := reference.Process(t.Context(), reference.Data{}, nil, reference.Options{}); out != nil || !errors.Is(err, reference.ErrInput) {
			t.Fatal(out, err)
		}

		set, _ := document.NewNodeSet(parse(t, `<r/>`))

		data, _ := reference.Nodes(set)
		if out := process(t, data, nil, reference.Options{}); out.Size() != 0 {
			t.Fatal("empty set")
		}
	})
}

func TestCanonicalizationConversions(t *testing.T) {
	algorithms := []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments}
	for _, a := range algorithms {
		t.Run(a, func(t *testing.T) {
			input := []byte(`<r z="2" a="1">text<!--c--></r>`)
			out := process(t, reference.Octets(input), []reference.Transform{{Algorithm: a}}, reference.Options{})

			want := `<r a="1" z="2">text</r>`
			if strings.HasSuffix(a, "WithComments") {
				want = `<r a="1" z="2">text<!--c--></r>`
			}

			if string(out.Bytes()) != want {
				t.Fatal(string(out.Bytes()))
			}

			steps := out.Steps()
			if len(steps) != 2 || steps[0].Algorithm != reference.ParseXML || !steps[0].Implicit || steps[1].Implicit || steps[1].InputKind != reference.NodeSet {
				t.Fatal(steps)
			}

			steps[0].Algorithm = "bad"
			if out.Steps()[0].Algorithm == "bad" {
				t.Fatal("step alias")
			}
		})
	}

	t.Run("octets after previous canonicalization are reparsed", func(t *testing.T) {
		out := process(t, reference.Octets([]byte(`<r/>`)), []reference.Transform{{Algorithm: c14n.Canonical11}, {Algorithm: c14n.Exclusive}}, reference.Options{})
		if len(out.Steps()) != 4 || string(out.Bytes()) != `<r></r>` || out.ProducedBytes() != 14 {
			t.Fatal(out.Steps(), out.ProducedBytes())
		}
	})
	t.Run("DTD stays forbidden", func(t *testing.T) {
		_, err := reference.Process(t.Context(), reference.Octets([]byte(`<!DOCTYPE r [<!ENTITY e "xx">]><r>&e;</r>`)), []reference.Transform{{Algorithm: c14n.Canonical11}}, reference.Options{})
		if !errors.Is(err, document.ErrUnsupported) {
			t.Fatal(err)
		}
	})
}

func TestBase64(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "SGVsbG8=", nameHello},
		{"whitespace", "S G\tVs\nbG8=\r", nameHello},
		{"RFC2045 nonalphabet", "S!G#V$s%bG8=\xff", nameHello},
		{"empty", "", ""},
		{"noncanonical padding bits", "TR==", "M"},
		{"two padding", "TQ==", "M"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := process(t, reference.Octets([]byte(tc.input)), []reference.Transform{{Algorithm: reference.Base64}}, reference.Options{})
			if string(out.Bytes()) != tc.want || out.Canonicalization() != "" {
				t.Fatal(out.Bytes())
			}
		})
	}

	t.Run("node set uses selected text only", func(t *testing.T) {
		d := parse(t, `<r a="BAD">SGV<!--AAAA--><b>sbG8=</b><?pi ignored?></r>`)

		out := process(t, all(t, d), []reference.Transform{{Algorithm: reference.Base64}}, reference.Options{})
		if string(out.Bytes()) != nameHello {
			t.Fatal(string(out.Bytes()))
		}
	})
	t.Run("sparse node set", func(t *testing.T) {
		d := parse(t, `<r>SGV<b>sbG8=</b><ignored>QUJD</ignored></r>`)
		nodes := d.Root().Node().Children()
		b, _ := nodes[1].Element()

		set, err := document.NewNodeSet(d, nodes[0], b.Node().Children()[0])
		if err != nil {
			t.Fatal(err)
		}

		data, _ := reference.Nodes(set)
		if out := process(t, data, []reference.Transform{{Algorithm: reference.Base64}}, reference.Options{}); string(out.Bytes()) != nameHello {
			t.Fatal(string(out.Bytes()))
		}
	})

	for _, input := range []string{"A", "AA", "AAA", "=AAA", "AA=A", "TQ===", "TQ==AA=="} {
		t.Run("invalid-"+input, func(t *testing.T) {
			out, err := reference.Process(t.Context(), reference.Octets([]byte(input)), []reference.Transform{{Algorithm: reference.Base64}}, reference.Options{})
			if out != nil || !errors.Is(err, reference.ErrInput) {
				t.Fatal(out, err)
			}
		})
	}

	t.Run("decode then XML parse then C14N", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`<r z="2" a="1"/>`))

		out := process(t, reference.Octets([]byte(encoded)), []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: c14n.Canonical11}}, reference.Options{})
		if string(out.Bytes()) != `<r a="1" z="2"></r>` || len(out.Steps()) != 3 {
			t.Fatal(string(out.Bytes()), out.Steps())
		}
	})
}

func TestEnvelopedIdentity(t *testing.T) {
	const xml = `<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature ID="one"><x>1</x></ds:Signature><ds:Signature ID="two"><x>2</x></ds:Signature><data>ok</data></r>`

	d := parse(t, xml)
	signature := d.Root().Children()[0]
	ts := []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}

	out := process(t, all(t, d), ts, reference.Options{Signature: signature})

	raw := out.Bytes()
	if bytes.Contains(raw, []byte(`ID="one"`)) || !bytes.Contains(raw, []byte(`ID="two"`)) {
		t.Fatalf("%s", raw)
	}

	original, _ := d.XML(t.Context())
	if string(original) != xml {
		t.Fatal("mutated XML")
	}

	foreign := parse(t, xml)
	for _, opt := range []reference.Options{{}, {Signature: foreign.Root().Children()[0]}, {Signature: d.Root()}} {
		out, err := reference.Process(t.Context(), all(t, d), ts, opt)
		if out != nil || !errors.Is(err, reference.ErrInput) {
			t.Fatal(out, err)
		}
	}
	// Re-serialization breaks node identity; do not strip a lookalike signature.
	out, err := reference.Process(t.Context(), all(t, d), []reference.Transform{{Algorithm: c14n.Exclusive}, {Algorithm: reference.EnvelopedSignature}}, reference.Options{Signature: signature})
	if out != nil || !errors.Is(err, reference.ErrInput) {
		t.Fatal(out, err)
	}
}

func TestLimitsAndPolicies(t *testing.T) {
	nested := base64.StdEncoding.EncodeToString([]byte("SGVsbG8="))
	transforms := []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: reference.Base64}}

	cases := []struct {
		name string
		opt  reference.Options
		want error
	}{
		{"exact total", reference.Options{MaxProducedBytes: 13}, nil},
		{"intermediate counts", reference.Options{MaxProducedBytes: 12}, reference.ErrLimit},
		{"per output", reference.Options{MaxOutputBytes: 7}, reference.ErrLimit},
		{"input", reference.Options{MaxInputBytes: 1}, reference.ErrLimit},
		{"count", reference.Options{MaxTransforms: 1}, reference.ErrLimit},
		{"negative", reference.Options{MaxTransforms: -1}, reference.ErrPolicy},
		{"too many", reference.Options{MaxTransforms: 65}, reference.ErrPolicy},
		{"algorithm", reference.Options{AllowedTransforms: []string{c14n.Exclusive}}, reference.ErrPolicy},
		{"unknown policy", reference.Options{AllowedTransforms: []string{"urn:bad"}}, reference.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := reference.Process(t.Context(), reference.Octets([]byte(nested)), transforms, tc.opt)
			if tc.want == nil {
				if err != nil || out.ProducedBytes() != 13 {
					t.Fatal(out, err)
				}
			} else if out != nil || !errors.Is(err, tc.want) {
				t.Fatal(out, err)
			}
		})
	}

	for _, ts := range [][]reference.Transform{
		{{Algorithm: reference.Base64}, {Algorithm: "urn:unknown"}},
		{{Algorithm: c14n.Canonical11, InclusivePrefixes: []string{"x"}}},
		{{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"xmlns"}}},
		{{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"a:b"}}},
		{{Algorithm: ""}},
	} {
		if out, err := reference.Process(t.Context(), reference.Octets([]byte("TQ==")), ts, reference.Options{}); out != nil || err == nil {
			t.Fatal(out, err)
		}
	}

	if out, err := reference.Process(t.Context(), all(t, parse(t, `<r><x/></r>`)), nil, reference.Options{MaxNodeVisits: 1}); out != nil || !errors.Is(err, reference.ErrLimit) {
		t.Fatal(out, err)
	}

	if out, err := reference.Process(t.Context(), reference.Octets([]byte(`<r>long</r>`)), []reference.Transform{{Algorithm: c14n.Exclusive}}, reference.Options{MaxOutputBytes: 1}); out != nil || err == nil {
		t.Fatal(out, err)
	}
}

func TestCancellationAndConcurrency(t *testing.T) {
	data := all(t, parse(t, `<r><x>ok</x></r>`))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if out, err := reference.Process(ctx, data, nil, reference.Options{}); out != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(out, err)
	}

	if out, err := reference.Process(nil, data, nil, reference.Options{}); out != nil || err == nil {
		t.Fatal(out, err)
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			out, err := reference.Process(t.Context(), data, nil, reference.Options{})
			if err != nil || string(out.Bytes()) != `<r><x>ok</x></r>` {
				t.Error(out, err)
			}
		})
	}

	wg.Wait()
}

func TestFinalBase64ClearsCanonicalizationReport(t *testing.T) {
	// <a> contributes one alphabet symbol and </a> contributes two (/ and a).
	// One text symbol completes a four-symbol RFC2045 block.
	doc := parse(t, `<a>A</a>`)

	result, err := reference.Process(t.Context(), all(t, doc), []reference.Transform{{Algorithm: c14n.Exclusive}, {Algorithm: reference.Base64}}, reference.Options{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Canonicalization() != "" || len(result.Steps()) != 2 || result.Steps()[1].Algorithm != reference.Base64 {
		t.Fatal(result.Canonicalization(), result.Steps())
	}
}

func TestKindJSON(t *testing.T) {
	for _, value := range []reference.Kind{reference.Invalid, reference.OctetStream, reference.NodeSet} {
		data, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}

		var got reference.Kind
		if e := json.Unmarshal(data, &got); e != nil || got != value {
			t.Fatal(string(data), got, e)
		}
	}

	k := reference.NodeSet
	if e := k.UnmarshalText([]byte("typo")); e == nil || k != reference.NodeSet {
		t.Fatal("bad value accepted/mutated")
	}

	var nilKind *reference.Kind
	if e := nilKind.UnmarshalText([]byte("node-set")); e == nil {
		t.Fatal("nil receiver accepted")
	}
}

func FuzzProcess(f *testing.F) {
	for _, s := range []string{"", "SGVsbG8=", `<r a="1"><x>text</x></r>`, `<!DOCTYPE r><r/>`, "\xff\x00"} {
		f.Add([]byte(s), uint8(0))
	}

	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			t.Skip()
		}

		data := reference.Octets(raw)
		transforms := [][]reference.Transform{nil, {{Algorithm: reference.Base64}}, {{Algorithm: c14n.Canonical11}}, {{Algorithm: reference.Base64}, {Algorithm: c14n.Exclusive}}, {{Algorithm: c14n.Exclusive}, {Algorithm: reference.Base64}}, {{Algorithm: reference.Base64}, {Algorithm: reference.Base64}}}

		chain := transforms[int(mode)%len(transforms)]
		options := reference.Options{MaxInputBytes: 4096, MaxOutputBytes: 8192, MaxProducedBytes: 16384, MaxNodeVisits: 8192}

		out, err := reference.Process(t.Context(), data, chain, options)
		if err != nil && out != nil {
			t.Fatal("partial output")
		}

		var streamed bytes.Buffer

		report, readerErr := reference.WriteReader(t.Context(), &streamed, bytes.NewReader(raw), chain, options)
		if (err == nil) != (readerErr == nil) {
			t.Fatalf("reader/process error mismatch: %v / %v", err, readerErr)
		}

		if err == nil && (!bytes.Equal(out.Bytes(), streamed.Bytes()) || out.Size() != report.Size() || out.ProducedBytes() != report.ProducedBytes()) {
			t.Fatal("reader/process result mismatch")
		}

		got, _ := data.Bytes()
		if !bytes.Equal(got, raw) {
			t.Fatal("input mutated")
		}

		if out != nil && out.ProducedBytes() > 16384 {
			t.Fatal("budget exceeded")
		}
	})
}

func BenchmarkBase64Pipeline(b *testing.B) {
	data := reference.Octets([]byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 8192))))
	tr := []reference.Transform{{Algorithm: reference.Base64}}

	b.ReportAllocs()
	b.SetBytes(8192)

	for b.Loop() {
		if _, err := reference.Process(b.Context(), data, tr, reference.Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDigestStreaming(b *testing.B) {
	for _, size := range []int{16 << 10, 1 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			doc, err := document.Parse(b.Context(), bytes.Join([][]byte{[]byte("<r>"), bytes.Repeat([]byte("x"), size), []byte("</r>")}, nil), document.DefaultLimits())
			if err != nil {
				b.Fatal(err)
			}

			nodes, err := doc.AllNodes(b.Context())
			if err != nil {
				b.Fatal(err)
			}

			data, err := reference.Nodes(nodes)
			if err != nil {
				b.Fatal(err)
			}

			transforms := []reference.Transform{{Algorithm: c14n.Exclusive}}

			b.Run("Writer", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))

				for b.Loop() {
					hash := sha256.New()
					if _, err := reference.Write(b.Context(), hash, data, transforms, reference.Options{}); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Buffered", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))

				for b.Loop() {
					result, err := reference.Process(b.Context(), data, transforms, reference.Options{})
					if err != nil {
						b.Fatal(err)
					}

					hash := sha256.Sum256(result.Bytes())
					_ = hash
				}
			})
		})
	}
}

func BenchmarkReaderDigestStreaming(b *testing.B) {
	for _, depth := range []int{0, 1, 2} {
		for _, size := range []int{16 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("base64-%d/%d", depth, size), func(b *testing.B) {
				source := bytes.Repeat([]byte("x"), size)

				transforms := make([]reference.Transform, 0, depth)

				for range depth {
					source = []byte(base64.StdEncoding.EncodeToString(source))

					transforms = append(transforms, reference.Transform{Algorithm: reference.Base64})
				}

				b.ReportAllocs()
				b.SetBytes(int64(size))

				for b.Loop() {
					if _, err := reference.WriteReader(b.Context(), sha256.New(), bytes.NewReader(source), transforms, reference.Options{}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestWriteAndCanonicalize(t *testing.T) {
	doc := parse(t, `<r xmlns:u="urn:unused" b="2" a="1">text<!--comment--></r>`)
	input := all(t, doc)
	for _, explicit := range []bool{false, true} {
		t.Run(strconv.FormatBool(explicit), func(t *testing.T) {
			var transforms []reference.Transform
			if explicit {
				transforms = []reference.Transform{{Algorithm: c14n.Canonical10}}
			}
			var original, alternate bytes.Buffer
			report, err := reference.WriteAndCanonicalize(t.Context(), &original, &alternate, input, transforms, reference.Transform{Algorithm: c14n.ExclusiveWithComments}, reference.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if original.String() != `<r xmlns:u="urn:unused" a="1" b="2">text</r>` {
				t.Fatal(original.String())
			}
			want := `<r a="1" b="2">text<!--comment--></r>`
			if explicit {
				want = original.String()
			}
			if alternate.String() != want {
				t.Fatal(alternate.String())
			}
			if report.Size() != original.Len() {
				t.Fatal("wrong digest input size")
			}
		})
	}
	t.Run("opaque octets stay opaque", func(t *testing.T) {
		var a, b bytes.Buffer
		raw := []byte{0, 255, '<'}
		if _, err := reference.WriteReaderAndCanonicalize(t.Context(), &a, &b, bytes.NewReader(raw), nil, reference.Transform{Algorithm: c14n.Exclusive}, reference.Options{}); err != nil || !bytes.Equal(a.Bytes(), raw) || !bytes.Equal(b.Bytes(), raw) {
			t.Fatal(a.Bytes(), b.Bytes(), err)
		}
	})
	for _, kind := range []string{"produced", "visits", "cancel", "writer"} {
		t.Run(kind, func(t *testing.T) {
			options := reference.DefaultOptions()
			var a, b bytes.Buffer
			ctx := t.Context()
			var output io.Writer = &b
			want := reference.ErrLimit
			switch kind {
			case "produced":
				options.MaxProducedBytes = 10
			case "visits":
				nodes, _ := input.Nodes()
				options.MaxNodeVisits = nodes.Len() * 2
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "writer":
				want = errors.New("alternate writer")
				output = canonicalErrorWriter{want}
			}
			report, err := reference.WriteAndCanonicalize(ctx, &a, output, input, nil, reference.Transform{Algorithm: c14n.Exclusive}, options)
			if report != nil || !errors.Is(err, want) {
				t.Fatal(report, err)
			}
		})
	}
}

type canonicalErrorWriter struct{ err error }

func (w canonicalErrorWriter) Write([]byte) (int, error) { return 0, w.err }
