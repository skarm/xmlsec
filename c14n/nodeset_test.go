package c14n_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

const (
	xmlRXmlBaseABCCXml    = "<r xml:base=\"a//b/../c\"><c xml:base=\"..\"></c></r>"
	xmlRXmlnsUrnRCXmlnsXX = "<r xmlns=\"urn:r\"><c xmlns=\"\"><x></x></c></r>"
)

func TestCanonicalAlgorithms(t *testing.T) {
	tests := []struct {
		name, xml, want10, want11, wantExclusive string
		child                                    bool
	}{
		{"namespace context", `<r xmlns:p="urn:p"><c/></r>`, `<r xmlns:p="urn:p"><c></c></r>`, `<r xmlns:p="urn:p"><c></c></r>`, `<r><c></c></r>`, false},
		{"empty default", `<r xmlns="urn:r"><c xmlns=""><x/></c></r>`, xmlRXmlnsUrnRCXmlnsXX, xmlRXmlnsUrnRCXmlnsXX, xmlRXmlnsUrnRCXmlnsXX, false},
		{"inherit simple", `<r xml:lang="ru" xml:space="preserve"><c/></r>`, `<c xml:lang="ru" xml:space="preserve"></c>`, `<c xml:lang="ru" xml:space="preserve"></c>`, canonicalEmptyChildXML, true},
		{"inherit xml id only 10", `<r xml:id="outer"><c/></r>`, `<c xml:id="outer"></c>`, canonicalEmptyChildXML, canonicalEmptyChildXML, true},
		{"unknown xml attribute", `<r xml:future="value"><c/></r>`, `<c xml:future="value"></c>`, canonicalEmptyChildXML, canonicalEmptyChildXML, true},
		{"xml base join", `<r xml:base="http://example.test/a/b/"><c xml:base="../x"/></r>`, `<c xml:base="../x"></c>`, `<c xml:base="http://example.test/a/x"></c>`, `<c xml:base="../x"></c>`, true},
		{"relative bases", `<r xml:base=".."><c xml:base=".."/></r>`, `<c xml:base=".."></c>`, `<c xml:base="../../"></c>`, `<c xml:base=".."></c>`, true},
		{"empty join omitted", `<r xml:base="abc/"><c xml:base="../"/></r>`, `<c xml:base="../"></c>`, canonicalEmptyChildXML, `<c xml:base="../"></c>`, true},
		{"no fixup in full document", `<r xml:base="a//b/../c"><c xml:base=".."/></r>`, xmlRXmlBaseABCCXml, xmlRXmlBaseABCCXml, xmlRXmlBaseABCCXml, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { testCanonicalAlgorithmsCase(t, &tt) })
	}
}

func testCanonicalAlgorithmsCase(t *testing.T, tt *struct {
	name          string
	xml           string
	want10        string
	want11        string
	wantExclusive string
	child         bool
},
) {
	d := parse(t, tt.xml)
	for _, method := range []struct{ uri, want string }{{c14n.Canonical10, tt.want10}, {c14n.Canonical11, tt.want11}, {c14n.Exclusive, tt.wantExclusive}} {
		t.Run(method.uri, func(t *testing.T) {
			var (
				direct bytes.Buffer
				set    document.NodeSet
				err    error
			)

			opt := c14n.Options{Algorithm: method.uri}

			if tt.child {
				e := d.Root().Children()[0]

				set, err = e.Subtree(t.Context())
				if err == nil {
					err = c14n.WriteElement(context.Background(), &direct, e, opt)
				}
			} else {
				set = all(t, d)
				err = c14n.WriteDocument(context.Background(), &direct, d, opt)
			}

			if err != nil {
				t.Fatal(err)
			}

			got := canonSet(t, set, opt)
			if got != method.want || direct.String() != got {
				t.Fatalf("set %q\ndirect %q\nwant %q", got, direct.String(), method.want)
			}
			// Attribute inheritance / fixup must never mutate the snapshot.
			fresh := parse(t, tt.xml)
			a, _ := d.XML(t.Context())

			b, _ := fresh.XML(t.Context())
			if !bytes.Equal(a, b) {
				t.Fatal("canonicalization mutated document")
			}
		})
	}
}

func TestSparseNodeSets(t *testing.T) {
	d := parse(t, `<?p before?><r xmlns:p="urn:p" a="1">A<c p:b="2">B<![CDATA[C]]></c>D<!--end--></r><?p after?>`)
	root := d.Root()
	child := root.Children()[0]

	for _, algorithm := range []string{c14n.Exclusive, c14n.Canonical10, c14n.Canonical11} {
		t.Run(algorithm, func(t *testing.T) {
			cases := []struct {
				name  string
				nodes []document.Node
				want  string
			}{
				{"empty", nil, ""},
				{"document only", []document.Node{d.Node()}, ""},
				{"element only", []document.Node{root.Node()}, explicitEmptyRootXML},
				{"text only", []document.Node{child.Node().Children()[0]}, "BC"},
				{"attribute only", []document.Node{root.AttributeNodes()[0]}, ` a="1"`},
				{"missing parent", []document.Node{root.Node(), child.Node().Children()[0]}, `<r>BC</r>`},
				{"PIs without root", []document.Node{d.Node().Children()[0], d.Node().Children()[2]}, "<?p before?>\n\n<?p after?>"},
			}
			for _, tt := range cases {
				t.Run(tt.name, func(t *testing.T) {
					s, err := document.NewNodeSet(d, tt.nodes...)
					if err != nil {
						t.Fatal(err)
					}

					if got := canonSet(t, s, c14n.Options{Algorithm: algorithm}); got != tt.want {
						t.Fatalf("got %q want %q", got, tt.want)
					}
				})
			}
		})
	}
}

func TestSparseNamespaces(t *testing.T) {
	d := parse(t, `<r xmlns:p="urn:p"><a><p:b/></a></r>`)
	root := d.Root()
	a := root.Children()[0]
	b := a.Children()[0]
	// r selects p, a intentionally does not; b must redeclare relative to its
	// nearest OUTPUT parent's selected axis in inclusive canonicalization.
	ns := func(e document.Element, p string) document.Node {
		for _, n := range e.NamespaceNodes() {
			if n.Name().Local == p {
				return n
			}
		}

		t.Fatal("missing namespace")

		return document.Node{}
	}

	s, err := document.NewNodeSet(d, root.Node(), ns(root, "p"), a.Node(), b.Node(), ns(b, "p"))
	if err != nil {
		t.Fatal(err)
	}

	for _, alg := range []string{c14n.Canonical10, c14n.Canonical11} {
		if got := canonSet(t, s, c14n.Options{Algorithm: alg}); got != `<r xmlns:p="urn:p"><a><p:b xmlns:p="urn:p"></p:b></a></r>` {
			t.Fatal(got)
		}
	}

	onlyNS, _ := document.NewNodeSet(d, ns(root, "p"))
	if got := canonSet(t, onlyNS, c14n.Options{Algorithm: c14n.Canonical10}); got != ` xmlns:p="urn:p"` {
		t.Fatal(got)
	}

	if got := canonSet(t, onlyNS, c14n.Options{}); got != "" {
		t.Fatal(got)
	}

	if got := canonSet(t, onlyNS, c14n.Options{InclusivePrefixes: []string{"p"}}); got != ` xmlns:p="urn:p"` {
		t.Fatal(got)
	}
	// Selected namespaces are not automatically added because a name needs one.
	bare, _ := document.NewNodeSet(d, b.Node())
	if got := canonSet(t, bare, c14n.Options{InclusivePrefixes: []string{"p"}}); got != `<p:b></p:b>` {
		t.Fatal(got)
	}
}

func TestOmittedXMLAttributeShadowsInheritance(t *testing.T) {
	// C14N 1.0 §2.4 / C14N 1.1 §2.4: an attribute already on the orphan
	// element suppresses ancestor inheritance WHETHER OR NOT it is selected.
	d := parse(t, `<r xml:lang="en" xml:space="preserve"><c xml:lang="ru"/></r>`)

	s, _ := document.NewNodeSet(d, d.Root().Children()[0].Node())
	for _, alg := range []string{c14n.Canonical10, c14n.Canonical11} {
		if got := canonSet(t, s, c14n.Options{Algorithm: alg}); got != `<c xml:space="preserve"></c>` {
			t.Fatal(got)
		}
	}
}

func TestW3C11ErratumE1101(t *testing.T) {
	// Adapted from §3.8, applying the E11-01 erratum. DTD defaults are made
	// explicit because DTD processing is outside this library's input profile.
	d := parse(t, `<doc xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org" xml:base="something/else"><e1><e2 xmlns="" xml:id="abc" xml:base="bar/" xml:space="preserve"><e3 id="E3" xml:base="foo"/></e2></e1></doc>`)
	e1 := d.Root().Children()[0]
	e3 := e1.Children()[0].Children()[0]
	refs := append([]document.Node{e1.Node()}, e1.NamespaceNodes()...)
	head, _ := document.NewNodeSet(d, refs...)
	tail, _ := e3.Subtree(t.Context())
	set, _ := head.Union(tail)

	want := `<e1 xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org" xml:base="something/else"><e3 xmlns="" id="E3" xml:base="bar/foo" xml:space="preserve"></e3></e1>`
	if got := canonSet(t, set, c14n.Options{Algorithm: c14n.Canonical11}); got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

func TestCommentAlgorithmURIs(t *testing.T) {
	d := parse(t, `<!--pre--><r><!--in--></r><!--post-->`)
	for _, alg := range []string{c14n.ExclusiveWithComments, c14n.Canonical10WithComments, c14n.Canonical11WithComments} {
		t.Run(alg, func(t *testing.T) {
			if got := canonSet(t, all(t, d), c14n.Options{Algorithm: alg}); got != "<!--pre-->\n<r><!--in--></r>\n<!--post-->" {
				t.Fatal(got)
			}
		})
	}
	// A comments algorithm does not re-add comments removed from the node-set.
	noComments := make([]document.Node, 0)

	for _, n := range all(t, d).Nodes() {
		if n.Kind() != document.CommentNode {
			noComments = append(noComments, n)
		}
	}

	s, _ := document.NewNodeSet(d, noComments...)
	if got := canonSet(t, s, c14n.Options{Algorithm: c14n.Canonical11WithComments}); got != explicitEmptyRootXML {
		t.Fatal(got)
	}
}

func TestNewCanonicalErrors(t *testing.T) {
	d := parse(t, emptyRootXML)
	s := all(t, d)

	cases := []struct {
		name string
		opt  c14n.Options
		want error
	}{
		{"unknown algorithm", c14n.Options{Algorithm: "urn:unknown"}, document.ErrUnsupported},
		{"prefixes with inclusive", c14n.Options{Algorithm: c14n.Canonical11, InclusivePrefixes: []string{"p"}}, document.ErrUnsupported},
		{"negative budget", c14n.Options{MaxOutputBytes: -1}, document.ErrLimit},
		{"namespace reserved prefix", c14n.Options{InclusivePrefixes: []string{"xmlns"}}, document.ErrMalformed},
		{"too many prefixes", c14n.Options{InclusivePrefixes: make([]string, 129)}, document.ErrLimit},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := c14n.WriteNodeSet(context.Background(), io.Discard, s, tt.opt); !errors.Is(err, tt.want) {
				t.Fatal(err)
			}
		})
	}

	if err := c14n.WriteNodeSet(context.Background(), io.Discard, document.NodeSet{}, c14n.Options{}); !errors.Is(err, document.ErrMalformed) {
		t.Fatal(err)
	}

	if err := c14n.WriteNodeSet(nil, io.Discard, s, c14n.Options{}); !errors.Is(err, document.ErrMalformed) {
		t.Fatal(err)
	}

	if err := c14n.WriteNodeSet(context.Background(), nil, s, c14n.Options{}); !errors.Is(err, document.ErrMalformed) {
		t.Fatal(err)
	}

	sentinel := errors.New("sentinel writer error")
	if err := c14n.WriteNodeSet(context.Background(), failingWriter{sentinel}, s, c14n.Options{}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func TestSparseDocumentBoundaryComments(t *testing.T) {
	d, err := document.Parse(t.Context(), []byte(`<!--before--><r><!--inside--></r><!--after-->`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	all, err := d.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	var chosen []document.Node

	for _, n := range all.Nodes() {
		if n.Kind() == document.CommentNode {
			chosen = append(chosen, n)
		}
	}

	set, err := document.NewNodeSet(d, chosen...)
	if err != nil {
		t.Fatal(err)
	}

	for _, alg := range []string{c14n.Canonical10, c14n.Exclusive, c14n.Canonical11} {
		t.Run(alg, func(t *testing.T) {
			var out bytes.Buffer

			err := c14n.WriteNodeSet(context.Background(), &out, set, c14n.Options{Algorithm: alg, WithComments: true})
			if err != nil {
				t.Fatal(err)
			}

			if want := "<!--before-->\n<!--inside-->\n<!--after-->"; out.String() != want {
				t.Fatalf("got %q, want %q", out.String(), want)
			}
		})
	}
}

func FuzzNodeSets(f *testing.F) {
	f.Add([]byte(`<r xmlns:p="urn:p">a<p:c x="1"/>b</r>`), []byte{1, 2, 3}, uint8(0))
	f.Add([]byte(`<r xml:base="../"><c xml:base=".."/></r>`), []byte{5, 0, 8}, uint8(2))
	f.Fuzz(func(t *testing.T, input, mask []byte, mode uint8) {
		if len(input) > 16<<10 || len(mask) > 1024 {
			t.Skip()
		}

		d, err := document.Parse(t.Context(), input, document.DefaultLimits())
		if err != nil {
			return
		}

		set, err := d.AllNodes(t.Context())
		if err != nil {
			return
		}

		refs := set.Nodes()

		selected := make([]document.Node, 0, len(refs))
		for i, n := range refs {
			if len(mask) > 0 && mask[i%len(mask)]&1 != 0 {
				selected = append(selected, n)
			}
		}

		set, err = document.NewNodeSet(d, selected...)
		if err != nil {
			t.Fatal(err)
		}

		alg := []string{c14n.Canonical10, c14n.Exclusive, c14n.Canonical11}[mode%3]

		var a, b bytes.Buffer

		opt := c14n.Options{Algorithm: alg, WithComments: mode&4 != 0, MaxOutputBytes: 128 << 10}
		ea := c14n.WriteNodeSet(context.Background(), &a, set, opt)

		eb := c14n.WriteNodeSet(context.Background(), &b, set, opt)
		if (ea == nil) != (eb == nil) || !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Fatal("non-deterministic canonicalization")
		}
	})
}

func TestCanonicalSiblingNamespaceScratch(t *testing.T) {
	doc := parse(t, `<r xmlns:p="urn:outer"><a xmlns:p="urn:one"><p:v/></a><a xmlns:p="urn:two"><p:v/></a><a><p:v/></a></r>`)
	for _, sparse := range []bool{false, true} {
		set, err := doc.AllNodes(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if sparse {
			for _, parent := range doc.Root().Children() {
				nodes := append([]document.Node{parent.Node()}, parent.NamespaceNodes()...)

				set, err = set.Without(nodes...)
				if err != nil {
					t.Fatal(err)
				}
			}
		}

		want := `<r><a><p:v xmlns:p="urn:one"></p:v></a><a><p:v xmlns:p="urn:two"></p:v></a><a><p:v xmlns:p="urn:outer"></p:v></a></r>`
		if sparse {
			want = `<r><p:v xmlns:p="urn:one"></p:v><p:v xmlns:p="urn:two"></p:v><p:v xmlns:p="urn:outer"></p:v></r>`
		}

		if got := canonSet(t, set, c14n.Options{}); got != want {
			t.Fatal("namespace scratch leaked across siblings", sparse, got)
		}
	}
}

func parse(t *testing.T, xml string) *document.Document {
	t.Helper()

	d, err := document.Parse(t.Context(), []byte(xml), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	return d
}

func all(t *testing.T, d *document.Document) document.NodeSet {
	t.Helper()

	s, err := d.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func canonSet(t *testing.T, set document.NodeSet, opt c14n.Options) string {
	t.Helper()

	var b bytes.Buffer
	if err := c14n.WriteNodeSet(context.Background(), &b, set, opt); err != nil {
		t.Fatal(err)
	}

	return b.String()
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }
