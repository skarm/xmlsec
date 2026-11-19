package transformxml_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func TestXPathParametersAndHereIdentity(t *testing.T) {
	input := []byte(`<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:p="urn:items" Algorithm="http://www.w3.org/2002/06/xmldsig-filter2"><xf:XPath xmlns:xf="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">//p:<!-- split -->item</xf:XPath></ds:Transform>`)
	doc, err := document.Parse(t.Context(), input, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := transformxml.Parse(t.Context(), doc, tree.Root(doc))
	if err != nil || parsed.Algorithm != reference.XPathFilter2 || len(parsed.XPath) != 1 {
		t.Fatalf("XPath program: %+v, %v", parsed, err)
	}

	x := parsed.XPath[0]
	if x.Expression != "//p:item" || x.Filter != "intersect" || x.Namespaces["p"] != "urn:items" || x.Namespaces["xml"] != document.XMLNamespace || !x.Here.Same(doc.Root().Children()[0]) {
		t.Fatalf("expression context/identity lost: %+v", x)
	}

	draft := &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: transformxml.Namespace, Local: "Transform"}, Prefix: "ds", NS: []tree.Namespace{{Prefix: "ds", URI: transformxml.Namespace}}, Attrs: []tree.Attribute{{Name: document.Name{Local: "Algorithm"}, Value: reference.XPathFilter2}}}
	program := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: "//p:item", Filter: "intersect", Namespaces: map[string]string{"p": "urn:items"}}}}
	if err := transformxml.AppendParameters(t.Context(), draft, program); err != nil {
		t.Fatal(err)
	}

	if len(program.XPath[0].Namespaces) != 1 || len(draft.Children) != 1 || draft.Children[0].Parent != draft {
		t.Fatal("parameter append changed caller bindings or lost parent ownership")
	}

	if len(draft.Children[0].NS) != 2 || draft.Children[0].NS[0].Prefix != "p" || draft.Children[0].NS[1].Prefix != "xf" {
		t.Fatal("parameter namespace declarations are not deterministic")
	}

	destination := tree.FromNodes([]*tree.Node{draft}, tree.DefaultLimits())
	roundTrip, err := transformxml.Parse(t.Context(), destination, draft)
	if err != nil || roundTrip.XPath[0].Expression != x.Expression || roundTrip.XPath[0].Filter != x.Filter || roundTrip.XPath[0].Namespaces["p"] != x.Namespaces["p"] {
		t.Fatalf("round trip: %+v, %v", roundTrip, err)
	}
}

func TestCanonicalParametersAndInvalidStructure(t *testing.T) {
	const namespace = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	for _, tc := range []struct {
		name string
		xml  string
		want error
	}{
		{"exclusive prefixes", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="p #default"/></ds:Transform>`, nil},
		{"parameters on inclusive algorithm", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Canonical10 + `"><x/></ds:Transform>`, reference.ErrInput},
		{"nested prefix element", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="p"><x/></ec:InclusiveNamespaces></ds:Transform>`, reference.ErrInput},
		{"invalid inclusive prefix", `<ds:Transform ` + namespace + ` Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="xmlns"/></ds:Transform>`, reference.ErrInput},
		{"unexpected attribute", `<ds:Transform ` + namespace + ` Algorithm="` + reference.Base64 + `" extra="x"/>`, reference.ErrInput},
		{"processing instruction", `<ds:Transform ` + namespace + ` Algorithm="` + reference.Base64 + `"><?test x?></ds:Transform>`, reference.ErrInput},
		{"unexpected text", `<ds:Transform ` + namespace + ` Algorithm="` + reference.Base64 + `">x</ds:Transform>`, reference.ErrInput},
		{"wrong XPath namespace", `<ds:Transform ` + namespace + ` Algorithm="` + reference.XPath + `"><XPath>true()</XPath></ds:Transform>`, reference.ErrInput},
		{"missing algorithm", `<ds:Transform ` + namespace + `/>`, reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := document.Parse(t.Context(), []byte(tc.xml), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			got, err := transformxml.Parse(t.Context(), doc, tree.Root(doc))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %+v, %v; want %v", got, err, tc.want)
			}

			if tc.want == nil && (got.Algorithm != c14n.Exclusive || len(got.InclusivePrefixes) != 2 || got.InclusivePrefixes[0] != "p" || got.InclusivePrefixes[1] != "#default") {
				t.Fatal("inclusive prefix order/spelling lost:", got)
			}
		})
	}

	if _, err := transformxml.Parse(nil, nil, nil); !errors.Is(err, reference.ErrInput) {
		t.Fatal("nil context/node:", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := transformxml.Parse(ctx, nil, &tree.Node{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled parse:", err)
	}
}

func TestStylesheetNamespaceContext(t *testing.T) {
	input := []byte(`<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:p="urn:items" Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="p:item"/></xsl:stylesheet></ds:Transform>`)
	doc, err := document.Parse(t.Context(), input, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	before, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	program, err := transformxml.Parse(t.Context(), doc, tree.Root(doc))
	if err != nil {
		t.Fatal(err)
	}

	standalone, err := document.Parse(t.Context(), program.Stylesheet, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	if uri, ok := standalone.Root().Namespace("p"); !ok || uri != "urn:items" {
		t.Fatal("standalone stylesheet lost inherited namespaces")
	}

	after, err := doc.XML(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("extracting a stylesheet changed the original snapshot:", err)
	}
}

func newTransformDraft(algorithm string) *tree.Node {
	return &tree.Node{
		Kind: tree.ElementNode, Name: document.Name{Space: transformxml.Namespace, Local: "Transform"},
		Prefix: "ds", NS: []tree.Namespace{{Prefix: "ds", URI: transformxml.Namespace}},
		Attrs: []tree.Attribute{{Name: document.Name{Local: "Algorithm"}, Value: algorithm}},
	}
}

func TestAppendParametersCanonicalPrefixes(t *testing.T) {
	t.Parallel()
	for _, algorithm := range []string{c14n.Exclusive, c14n.ExclusiveWithComments} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			input := reference.Transform{Algorithm: algorithm, InclusivePrefixes: []string{"z", "#default", "a"}}
			draft := newTransformDraft(algorithm)
			if err := transformxml.AppendParameters(t.Context(), draft, input); err != nil {
				t.Fatal(err)
			}
			if len(draft.Children) != 1 {
				t.Fatalf("number of parameters = %d, want 1", len(draft.Children))
			}
			child := draft.Children[0]
			wantName := document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}
			wantAttrs := []tree.Attribute{{Name: document.Name{Local: "PrefixList"}, Value: "z #default a"}}
			if child.Name != wantName || child.Parent != draft || !slices.Equal(child.Attrs, wantAttrs) {
				t.Fatalf("parameter name = %+v, parent ownership = %t, attributes = %+v", child.Name, child.Parent == draft, child.Attrs)
			}
			roundTrip, err := transformxml.ParseCanonical(draft, "Transform")
			if err != nil || roundTrip.Algorithm != algorithm || !slices.Equal(roundTrip.InclusivePrefixes, input.InclusivePrefixes) {
				t.Fatalf("ParseCanonical = %+v, %v, want algorithm %q and prefixes %v", roundTrip, err, algorithm, input.InclusivePrefixes)
			}
		})
	}
}

func TestCancelledCanonicalParametersLeaveDraftUnchanged(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	input := reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"p"}}
	draft := newTransformDraft(input.Algorithm)
	if err := transformxml.AppendParameters(ctx, draft, input); !errors.Is(err, context.Canceled) || len(draft.Children) != 0 {
		t.Fatalf("cancelled AppendParameters appended %d children and returned %v", len(draft.Children), err)
	}
}

func TestAppendCanonicalizationMethodPrefixes(t *testing.T) {
	t.Parallel()

	input := reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"p", "#default"}}
	draft := newTransformDraft(input.Algorithm)
	draft.Name.Local = "CanonicalizationMethod"
	if err := transformxml.AppendParameters(t.Context(), draft, input); err != nil {
		t.Fatal(err)
	}
	parsed, err := transformxml.ParseCanonical(draft, "CanonicalizationMethod")
	if err != nil || parsed.Algorithm != input.Algorithm || !slices.Equal(parsed.InclusivePrefixes, input.InclusivePrefixes) {
		t.Fatalf("parsed %+v with %v, want %+v", parsed, err, input)
	}
}

func TestAppendParametersValidatesAlgorithmContract(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input reference.Transform
		want  error
	}{
		{"inclusive_canonicalization_without_parameters", reference.Transform{Algorithm: c14n.Canonical11}, nil},
		{"base64_without_parameters", reference.Transform{Algorithm: reference.Base64}, nil},
		{"enveloped_without_parameters", reference.Transform{Algorithm: reference.EnvelopedSignature}, nil},
		{"unsupported_algorithm", reference.Transform{Algorithm: "urn:example:unknown"}, reference.ErrUnsupported},
		{"inclusive_canonicalization_cannot_declare_prefixes", reference.Transform{Algorithm: c14n.Canonical11, InclusivePrefixes: []string{"p"}}, reference.ErrInput},
		{"forbidden_inclusive_prefix", reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"xmlns"}}, reference.ErrInput},
		{"multiple_tokens_in_one_prefix", reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"p q"}}, reference.ErrInput},
		{"base64_cannot_carry_xpath", reference.Transform{Algorithm: reference.Base64, XPath: []reference.XPathExpression{{Expression: "true()"}}}, reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			draft := newTransformDraft(tc.input.Algorithm)
			err := transformxml.AppendParameters(t.Context(), draft, tc.input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("AppendParameters(%+v) error = %v, want %v", tc.input, err, tc.want)
			}
			if len(draft.Children) != 0 {
				t.Fatalf("unexpectedly appended %d children", len(draft.Children))
			}
		})
	}
}

func TestAppendProgramXPathBindings(t *testing.T) {
	t.Parallel()
	input := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{
		Expression: `self::p:item and @xml:lang = "en"`,
		Namespaces: map[string]string{"p": "urn:item", "": "urn:default", "xml": document.XMLNamespace},
	}}}
	draft := newTransformDraft(input.Algorithm)
	if err := transformxml.AppendProgram(t.Context(), draft, input); err != nil {
		t.Fatal(err)
	}
	if len(draft.Children) != 1 || len(draft.Children[0].Children) != 1 {
		t.Fatalf("unexpected XPath subtree: %+v", draft.Children)
	}
	child := draft.Children[0]
	wantNS := []tree.Namespace{
		{URI: "urn:default"},
		{Prefix: "ds", URI: transformxml.Namespace},
		{Prefix: "p", URI: "urn:item"},
	}
	if !slices.Equal(child.NS, wantNS) || len(child.Attrs) != 0 || child.Children[0].Data != input.XPath[0].Expression {
		t.Fatalf("XPath namespaces = %v, attributes = %v, expression = %q", child.NS, child.Attrs, child.Children[0].Data)
	}
	if want := map[string]string{"p": "urn:item", "": "urn:default", "xml": document.XMLNamespace}; !reflect.DeepEqual(input.XPath[0].Namespaces, want) {
		t.Fatalf("input namespace map changed to %v", input.XPath[0].Namespaces)
	}
}

func TestAppendProgramRejectsInvalidXPathBeforeAppending(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, algorithm, prefix, filter string
		want                            error
	}{
		{"xpath_reserved_prefix", reference.XPath, "ds", "", reference.ErrPolicy},
		{"filter2_reserved_prefix", reference.XPathFilter2, "xf", "intersect", reference.ErrPolicy},
		{"invalid_filter_operation", reference.XPathFilter2, "p", "replace", reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := reference.Transform{Algorithm: tc.algorithm, XPath: []reference.XPathExpression{{
				Expression: "//item", Filter: tc.filter, Namespaces: map[string]string{tc.prefix: "urn:item"},
			}}}
			draft := newTransformDraft(tc.algorithm)
			err := transformxml.AppendProgram(t.Context(), draft, input)
			if !errors.Is(err, tc.want) || len(draft.Children) != 0 {
				t.Fatalf("AppendProgram error = %v and appended %d children, want %v and no children", err, len(draft.Children), tc.want)
			}
		})
	}

	t.Run("second_filter_has_conflicting_prefix", func(t *testing.T) {
		t.Parallel()

		input := reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{
			{Expression: "//first", Filter: "intersect"},
			{Expression: "//second", Filter: "union", Namespaces: map[string]string{"xf": "urn:items"}},
		}}

		draft := newTransformDraft(input.Algorithm)
		if err := transformxml.AppendProgram(t.Context(), draft, input); !errors.Is(err, reference.ErrPolicy) {
			t.Fatalf("AppendProgram = %v; want ErrPolicy", err)
		}

		if len(draft.Children) != 0 {
			t.Fatal("invalid program partially changed the transform")
		}
	})

	t.Run("cancelled_xpath", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		input := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "true()"}}}
		draft := newTransformDraft(input.Algorithm)
		if err := transformxml.AppendProgram(ctx, draft, input); !errors.Is(err, context.Canceled) {
			t.Fatalf("AppendProgram = %v; want context.Canceled", err)
		}

		if len(draft.Children) != 0 {
			t.Fatal("cancelled program changed the transform")
		}
	})
}

func TestAppendProgramStylesheet(t *testing.T) {
	t.Parallel()
	const source = `<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:item" version="1.0"><xsl:template match="p:item"><result/></xsl:template></xsl:transform>`
	input := reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(source)}
	draft := newTransformDraft(input.Algorithm)
	if err := transformxml.AppendProgram(t.Context(), draft, input); err != nil {
		t.Fatal(err)
	}
	if len(draft.Children) != 1 || draft.Children[0].Parent != draft {
		t.Fatal("stylesheet root was not attached to the transform")
	}
	doc := tree.FromNodes([]*tree.Node{draft}, tree.DefaultLimits())
	parsed, err := transformxml.ParseProgram(t.Context(), draft, doc)
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := document.Parse(t.Context(), parsed.Stylesheet, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := stylesheet.Root()
	wantName := document.Name{Space: "http://www.w3.org/1999/XSL/Transform", Local: "transform"}
	if uri, ok := root.Namespace("p"); root.Name() != wantName || !ok || uri != "urn:item" {
		t.Fatalf("stylesheet root = %+v, p = %q (%t)", root.Name(), uri, ok)
	}
	template := root.Children()
	if len(template) != 1 {
		t.Fatalf("stylesheet has %d children, want one template", len(template))
	}
	if value, present := template[0].Attribute(document.Name{Local: "match"}); !present || value != "p:item" {
		t.Fatalf("match = %q (%t), want p:item", value, present)
	}

	t.Run("cancelled_stylesheet_parse", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		draft := newTransformDraft(input.Algorithm)
		if err := transformxml.AppendProgram(ctx, draft, input); !errors.Is(err, context.Canceled) || len(draft.Children) != 0 {
			t.Fatalf("cancelled AppendProgram appended %d children and returned %v", len(draft.Children), err)
		}
	})
}

func TestParseCanonicalPrefixLimit(t *testing.T) {
	t.Parallel()
	const maximumPrefixes = 128
	const start = `<ds:CanonicalizationMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="` + c14n.Exclusive + `"><ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `" PrefixList="`
	const end = `"/></ds:CanonicalizationMethod>`
	prefixes := append(strings.Fields(strings.Repeat("p ", maximumPrefixes-1)), "#default")
	for _, tc := range []struct {
		name, prefixList string
		want             error
	}{
		{"exact_limit", strings.Join(prefixes, "&#x9;&#xA;"), nil},
		{"exceeds_limit", strings.Join(prefixes, " ") + " extra", reference.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc, err := document.Parse(t.Context(), []byte(start+tc.prefixList+end), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			got, err := transformxml.ParseCanonical(tree.Root(doc), "CanonicalizationMethod")
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParseCanonical error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && (got.Algorithm != c14n.Exclusive || !slices.Equal(got.InclusivePrefixes, prefixes)) {
				t.Fatalf("ParseCanonical returned %q and %d prefixes, want exclusive canonicalization and %d ordered prefixes", got.Algorithm, len(got.InclusivePrefixes), len(prefixes))
			}
		})
	}
}

func TestParseCanonicalValidatesMethodAndPrefixList(t *testing.T) {
	t.Parallel()

	const method = "CanonicalizationMethod"
	const ds = ` xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	const exclusive = ` Algorithm="` + c14n.Exclusive + `"`
	const inclusiveNamespaces = `<ec:InclusiveNamespaces xmlns:ec="` + c14n.Exclusive + `"`
	for _, tc := range []struct {
		name, source string
		wantErr      error
	}{
		{"unexpected_method_name", `<ds:Transform` + ds + exclusive + `/>`, reference.ErrInput},
		{"missing_algorithm", `<ds:CanonicalizationMethod` + ds + `/>`, reference.ErrInput},
		{"noncanonical_algorithm", `<ds:CanonicalizationMethod` + ds + ` Algorithm="` + reference.Base64 + `"/>`, reference.ErrUnsupported},
		{"without_parameters", `<ds:CanonicalizationMethod` + ds + exclusive + `/>`, nil},
		{"unknown_parameter", `<ds:CanonicalizationMethod` + ds + exclusive + `><other/></ds:CanonicalizationMethod>`, reference.ErrInput},
		{"missing_prefix_list", `<ds:CanonicalizationMethod` + ds + exclusive + `>` + inclusiveNamespaces + `/></ds:CanonicalizationMethod>`, reference.ErrInput},
		{"unexpected_parameter_attribute", `<ds:CanonicalizationMethod` + ds + exclusive + `>` + inclusiveNamespaces + ` PrefixList="p" Extra="1"/></ds:CanonicalizationMethod>`, reference.ErrInput},
		{"unexpected_parameter_text", `<ds:CanonicalizationMethod` + ds + exclusive + `>` + inclusiveNamespaces + ` PrefixList="p">text</ec:InclusiveNamespaces></ds:CanonicalizationMethod>`, reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := document.Parse(t.Context(), []byte(tc.source), document.DefaultLimits())
			if err != nil {
				t.Fatalf("parse XML fixture: %v", err)
			}
			got, err := transformxml.ParseCanonical(tree.Root(doc), method)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseCanonical error = %v, want %v", err, tc.wantErr)
			}
			wantAlgorithm := c14n.Exclusive
			if tc.wantErr != nil {
				wantAlgorithm = ""
			}
			if got.Algorithm != wantAlgorithm || len(got.InclusivePrefixes) != 0 {
				t.Errorf("ParseCanonical = (%q, %q), want %q and no prefixes", got.Algorithm, got.InclusivePrefixes, wantAlgorithm)
			}
		})
	}
}

func TestParseParameterlessTransform(t *testing.T) {
	t.Parallel()

	const start = `<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="` + reference.Base64 + `">`
	const end = `</ds:Transform>`
	for _, tc := range []struct {
		name, content string
		wantAlgorithm string
		wantErr       error
	}{
		{"empty", "", reference.Base64, nil},
		{"whitespace_and_comment", " \n<!-- base64 -->\t", reference.Base64, nil},
		{"child_element", `<parameter/>`, "", reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := document.Parse(t.Context(), []byte(start+tc.content+end), document.DefaultLimits())
			if err != nil {
				t.Fatalf("parse XML fixture: %v", err)
			}
			got, err := transformxml.Parse(t.Context(), doc, tree.Root(doc))
			if !errors.Is(err, tc.wantErr) || got.Algorithm != tc.wantAlgorithm {
				t.Errorf("Parse = (algorithm %q, %v), want (%q, %v)", got.Algorithm, err, tc.wantAlgorithm, tc.wantErr)
			}
			if len(got.InclusivePrefixes)+len(got.XPath)+len(got.Stylesheet) != 0 {
				t.Errorf("Parse returned unexpected parameters: %+v", got)
			}
		})
	}
}

func TestParseProgramRejectsInvalidParameterShape(t *testing.T) {
	t.Parallel()
	const dsPrefix = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	const expressionBytes = 16 << 10
	for _, tc := range []struct {
		name, algorithm, body string
		want                  error
	}{
		{"missing_algorithm", "", `<ds:XPath>true()</ds:XPath>`, reference.ErrInput},
		{"xpath_cannot_use_filter", reference.XPath, `<ds:XPath Filter="intersect">true()</ds:XPath>`, reference.ErrInput},
		{"xpath_must_be_text", reference.XPath, `<ds:XPath><test/></ds:XPath>`, reference.ErrInput},
		{"xpath_requires_one_parameter", reference.XPath, `<ds:XPath>true()</ds:XPath><ds:XPath>false()</ds:XPath>`, reference.ErrInput},
		{"xpath_limit_combines_split_text", reference.XPath, `<ds:XPath>` + strings.Repeat(" ", expressionBytes) + `<!-- boundary -->x</ds:XPath>`, reference.ErrLimit},
		{"xslt_requires_one_stylesheet", reference.XSLT, "", reference.ErrInput},
		{"xslt_requires_stylesheet_element", reference.XSLT, `<test/>`, reference.ErrInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attribute := ""
			if tc.algorithm != "" {
				attribute = ` Algorithm="` + tc.algorithm + `"`
			}
			source := `<ds:Transform ` + dsPrefix + attribute + `>` + tc.body + `</ds:Transform>`
			doc, err := document.Parse(t.Context(), []byte(source), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := transformxml.ParseProgram(t.Context(), tree.Root(doc), doc); !errors.Is(err, tc.want) {
				t.Fatalf("ParseProgram error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseProgramPropagatesCancellation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, algorithm, body string }{
		{"xpath", reference.XPath, `<ds:XPath>true()</ds:XPath>`},
		{"xslt", reference.XSLT, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			source := `<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="` + tc.algorithm + `">` + tc.body + `</ds:Transform>`
			doc, err := document.Parse(t.Context(), []byte(source), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			got, err := transformxml.ParseProgram(ctx, tree.Root(doc), doc)
			if !errors.Is(err, context.Canceled) || len(got.XPath) != 0 || len(got.Stylesheet) != 0 {
				t.Fatalf("cancelled ParseProgram = %+v, %v; want no decoded parameters and context.Canceled", got, err)
			}
		})
	}
}
