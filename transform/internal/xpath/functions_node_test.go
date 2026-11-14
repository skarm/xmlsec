package xpath //nolint:testpackage // Exercises document and collection functions through the evaluator.

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestDocumentFunctionsShareSnapshotsWithinAnEvaluation(t *testing.T) {
	t.Parallel()
	const base = "https://example.test/catalog/query.xq"
	const resource = "https://example.test/catalog/data.xml"
	const expression = `if (doc-available('data.xml')) then
		let $a := doc('data.xml'), $b := doc('https://example.test/catalog/data.xml')
		return ($a is $b, string(document-uri($b)), string(base-uri($b/r/n)), string($b/r/n))
		else false()`
	compiled, err := NewCompiler().Language(31, nil).Compile(expression)
	if err != nil {
		t.Fatal(err)
	}
	var opened []string
	var readers []*documentTestReader
	resolver := documentResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		opened = append(opened, uri)
		if uri != resource {
			return nil, fs.ErrNotExist
		}
		body := `<r xml:base="entries/"><n>first</n></r>`
		if len(readers) > 0 {
			body = `<r xml:base="entries/"><n>second</n></r>`
		}
		reader := &documentTestReader{Reader: strings.NewReader(body)}
		readers = append(readers, reader)
		return reader, nil
	})
	evaluator := NewEvaluator(DefaultEvaluatorOptions).BaseURI(base).URIResolver(resolver)
	for _, label := range []string{"first", "second"} {
		result, err := evaluator.Evaluate(t.Context(), compiled, nil)
		if err != nil {
			t.Fatalf("Evaluate (%s): %v", label, err)
		}
		assertAtomicSequence(t, result.Sequence(), []xdm.AtomicValue{
			{TypeName: xdm.TypeBoolean, Value: true},
			{TypeName: xdm.TypeString, Value: resource},
			{TypeName: xdm.TypeString, Value: "https://example.test/catalog/entries/"},
			{TypeName: xdm.TypeString, Value: label},
		})
	}
	if !slices.Equal(opened, []string{resource, resource}) {
		t.Errorf("resolved URIs = %q, want one request to %q per evaluation", opened, resource)
	}
	for i, reader := range readers {
		if reader.closed != 1 {
			t.Errorf("reader %d closed %d times, want once", i, reader.closed)
		}
	}
}

func TestDocAvailableAndDocDistinguishResourceFailure(t *testing.T) {
	t.Parallel()
	closeFailure := errors.New("close fixture failed")
	for _, tc := range []struct {
		name string
		body string
		err  error
	}{
		{name: "not_found", err: fs.ErrNotExist},
		{name: "malformed_document", body: `<r>`},
		{name: "close_failure", body: `<r/>`, err: closeFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const uri = "urn:example:document"
			compiled, err := NewCompiler().Language(31, nil).Compile(`if (doc-available('urn:example:document')) then 'unexpected' else doc('urn:example:document')`)
			if err != nil {
				t.Fatal(err)
			}
			reader := &documentTestReader{Reader: strings.NewReader(tc.body), err: tc.err}
			calls := 0
			evaluator := NewEvaluator(DefaultEvaluatorOptions).URIResolver(documentResolverFunc(func(_ context.Context, got string) (io.ReadCloser, error) {
				calls++
				if got != uri {
					t.Errorf("resolved URI = %q, want %q", got, uri)
				}
				if tc.body == "" {
					return nil, tc.err
				}
				return reader, nil
			}))
			result, err := evaluator.Evaluate(t.Context(), compiled, nil)
			if result != nil || !errors.Is(err, &xdm.Error{Code: "FODC0002"}) || (tc.err != nil && !errors.Is(err, tc.err)) {
				t.Errorf("Evaluate = %v, %v, want no result and FODC0002 (cause %v)", result, err, tc.err)
			}
			wantCloses := 0
			if tc.body != "" {
				wantCloses = 1
			}
			if calls != 1 || reader.closed != wantCloses {
				t.Errorf("resolver calls=%d, closes=%d, want 1 and %d", calls, reader.closed, wantCloses)
			}
		})
	}
}

type nodeCollectionResolver struct {
	collection func(string) (xdm.Sequence, error)
	uris       func(string) ([]string, error)
}

func (r nodeCollectionResolver) ResolveCollection(_ context.Context, uri string) (xdm.Sequence, error) {
	return r.collection(uri)
}

func (r nodeCollectionResolver) ResolveURICollection(_ context.Context, uri string) ([]string, error) {
	return r.uris(uri)
}

func TestCollectionFunctionsKeepMemberIdentityAndOrder(t *testing.T) {
	t.Parallel()
	const base = "https://example.test/catalog/query.xq"
	const collectionURI = "https://example.test/catalog/items"
	const firstURI = "https://example.test/catalog/first.xml"
	const secondURI = "https://example.test/catalog/second.xml"
	first, err := (xdm.ParseOptions{}).ParseReader(t.Context(), strings.NewReader(`<item>first</item>`))
	if err != nil {
		t.Fatal(err)
	}
	first.SetURL(firstURI)
	second, err := (xdm.ParseOptions{}).ParseReader(t.Context(), strings.NewReader(`<item>second</item>`))
	if err != nil {
		t.Fatal(err)
	}
	second.SetURL(secondURI)
	var collectionCalls, uriCalls []string
	resolver := nodeCollectionResolver{
		collection: func(uri string) (xdm.Sequence, error) {
			collectionCalls = append(collectionCalls, uri)
			return xdm.ItemSlice{xdm.NodeItem{Node: second}, xdm.NodeItem{Node: first}}, nil
		},
		uris: func(uri string) ([]string, error) {
			uriCalls = append(uriCalls, uri)
			return []string{secondURI, firstURI}, nil
		},
	}
	const expression = `let $items := collection('items'), $again := collection('items'),
		$uris := uri-collection('items'), $more := uri-collection('items')
		return ($items[1] is $again[1], $items[2] is doc('first.xml'),
			$items ! string(item), $uris, $more)`
	compiled, err := NewCompiler().Language(31, nil).Compile(expression)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := NewEvaluator(DefaultEvaluatorOptions).BaseURI(base).CollectionResolver(resolver)
	result, err := evaluator.Evaluate(t.Context(), compiled, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertAtomicSequence(t, result.Sequence(), []xdm.AtomicValue{
		{TypeName: xdm.TypeBoolean, Value: true},
		{TypeName: xdm.TypeBoolean, Value: true},
		{TypeName: xdm.TypeString, Value: "second"},
		{TypeName: xdm.TypeString, Value: "first"},
		{TypeName: xdm.TypeAnyURI, Value: secondURI},
		{TypeName: xdm.TypeAnyURI, Value: firstURI},
		{TypeName: xdm.TypeAnyURI, Value: secondURI},
		{TypeName: xdm.TypeAnyURI, Value: firstURI},
	})
	if !slices.Equal(collectionCalls, []string{collectionURI}) || !slices.Equal(uriCalls, []string{collectionURI}) {
		t.Errorf("collection and URI calls = %q and %q, want one %q each", collectionCalls, uriCalls, collectionURI)
	}
}

func TestNodeNavigationFunctionsASTAndVM(t *testing.T) {
	t.Parallel()
	const doc = `let $d := parse-xml('<r xmlns:p="urn:sample" xml:lang="en-GB"><p:a/><a p:k="1">x<!--one--><?a v?><?b v?><?a w?>y<!--two--></a><a xml:lang="fr"/><a/></r>') return `
	assertFunctionResults(t, []functionResultCase{
		{"path positions count matching expanded names", doc + `(path($d),path($d/r/a[2]),path($d/r/a[1]/@*))`, `/|/Q{}r[1]/Q{}a[2]|/Q{}r[1]/Q{}a[1]/@Q{urn:sample}k`},
		{"path positions distinguish child node kinds", doc + `(path($d/r/a[1]/text()[2]),path($d/r/a[1]/comment()[2]),path($d/r/a[1]/processing-instruction('a')[2]))`, `/Q{}r[1]/Q{}a[1]/text()[2]|/Q{}r[1]/Q{}a[1]/comment()[2]|/Q{}r[1]/Q{}a[1]/processing-instruction(a)[2]`},
		{"namespace functions respect inherited bindings", doc + `(sort(in-scope-prefixes($d/r/a[1])),namespace-uri-for-prefix('p',$d/r/a[1]),count(namespace-uri-for-prefix('absent',$d/r/a[1])))`, `p|xml|urn:sample|0`},
		{"language matching inherits and respects overrides", doc + `(lang('EN',$d/r/a[1]),lang('en-US',$d/r/a[1]),lang('en',$d/r/a[2]),lang('fr',$d/r/a[2]))`, `true|false|false|true`},
		{"inner and outer selection remove duplicates and order results", doc + `(innermost(($d/r/a[2],$d/r,$d/r/a[1],$d/r/a[2])) ! path(.),outermost(($d/r/a[1],$d/r,$d/r)) ! path(.))`, `/Q{}r[1]/Q{}a[1]|/Q{}r[1]/Q{}a[2]|/Q{}r[1]`},
		{"identity and empty node arguments", doc + `(root($d/r/a[1]) is $d,has-children($d/r),has-children($d/r/a[2]),count(path(())),count(node-name($d/r/a[1]/text()[1])))`, `true|true|false|0|0`},
		{"ID search returns document order regardless of token order", `let $d := parse-xml('<r><a xml:id="a"/><b xml:id="b"/></r>') return id(('b a','a','missing'),$d) ! local-name(.)`, `a|b`},
	})
}

type dataContentSchema struct{ castContractSchema }

func (dataContentSchema) SchemaTypeContentKind(name string) (ContentTypeKind, bool) {
	switch name {
	case "Q{urn:test}Empty":
		return ContentTypeEmpty, true
	case "Q{urn:test}ElementOnly":
		return ContentTypeElementOnly, true
	default:
		return ContentTypeSimple, false
	}
}

func TestFnDataTypedValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source string
		want         []xdm.AtomicValue
		code         string
	}{
		{"nested_arrays_skip_nilled_and_empty_elements", `data([r/nilled, [1,r/empty,2], r/count])`, []xdm.AtomicValue{
			{TypeName: xdm.TypeInteger, Value: int64(1)},
			{TypeName: xdm.TypeInteger, Value: int64(2)},
			{TypeName: xdm.TypeInteger, Value: int64(7)},
		}, ""},
		{"uses_context_node_annotation", `r/count ! data()`, []xdm.AtomicValue{{TypeName: xdm.TypeInteger, Value: int64(7)}}, ""},
		{"atomizes_attribute_and_untyped_element", `data((r/@name, r/complex/v))`, []xdm.AtomicValue{
			{TypeName: xdm.TypeUntypedAtomic, Value: "count"},
			{TypeName: xdm.TypeUntypedAtomic, Value: "kept"},
		}, ""},
		{"element_only_content_has_no_typed_value", `data(r/complex)`, nil, "FOTY0012"},
		{"first_error_comes_from_map_inside_array", `data([map{}, r/complex])`, nil, "FOTY0013"},
		{"first_error_comes_from_element_inside_array", `data([r/complex, map{}])`, nil, "FOTY0012"},
		{"empty_input_has_no_atoms", `data(())`, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const fixture = `<r name="count"><nilled/><empty/><complex><v>kept</v></complex><count>7</count></r>`
			doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), fixture)
			if err != nil {
				t.Fatal(err)
			}
			children := slices.Collect(xdm.Children(doc.DocumentElement()))
			if len(children) != 4 {
				t.Fatalf("fixture has %d children, want 4", len(children))
			}
			nilled, empty, elementOnly, count := children[0], children[1], children[2], children[3]
			evaluator := NewEvaluator(DefaultEvaluatorOptions).
				SchemaDeclarations(dataContentSchema{}).
				NilledElements(map[xdm.Node]struct{}{nilled: {}}).
				TypeAnnotations(map[xdm.Node]string{
					nilled: "Q{urn:test}ElementOnly", empty: "Q{urn:test}Empty",
					elementOnly: "Q{urn:test}ElementOnly", count: xdm.TypeInteger,
				})
			expr, err := NewCompiler().Language(31, nil).Compile(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := evaluator.Evaluate(t.Context(), expr, doc)
			if tc.code != "" {
				if got != nil || !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Fatalf("%s returned %v, %v; want no result and %s", tc.source, got, err, tc.code)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.source, err)
			}
			seq := got.Sequence()
			if xdm.SequenceLen(seq) != len(tc.want) {
				t.Fatalf("%s returned %d items, want %d", tc.source, xdm.SequenceLen(seq), len(tc.want))
			}
			for index, want := range tc.want {
				item, ok := seq.Get(index).(xdm.AtomicValue)
				if !ok || item.TypeName != want.TypeName {
					t.Errorf("%s item %d = %v, want %v", tc.source, index+1, seq.Get(index), want)
					continue
				}
				equal := item.Value == want.Value
				if integer, ok := want.Value.(int64); ok {
					value, fits := item.Int64Val()
					equal = fits && value == integer
				}
				if !equal {
					t.Errorf("%s item %d = %v, want %v", tc.source, index+1, item, want)
				}
			}
		})
	}
}

func TestFnNilledDistinguishesSchemaPropertyFromAttribute(t *testing.T) {
	t.Parallel()
	const fixture = `<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><confirmed xsi:nil="true"/><unvalidated xsi:nil="true"/></r>`
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	expression, err := NewCompiler().Language(31, nil).Compile(`(nilled(r/confirmed), r/unvalidated ! nilled(), count(nilled(r/unvalidated/@*)), count(nilled(())))`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mark bool
	}{
		{"validated_nilled_element", true},
		{"unvalidated_document", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evaluator := NewEvaluator(DefaultEvaluatorOptions)
			if tc.mark {
				evaluator = evaluator.NilledElements(map[xdm.Node]struct{}{doc.DocumentElement().FirstChild(): {}})
			}
			got, err := evaluator.Evaluate(t.Context(), expression, doc)
			if err != nil {
				t.Fatal(err)
			}
			assertAtomicSequence(t, got.Sequence(), []xdm.AtomicValue{
				{TypeName: xdm.TypeBoolean, Value: tc.mark},
				{TypeName: xdm.TypeBoolean, Value: false},
				{TypeName: xdm.TypeInteger, Value: int64(0)},
				{TypeName: xdm.TypeInteger, Value: int64(0)},
			})
		})
	}
}

func TestFnNumber(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, query string
		want        float64
		code        string
	}{
		{"absent_context", `number()`, 0, "XPDY0002"},
		{"empty_sequence", `number(())`, math.NaN(), ""},
		{"invalid_lexical_number", `number('two')`, math.NaN(), ""},
		{"boolean_conversion", `number(true())`, 1, ""},
		{"node_context", `parse-xml('<n> 12.5 </n>')/n ! number()`, 12.5, ""},
		{"explicit_attribute", `number(parse-xml('<n x=" 2.5 "/>')/n/@x)`, 2.5, ""},
		{"infinity", `number('INF')`, math.Inf(1), ""},
		{"cannot_atomize_a_map", `number(map{})`, 0, "FOTY0013"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, tc.query, mode)
				if tc.code != "" {
					if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: tc.code}) {
						t.Fatalf("%s returned %v, %v; want no result and %s", tc.query, seq, err, tc.code)
					}
					return
				}
				if err != nil || xdm.SequenceLen(seq) != 1 {
					t.Fatalf("%s returned %v, %v; want one xs:double", tc.query, seq, err)
				}
				item, ok := seq.Get(0).(xdm.AtomicValue)
				if !ok || item.TypeName != xdm.TypeDouble {
					t.Fatalf("%s returned %v; want xs:double", tc.query, seq.Get(0))
				}
				got := item.DoubleVal()
				if got != tc.want && !(math.IsNaN(got) && math.IsNaN(tc.want)) {
					t.Errorf("%s = %g, want %g", tc.query, got, tc.want)
				}
			})
		}
	}
}

func TestIDLookupTypedNodes(t *testing.T) {
	t.Parallel()
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<r><entry><code>one</code></entry><other key="two"/><link refs="two one"/><plain refs="two"/></r>`)
	if err != nil {
		t.Fatal(err)
	}
	children := slices.Collect(xdm.Children(doc.DocumentElement()))
	if len(children) != 4 {
		t.Fatalf("fixture has %d child nodes; want 4", len(children))
	}
	entry, other, link := children[0], children[1], children[2]
	otherElement, otherOK := other.(*xdm.Element)
	linkElement, linkOK := link.(*xdm.Element)
	if !otherOK || !linkOK {
		t.Fatalf("fixture has child nodes %T and %T; want elements", other, link)
	}
	code := entry.FirstChild()
	keys, references := otherElement.Attributes(), linkElement.Attributes()
	if code == nil || len(keys) != 1 || len(references) != 1 {
		t.Fatal("fixture lacks the ID or IDREF nodes")
	}
	key, refs := keys[0], references[0]
	foreign, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<foreign>one</foreign>`)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := NewEvaluator(DefaultEvaluatorOptions).TypeAnnotations(map[xdm.Node]string{
		code: xdm.TypeID, key: xdm.TypeID, refs: "xs:IDREFS", foreign.DocumentElement(): xdm.TypeID,
	})

	for _, tc := range []struct {
		name, expr string
		want       []xdm.Node
	}{
		{"id selects the annotated element and the attribute owner in document order", `id(('two one', 'one', 'missing', '1invalid'), /r/other)`, []xdm.Node{code, other}},
		{"element-with-id returns the annotated element's parent", `element-with-id(('two', 'one'), /r)`, []xdm.Node{entry, other}},
		{"idref matches list members without duplicates", `idref(('two', 'one', 'two'), /r)`, []xdm.Node{refs}},
		{"idref input strings are individual tokens", `idref('two one', /r)`, nil},
		{"empty id input", `id((), /r)`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			compiled, err := NewCompiler().Language(31, nil).Compile(tc.expr)
			if err != nil {
				t.Fatal(err)
			}
			result, err := evaluator.Evaluate(t.Context(), compiled, doc)
			if err != nil {
				t.Fatal(err)
			}
			seq := result.Sequence()
			if xdm.SequenceLen(seq) != len(tc.want) {
				t.Fatalf("%s returned %d nodes; want %d", tc.expr, xdm.SequenceLen(seq), len(tc.want))
			}
			for i, want := range tc.want {
				got, ok := seq.Get(i).(xdm.NodeItem)
				if !ok || got.Node != want {
					t.Errorf("%s item %d = %v; want node %s in the fixture document", tc.expr, i+1, seq.Get(i), want.Name())
				}
			}
		})
	}
}
