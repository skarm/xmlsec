package xpath //nolint:testpackage // Exercises document and collection functions through the evaluator.

import (
	"context"
	"errors"
	"io"
	"io/fs"
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
