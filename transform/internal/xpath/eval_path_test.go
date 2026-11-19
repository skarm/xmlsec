package xpath //nolint:testpackage // Checks schema-aware node tests and the typed values they expose.

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type pathTestSchema struct {
	SchemaDeclarations
}

func (pathTestSchema) LookupSchemaElement(local, ns string) (string, bool) {
	if local == "entry" && ns == "urn:catalog" {
		return xdm.TypeInteger, true
	}
	return "", false
}

func (pathTestSchema) LookupSchemaAttribute(local, ns string) (string, bool) {
	if local == "rank" && ns == "" {
		return xdm.TypeInteger, true
	}
	return "", false
}

func (pathTestSchema) LookupSchemaType(local, ns string) (string, bool) {
	if local == "positive" && ns == "urn:catalog" {
		return xdm.TypeInteger, true
	}
	return "", false
}

func (pathTestSchema) IsSubtypeOf(name, base string) bool {
	return name == base || name == "Q{urn:catalog}positive" && base == xdm.TypeInteger
}

func (pathTestSchema) IsSubstitutionGroupMember(member, memberNS, head, headNS string) bool {
	return member == "special" && memberNS == "urn:catalog" && head == "entry" && headNS == "urn:catalog"
}

func (pathTestSchema) ListItemType(name string) (string, bool) {
	switch name {
	case "Q{urn:catalog}numbers":
		return xdm.TypeInteger, true
	case "Q{urn:catalog}labels":
		return "Q{urn:catalog}label", true
	default:
		return "", false
	}
}

func (pathTestSchema) UnionMemberTypes(name string) []string {
	switch name {
	case "Q{urn:catalog}value":
		return []string{"Q{urn:catalog}positive", "Q{urn:catalog}label"}
	case "Q{urn:catalog}label":
		return []string{xdm.TypeQName, xdm.TypeString}
	case "Q{urn:catalog}numbers-or-label":
		return []string{"Q{urn:catalog}numbers", xdm.TypeString}
	default:
		return nil
	}
}

func (pathTestSchema) ValidateCastWithNS(_ context.Context, value, name string, namespaces map[string]string) error {
	if name == "Q{urn:catalog}positive" && value == "-2" {
		return errors.New("value must be positive")
	}
	if name == xdm.TypeQName {
		if value == "-2" {
			return errors.New("invalid QName")
		}
		if value == "p:title" && namespaces["p"] != "urn:title" {
			return errors.New("incorrect namespace for title")
		}
	}
	return nil
}

func TestSchemaPathMatchesDeclarationsAndSubstitutionGroups(t *testing.T) {
	t.Parallel()

	const fixture = `<catalog xmlns:c="urn:catalog" rank="7" c:rank="8"><c:entry id="declared"/><c:special id="substitute"/><c:special id="untyped"/><c:other id="same-type"/><c:entry id="wrong-type"/><entry id="no-namespace"/></catalog>`
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	root := doc.DocumentElement()
	children := slices.Collect(xdm.Children(root))
	attrs := root.Attributes()
	if len(children) != 6 || len(attrs) != 2 {
		t.Fatalf("fixture children = %d, attributes = %d; want 6 and 2", len(children), len(attrs))
	}
	annotations := map[xdm.Node]string{
		children[0]: "Q{urn:catalog}positive", children[1]: xdm.TypeInteger,
		children[3]: xdm.TypeInteger, children[4]: xdm.TypeString,
		attrs[0]: "Q{urn:catalog}positive", attrs[1]: xdm.TypeInteger,
	}
	namespaces := map[string]string{"c": "urn:catalog"}
	evaluator := NewEvaluator(DefaultEvaluatorOptions).Namespaces(namespaces).
		SchemaDeclarations(pathTestSchema{}).TypeAnnotations(annotations)

	for _, tc := range []struct {
		name, source string
		want         []xdm.Node
	}{
		{"declared_element_and_typed_substitute", `/catalog/schema-element(c:entry)`, []xdm.Node{children[0], children[1]}},
		{"unqualified_attribute", `/catalog/attribute::schema-attribute(rank)`, []xdm.Node{attrs[0]}},
		{"undeclared_namespaced_attribute", `/catalog/attribute::schema-attribute(c:rank)`, nil},
		{"undeclared_element_of_matching_type", `/catalog/schema-element(c:other)`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			expr, err := NewCompiler().Language(31, namespaces).Compile(tc.source)
			if err != nil {
				t.Fatalf("compile %s: %v", tc.source, err)
			}
			result, err := evaluator.Evaluate(t.Context(), expr, doc)
			if err != nil {
				t.Fatalf("evaluate %s: %v", tc.source, err)
			}
			got, allNodes := xdm.NodesFrom(result.Sequence())
			if !allNodes || !slices.Equal(got, tc.want) {
				t.Errorf("%s = %v (all nodes: %t), want nodes %v in document order", tc.source, got, allNodes, tc.want)
			}
		})
	}
}

func TestNodeItemForResolvesActiveUnionLeaves(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input, annotation string
		want                    []xdm.AtomicValue
	}{
		{"first_member_satisfies_facet", "5", "Q{urn:catalog}value", []xdm.AtomicValue{{TypeName: "Q{urn:catalog}positive", BaseType: xdm.TypeInteger, Value: int64(5)}}},
		{"rejects_first_members_facet", "-2", "Q{urn:catalog}value", []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "-2"}}},
		{"nested_qname_uses_attribute_scope", "p:title", "Q{urn:catalog}value", []xdm.AtomicValue{{TypeName: xdm.TypeQName, Value: xdm.QNameValue{URI: "urn:title", Local: "title", Prefix: "p"}}}},
		{"invalid_qname_falls_back_to_string", "q:title", "Q{urn:catalog}value", []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "q:title"}}},
		{"each_list_token_selects_own_member", "p:title q:subtitle", "Q{urn:catalog}labels", []xdm.AtomicValue{
			{TypeName: xdm.TypeQName, Value: xdm.QNameValue{URI: "urn:title", Local: "title", Prefix: "p"}},
			{TypeName: xdm.TypeString, Value: "q:subtitle"},
		}},
		{"union_selects_list", "1 2", "Q{urn:catalog}numbers-or-label", []xdm.AtomicValue{
			{TypeName: xdm.TypeInteger, Value: int64(1)}, {TypeName: xdm.TypeInteger, Value: int64(2)},
		}},
		{"empty_list_precedes_string_member", "", "Q{urn:catalog}numbers-or-label", nil},
		{"invalid_list_token_selects_string", "1 text", "Q{urn:catalog}numbers-or-label", []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: "1 text"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), `<catalog xmlns:p="urn:title"><entry value="`+tc.input+`"/></catalog>`)
			if err != nil {
				t.Fatal(err)
			}
			entry, ok := doc.DocumentElement().FirstChild().(*xdm.Element)
			if !ok || len(entry.Attributes()) != 1 {
				t.Fatal("fixture entry must have one attribute")
			}
			attr := entry.Attributes()[0]
			ec := &evalContext{typeAnnotations: map[xdm.Node]string{attr: tc.annotation}, schemaDeclarations: pathTestSchema{}}
			item := nodeItemFor(t.Context(), ec, attr)
			if item.Node != attr || item.TypeAnnotation != tc.annotation {
				t.Fatalf("node item = %+v, want original attribute with annotation %s", item, tc.annotation)
			}
			got, err := AtomizeSequence(xdm.ItemSlice{item})
			if err != nil || len(got) != len(tc.want) {
				t.Fatalf("typed value = %v, %v; want %v", got, err, tc.want)
			}
			for i, want := range tc.want {
				actual := got[i]
				equal := actual.Value == want.Value
				if n, integer := want.Value.(int64); integer {
					value, fits := actual.Int64Val()
					equal = fits && value == n
				}
				if !equal || actual.TypeName != want.TypeName || actual.BaseType != want.BaseType {
					t.Errorf("atom %d = %+v (base %q), want %+v (base %q)", i, actual, actual.BaseType, want, want.BaseType)
				}
			}
		})
	}
}

func TestPathAxesAndPredicateFocusASTAndVM(t *testing.T) {
	t.Parallel()
	const doc = `let $d := parse-xml('<r><a id="a1"><v id="v1"/><v id="v2"/></a><b id="b1"><v id="v3"/></b><a id="a2"><v id="v4"/></a></r>') return `
	assertFunctionResults(t, []functionResultCase{
		{"descendant traversal returns document order", doc + `$d//v/@id`, "v1|v2|v3|v4"},
		{"abbreviated descendant predicate uses sibling focus", doc + `($d//v[1]/@id,($d//v)[1]/@id)`, "v1|v3|v4|v1"},
		{"reverse axis applies proximity before sorting", doc + `($d/r/a[2]/preceding-sibling::*[1]/@id,($d/r/a[2]/preceding-sibling::*)[1]/@id)`, "b1|a1"},
		{"ancestor and following axes exclude self and descendants", doc + `($d//v[@id='v2']/ancestor::*[1]/@id,$d/r/a[1]/following::v/@id)`, "a1|v3|v4"},
		{"path removes duplicate nodes but simple map retains them", doc + `(($d/r/a[2],$d/r/a[1],$d/r/a[2])/v/@id,($d/r/a[2],$d/r/a[2]) ! v/@id)`, "v1|v2|v4|v4|v4"},
		{"node set operations order and deduplicate", doc + `(($d/r/a | $d/r/b)/@id,($d/r/* except $d/r/a[1])/@id,($d/r/* intersect $d/r/a)/@id)`, "a1|b1|a2|b1|a2|a1|a2"},
		{"descendant comparison predicates isolate relative paths", doc + `($d/r/*[v/@id = 'v2']/@id,$d/r/*[descendant::v[@id = 'v4']]/@id)`, "a1|a2"},
	})
}

func TestEvalLocationPathErrorsASTAndVM(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, expression, code string }{
		{"mixed node and atomic path result", `parse-xml('<r/>')/(r,1)`, "XPTY0018"},
		{"atomic path step input", `(1,2)/r`, "XPTY0019"},
		{"attribute value comparison requires singleton", `parse-xml('<r a="1" b="2"/>')/r[@* eq '1']`, "XPTY0004"},
		{"descendant attribute value comparison requires singleton", `parse-xml('<r a="1" b="2"/>')//r['1' eq @*]`, "XPTY0004"},
		{"namespace wildcard value comparison requires singleton", `parse-xml('<r xmlns:p="urn:p" a="1" p:a="2"/>')/r[@*:a eq '1']`, "XPTY0004"},
		{"existence probe retains attribute value cardinality", `exists(parse-xml('<r a="1" b="2"/>')//r[@* eq '1'])`, "XPTY0004"},
	} {
		for _, mode := range []string{runtimeASTMode, "VM"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				seq, err := evaluateFunctionExpression(t, test.expression, mode)
				if xdm.SequenceLen(seq) != 0 || !errors.Is(err, &xdm.Error{Code: test.code}) {
					t.Fatalf("%s = %v, %v; want no result and %s", test.expression, seq, err, test.code)
				}
			})
		}
	}
}

func TestMatchNodeTest(t *testing.T) {
	t.Parallel()
	const doc = `let $d := parse-xml('<!--lead--><r xmlns:p="urn:test"><p:v p:id="p" id="plain"/><v id="other"/><missing/></r>') return `
	assertFunctionResults(t, []functionResultCase{
		{"element kind test matches the expanded name", doc + `($d/r/element(Q{urn:test}v)/@id, $d/r/element(v)/@id)`, "plain|other"},
		{"element type distinguishes untyped input", doc + `(count($d/r/element(*, xs:untyped)), count($d/r/element(*, xs:string)))`, "3|0"},
		{"attribute names and namespaces stay distinct", doc + `($d//v/attribute(id), $d/r/element(Q{urn:test}v)/attribute(Q{urn:test}id))`, "other|p"},
		{
			"namespace node names have no namespace URI",
			doc + `(count($d/r/namespace::Q{urn:test}p), count($d/r/namespace::Q{}p), count($d/r/namespace::*:p),
			        count($d/r/namespace::Q{urn:test}*), count($d/r/namespace::Q{}*), count($d/r/namespace::p))`,
			"0|1|1|0|2|1",
		},
		{"empty URI wildcard retains default namespace binding", `count(parse-xml('<r xmlns="urn:default" xmlns:p="urn:test"/>')/*/namespace::Q{}*)`, "3"},
		{"keyword PI target uses the literal name", `string(parse-xml('<r><?map hello?></r>')/r/processing-instruction(map))`, "hello"},
		{"attribute type distinguishes untyped atomic input", doc + `($d/r/*/attribute(*, xs:untypedAtomic), count($d/r/*/attribute(*, xs:integer)))`, "p|plain|other|0"},
		{"document kind test checks the root element", doc + `($d instance of document-node(element(r)), $d instance of document-node(element(v)), $d/r instance of document-node())`, "true|false|false"},
		{"document kind test rejects text and multiple elements", `let $d := parse-xml-fragment('text<r/>'), $e := parse-xml-fragment('<r/><r/>'), $c := parse-xml-fragment('<!--comment-->') return ($d instance of document-node(element(r)), $e instance of document-node(element(r)), $c instance of document-node(element(r)))`, "false|false|false"},
		{"attribute presence filters preserve document order", doc + `($d/r/*[@id]/@id, $d/r/*[@Q{urn:test}id]/@id, $d/r/*[@missing]/@id)`, "plain|other|plain"},
		{"attribute comparison retains general and singleton semantics", doc + `(count($d/r/*[@* = 'plain']), count($d/r/*[@id eq 'plain']), count($d/r/*['p' eq @Q{urn:test}id]), count($d/r/*[@missing eq 'plain']))`, "1|1|1|0"},
		{"numeric position tests share one-based focus", doc + `($d/r/*[position() eq 2]/@id, $d/r/*[2 = position()]/@id, $d/r/*[2.0]/@id, count($d/r/*[2.5]))`, "other|other|other|0"},
	})
}
