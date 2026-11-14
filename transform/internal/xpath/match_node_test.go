package xpath //nolint:testpackage // Checks XPath node kind tests on the AST and VM paths.

import "testing"

func TestMatchNodeTest(t *testing.T) {
	t.Parallel()
	const doc = `let $d := parse-xml('<!--lead--><r xmlns:p="urn:test"><p:v p:id="p" id="plain"/><v id="other"/><missing/></r>') return `
	assertFunctionResults(t, []functionResultCase{
		{"element kind test matches the expanded name", doc + `($d/r/element(Q{urn:test}v)/@id, $d/r/element(v)/@id)`, "plain|other"},
		{"element type distinguishes untyped input", doc + `(count($d/r/element(*, xs:untyped)), count($d/r/element(*, xs:string)))`, "3|0"},
		{"attribute names and namespaces stay distinct", doc + `($d//v/attribute(id), $d/r/element(Q{urn:test}v)/attribute(Q{urn:test}id))`, "other|p"},
		{"attribute type distinguishes untyped atomic input", doc + `($d/r/*/attribute(*, xs:untypedAtomic), count($d/r/*/attribute(*, xs:integer)))`, "p|plain|other|0"},
		{"document kind test checks the root element", doc + `($d instance of document-node(element(r)), $d instance of document-node(element(v)), $d/r instance of document-node())`, "true|false|false"},
		{"document kind test rejects text and multiple elements", `let $d := parse-xml-fragment('text<r/>'), $e := parse-xml-fragment('<r/><r/>'), $c := parse-xml-fragment('<!--comment-->') return ($d instance of document-node(element(r)), $e instance of document-node(element(r)), $c instance of document-node(element(r)))`, "false|false|false"},
		{"attribute presence filters preserve document order", doc + `($d/r/*[@id]/@id, $d/r/*[@Q{urn:test}id]/@id, $d/r/*[@missing]/@id)`, "plain|other|plain"},
		{"numeric position tests share one-based focus", doc + `($d/r/*[position() eq 2]/@id, $d/r/*[2 = position()]/@id, $d/r/*[2.0]/@id, count($d/r/*[2.5]))`, "other|other|other|0"},
	})
}
