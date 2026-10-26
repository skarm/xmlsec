package xslt //nolint:testpackage // Tests the compiler and invocation contracts without the public transform adapter.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

type recordingMessageHandler struct {
	message   string
	terminate bool
	err       error
	calls     int
}

func (h *recordingMessageHandler) HandleMessage(message string, terminate bool) error {
	h.message, h.terminate = message, terminate
	h.calls++
	return h.err
}

func parseTestDocument(t *testing.T, source string) *xdm.Document {
	t.Helper()
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func stylesheetDocument(t *testing.T, declarations, body string) *xdm.Document {
	t.Helper()
	return parseTestDocument(t, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:f="urn:unit" version="3.0"><xsl:output method="text"/>`+declarations+`<xsl:template match="/">`+body+`</xsl:template></xsl:stylesheet>`)
}

func compileTestStylesheet(t *testing.T, declarations, body string) *Stylesheet {
	t.Helper()
	ss, err := NewCompiler().Compile(t.Context(), stylesheetDocument(t, declarations, body))
	if err != nil {
		t.Fatal(err)
	}
	return ss
}

func TestStylesheetExecutesInstructions(t *testing.T) {
	t.Parallel()
	source := parseTestDocument(t, `<r><n id="b" rank="2">2</n><n id="a" rank="1">1</n><n id="c" rank="2">3</n></r>`)
	for _, test := range []struct {
		name, declarations, body, want string
	}{
		{"template selection", `<xsl:template match="n"><xsl:value-of select="@id"/></xsl:template>`, `<xsl:apply-templates select="r/n"/>`, "bac"},
		{"numeric descending sort", "", `<xsl:for-each select="r/n"><xsl:sort select="." data-type="number" order="descending"/><xsl:value-of select="@id"/></xsl:for-each>`, "cba"},
		{"stable equal sort keys", "", `<xsl:for-each select="r/n"><xsl:sort select="@rank" data-type="number" stable="yes"/><xsl:value-of select="@id"/></xsl:for-each>`, "abc"},
		{"group preserves first appearance", "", `<xsl:for-each-group select="r/n" group-by="@rank"><xsl:value-of select="current-grouping-key()"/><xsl:text>:</xsl:text><xsl:value-of select="current-group()/@id" separator=""/><xsl:text>;</xsl:text></xsl:for-each-group>`, "2:bc;1:a;"},
		{"key index hit and miss", `<xsl:key name="by-id" match="n" use="@id"/>`, `<xsl:value-of select="(key('by-id','c'), key('by-id','missing'))"/>`, "3"},
		{"iterate carried parameter", "", `<xsl:iterate select="1 to 4"><xsl:param name="sum" select="0"/><xsl:on-completion select="$sum"/><xsl:next-iteration><xsl:with-param name="sum" select="$sum + ."/></xsl:next-iteration></xsl:iterate>`, "10"},
		{"typed function", `<xsl:function name="f:twice" as="xs:integer"><xsl:param name="n" as="xs:integer"/><xsl:sequence select="$n * 2"/></xsl:function>`, `<xsl:value-of select="f:twice(7)"/>`, "14"},
		{"analyze matching and nonmatching spans", "", `<xsl:analyze-string select="'a1b22'" regex="\d+"><xsl:matching-substring><xsl:value-of select="'[' || regex-group(0) || ']'"/></xsl:matching-substring><xsl:non-matching-substring><xsl:value-of select="upper-case(.)"/></xsl:non-matching-substring></xsl:analyze-string>`, "A[1]B[22]"},
		{"catch expanded error name", "", `<xsl:try><xsl:sequence select="error(QName('urn:unit','f:failure'))"/><xsl:catch errors="f:failure"><xsl:text>caught</xsl:text></xsl:catch></xsl:try>`, "caught"},
		{"merge matching keys", "", `<xsl:merge><xsl:merge-source select="(1,3)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-source select="(2,3)"><xsl:merge-key select="."/></xsl:merge-source><xsl:merge-action><xsl:value-of select="current-merge-key()"/><xsl:text>:</xsl:text><xsl:value-of select="count(current-merge-group())"/><xsl:text>;</xsl:text></xsl:merge-action></xsl:merge>`, "1:1;2:1;3:2;"},
		{"number positional formatting", "", `<xsl:for-each select="r/n"><xsl:number format="01"/><xsl:text>|</xsl:text></xsl:for-each>`, "01|02|03|"},
		{"empty array variable conversion", "", `<xsl:variable name="v" as="xs:string*" select="[()]"/><xsl:value-of select="count($v)"/>`, "0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, test.declarations, test.body)
			got, err := ss.Transform(source).Serialize(t.Context())
			if err != nil || got != test.want {
				t.Fatalf("output = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestInvocationParameterIsolation(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `<xsl:param name="p" select="'default'"/><xsl:template name="start"><xsl:param name="local" select="'local-default'"/><xsl:param name="t" tunnel="yes" select="'tunnel-default'"/><xsl:value-of select="($p,$local,$t)" separator="|"/></xsl:template>`, ``)
	parameters := NewParameters()
	sequence := xdm.ItemSlice{stringItem("original")}
	parameters.Set("p", sequence)
	base := ss.CallTemplate("start").GlobalParameters(parameters)
	parameters.SetString("p", "changed collection")
	sequence[0] = stringItem("changed sequence")
	branch := base.SetParameter("p", xdm.SingleString("branch")).SetInitialTemplateParameter("local", xdm.SingleString("argument")).SetTunnelParameter("t", xdm.SingleString("tunneled"))
	for _, test := range []struct {
		inv  Invocation
		want string
	}{
		{base, "original|local-default|tunnel-default"},
		{branch, "branch|argument|tunneled"},
		{base, "original|local-default|tunnel-default"},
	} {
		got, err := test.inv.Serialize(t.Context())
		if err != nil || got != test.want {
			t.Fatalf("parameter snapshot = %q, %v; want %q", got, err, test.want)
		}
	}
}

func TestFunctionCachePreservesArgumentSemantics(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, parameterType, resultType, selectExpr, calls, want string }{
		{"QName namespace identity", "xs:QName", "xs:string", `string(namespace-uri-from-QName($x))`, `f:probe(QName('urn:a','n')),f:probe(QName('urn:b','n')),f:probe(QName('urn:a','n'))`, "urn:a|urn:b|urn:a"},
		{"node identity", "node()", "node()", `$x`, `f:probe(r/n[1]) is r/n[1],f:probe(r/n[2]) is r/n[2],f:probe(r/n[1]) is f:probe(r/n[2])`, "true|true|false"},
		{"sequence boundaries inside arrays", "array(*)", "xs:string", `array:size($x) || ':' || count($x?1) || ':' || string-join($x?* ! string(.), ',')`, `f:probe([(),(1,2)]),f:probe([(1,2),()]),f:probe([(),(1,2)])`, "2:0:1,2|2:2:1,2|2:0:1,2"},
		{"map values", "map(*)", "xs:string", `string($x('key'))`, `f:probe(map{'key':'a'}),f:probe(map{'key':'b'}),f:probe(map{'key':'a'})`, "a|b|a"},
		{"function arguments bypass cache", "function(*)", "xs:string", `$x()`, `let $a := function(){'a'}, $b := function(){'b'} return (f:probe($a),f:probe($b),f:probe($a))`, "a|b|a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			declarations := `<xsl:function xmlns:array="http://www.w3.org/2005/xpath-functions/array" name="f:probe" cache="yes" new-each-time="no" as="` + tc.resultType + `"><xsl:param name="x" as="` + tc.parameterType + `"/><xsl:sequence select="` + tc.selectExpr + `"/></xsl:function>`
			ss := compileTestStylesheet(t, declarations, `<xsl:value-of select="(`+tc.calls+`)" separator="|"/>`)
			for range 2 {
				got, err := ss.Transform(parseTestDocument(t, `<r><n>same</n><n>same</n></r>`)).Serialize(t.Context())
				if err != nil || got != tc.want {
					t.Fatalf("cached function = %q, %v; want %q", got, err, tc.want)
				}
			}
		})
	}
}

func TestProactiveFunctionCacheHintPreservesFreshNodes(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `<xsl:function name="f:fresh" cache="yes" new-each-time="yes" as="element()"><xsl:param name="v"/><n><xsl:value-of select="$v"/></n></xsl:function>`, `<xsl:variable name="a" select="f:fresh('same')"/><xsl:variable name="b" select="f:fresh('same')"/><xsl:value-of select="($a is $a,$a is $b,string($a),string($b))" separator="|"/>`)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	if err != nil || got != "true|false|same|same" {
		t.Fatalf("proactive function = %q, %v; want distinct equal-content nodes", got, err)
	}
}

func TestCompilerStaticParameterIsolation(t *testing.T) {
	t.Parallel()
	doc := stylesheetDocument(t, `<xsl:param name="p" static="yes" select="'default'"/>`, `<xsl:value-of select="$p"/>`)
	parameters := NewParameters()
	parameters.SetString("p", "original")
	base := NewCompiler().StaticParameters(parameters)
	parameters.Clear()
	branch := base.SetStaticParameter("p", xdm.SingleString("branch"))
	for _, test := range []struct {
		compiler Compiler
		want     string
	}{{base, "original"}, {branch, "branch"}, {branch.ClearStaticParameters(), "default"}, {base, "original"}} {
		ss, err := test.compiler.Compile(t.Context(), doc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
		if err != nil || got != test.want {
			t.Fatalf("static parameter snapshot = %q, %v; want %q", got, err, test.want)
		}
	}
}

func TestInvocationMessageFailure(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, "", `<xsl:message select="'notice'"/><xsl:text>completed</xsl:text>`)
	source := parseTestDocument(t, `<r/>`)
	sentinel := errors.New("message sink failed")
	for _, sinkErr := range []error{nil, sentinel} {
		handler := &recordingMessageHandler{err: sinkErr}
		got, err := ss.Transform(source).MessageHandler(handler).Serialize(t.Context())
		if handler.calls != 1 || handler.message != "notice" || handler.terminate {
			t.Fatalf("message delivery = %+v", handler)
		}
		if sinkErr == nil {
			if err != nil || got != "completed" {
				t.Fatalf("successful handler = %q, %v", got, err)
			}
		} else if got != "" || !errors.Is(err, sentinel) {
			t.Fatalf("failed handler = %q, %v; want no result and original cause", got, err)
		}
	}
}

func TestInvocationOutputSnapshot(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, "", `<xsl:text>result</xsl:text>`)
	inv := ss.Transform(parseTestDocument(t, `<r/>`))
	if inv.ResolvedOutputDef() != nil {
		t.Fatal("output already resolved before execution")
	}
	var output strings.Builder
	if err := inv.WriteTo(t.Context(), &output); err != nil || output.String() != "result" {
		t.Fatalf("writer output = %q, %v", output.String(), err)
	}
	def := inv.ResolvedOutputDef()
	if def == nil || def.Method != "text" {
		t.Fatalf("resolved output = %+v", def)
	}
	def.Method = "html"
	if got := inv.ResolvedOutputDef(); got == nil || got.Method != "text" {
		t.Fatalf("caller changed retained output: %+v", got)
	}
	clone := inv.BaseOutputURI("https://output.example/result")
	if clone.ResolvedOutputDef() != nil || inv.ResolvedOutputDef().Method != "text" {
		t.Fatal("fluent branch shares resolved output state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := clone.Serialize(ctx); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled invocation = %q, %v", got, err)
	}
}
