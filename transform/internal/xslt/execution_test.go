package xslt //nolint:testpackage // Tests the compiler and invocation contracts without the public transform adapter.

import (
	"context"
	"errors"
	"io"
	"reflect"
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

func TestApplyTemplatesStripsWhitespaceOnlyFromSource(t *testing.T) {
	t.Parallel()

	const source = `<r> <a>source</a> <r xml:space="preserve"> <a>kept</a></r></r>`
	const sourceBody = `<xsl:value-of select="count(r/text())"/>|<xsl:apply-templates select="r/a"/>|<xsl:apply-templates select="r/r"/>`
	const temporaryBody = `|<xsl:variable name="temp" as="element(r)"><r><xsl:text> </xsl:text><a>value</a></r></xsl:variable>`
	const checkItems = `<xsl:value-of select="$items" separator="|"/>[<xsl:apply-templates select="$items"/>]<xsl:value-of select="$items" separator="|"/>`

	for _, tc := range []struct {
		version   string
		processor int
		body      string
		want      string
	}{
		{"1.0", processorXSLT10, sourceBody, "0|a;|text;a;"},
		{
			version:   "2.0",
			processor: processorXSLT20,
			body: sourceBody + temporaryBody +
				`<xsl:variable name="items" as="item()*" select="($temp/text(), $temp/a)"/>` + checkItems,
			want: "0|a;|text;a;| |value[text;a;] |value",
		},
		{
			version:   "3.0",
			processor: processorXSLT30,
			body: sourceBody + temporaryBody +
				`<xsl:variable name="items" as="item()*" select="($temp/text(), $temp/a, 'end')"/>` + checkItems +
				`|<xsl:apply-templates select="parse-xml('&lt;r> &lt;a>parsed&lt;/a>&lt;/r>')/r"/>`,
			want: "0|a;|text;a;| |value|end[text;a;end] |value|end|text;a;",
		},
	} {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()

			sheet := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="` + tc.version + `">
				<xsl:output method="text"/>
				<xsl:strip-space elements="r"/>
				<xsl:template match="/">` + tc.body + `</xsl:template>
				<xsl:template match="r"><xsl:apply-templates/></xsl:template>
				<xsl:template match="text()">text;</xsl:template>
				<xsl:template match="a">a;</xsl:template>
			</xsl:stylesheet>`
			ss, err := NewCompiler().ProcessorVersion(tc.processor).Compile(t.Context(), parseTestDocument(t, sheet))
			if err != nil {
				t.Fatal(err)
			}

			got, err := ss.Transform(parseTestDocument(t, source)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}

func TestPerformSortPreservesOutputItemsAndCallerFocus(t *testing.T) {
	t.Parallel()
	const source = `<r><n>b</n><n>a</n><scope/><scope active="yes"/><scope/></r>`
	for _, tc := range []struct{ name, body, want string }{
		{
			name: "mixed_sorted_content_keeps_nodes",
			body: `<xsl:variable name="result" as="element(out)">
				<out>
					<xsl:perform-sort select="('b',r/n[1],'a')">
						<xsl:sort select="if (. instance of node()) then 'am' else string(.)"/>
					</xsl:perform-sort>
				</out>
			</xsl:variable>
			<xsl:value-of select="($result/text()[1], name($result/n), string($result/n), $result/text()[2])" separator="|"/>`,
			want: "a|n|b|b",
		},
		{
			name: "sorted_empty_atomic_retains_its_separator",
			body: `<out>[<xsl:perform-sort select="('b','')">
				<xsl:sort select="." order="descending"/>
			</xsl:perform-sort>]</out>`,
			want: "[b ]",
		},
		{
			name: "atomic_sort_options_use_containing_focus",
			body: `<xsl:for-each select="('skip','caller','skip')">
				<xsl:if test=". = 'caller'">
					<xsl:variable name="sorted" as="item()*">
						<xsl:perform-sort select="('b','a')">
							<xsl:sort select="." order="{if (. = 'caller' and position() = 2 and last() = 3) then 'ascending' else 'descending'}"/>
						</xsl:perform-sort>
					</xsl:variable>
					<xsl:value-of select="$sorted" separator=""/>
				</xsl:if>
			</xsl:for-each>`,
			want: "ab",
		},
		{
			name: "node_sort_options_use_containing_focus",
			body: `<xsl:for-each select="r/scope">
				<xsl:if test="@active">
					<xsl:for-each select="../n">
						<xsl:sort select="current()" order="{if (@active and position() = 2 and last() = 3) then 'ascending' else 'descending'}"/>
						<xsl:sort select="position()"/>
						<xsl:value-of select="."/>
					</xsl:for-each>
				</xsl:if>
			</xsl:for-each>`,
			want: "ab",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := compileTestStylesheet(t, "", tc.body)
			got, err := ss.Transform(parseTestDocument(t, source)).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
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
	global := xdm.ItemSlice{stringItem("branch")}
	local := xdm.ItemSlice{stringItem("argument")}
	tunnel := xdm.ItemSlice{stringItem("tunneled")}
	branch := base.SetParameter("p", global).SetInitialTemplateParameter("local", local).SetTunnelParameter("t", tunnel)
	global[0], local[0], tunnel[0] = stringItem("changed global"), stringItem("changed local"), stringItem("changed tunnel")
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

func TestElementAvailableReflectsBasicProcessor(t *testing.T) {
	t.Parallel()
	const declarations = `<xsl:variable name="available" select="element-available('xsl:import-schema')" static="yes"/>`
	const body = `<xsl:value-of select="($available,element-available('xsl:import-schema'),
			element-available('xsl:function'),system-property('xsl:is-schema-aware'))" separator="|"/>`
	ss := compileTestStylesheet(t, declarations, body)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "false|false|true|no", "")
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

func TestProactiveFunctionCachePreservesQNamePrefixes(t *testing.T) {
	t.Parallel()
	const declarations = `<xsl:function name="f:identity" cache="yes">
		<xsl:param name="value"/>
		<xsl:sequence select="$value"/>
	</xsl:function>`
	const body = `<xsl:value-of select="(
		string(f:identity(QName('urn:unit','x:n'))),
		string(f:identity(QName('urn:unit','y:n'))),
		string(f:identity(QName('urn:unit','x:n'))),
		string(f:identity(QName('urn:unit','n'))),
		f:identity(7) instance of xs:integer,
		f:identity('7') instance of xs:string,
		f:identity(true()) instance of xs:boolean
	)" separator="|"/>`
	ss := compileTestStylesheet(t, declarations, body)
	got, err := ss.Transform(parseTestDocument(t, `<r/>`)).Serialize(t.Context())
	requireSerialization(t, got, err, "x:n|y:n|x:n|n|true|true|true", "")
}

func TestCompilerStaticParameterIsolation(t *testing.T) {
	t.Parallel()
	doc := stylesheetDocument(t, `<xsl:param name="p" static="yes" select="'default'"/>`, `<xsl:value-of select="$p"/>`)
	parameters := NewParameters()
	parameters.SetString("p", "original")
	base := NewCompiler().StaticParameters(parameters)
	parameters.Clear()
	parameter := xdm.ItemSlice{stringItem("branch")}
	branch := base.SetStaticParameter("p", parameter)
	parameter[0] = stringItem("changed sequence")
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
	retained := inv.ResolvedOutputDef()
	if clone.ResolvedOutputDef() != nil || retained == nil || retained.Method != "text" {
		t.Fatal("fluent branch shares resolved output state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := clone.Serialize(ctx); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled invocation = %q, %v", got, err)
	}
}

type cancelingOutput struct {
	strings.Builder
	cancel context.CancelFunc
}

func (w *cancelingOutput) Write(data []byte) (int, error) {
	n, err := w.Builder.Write(data)
	w.cancel()
	return n, err
}

func (w *cancelingOutput) WriteString(data string) (int, error) {
	return w.Write([]byte(data))
}

func TestXHTMLSerializationCancellationAfterBOM(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &cancelingOutput{cancel: cancel}
	doc := parseTestDocument(t, `<html xmlns="http://www.w3.org/1999/xhtml"><head/><body>content</body></html>`)
	result := ValueResult{
		Document: doc,
		Items:    xdm.ItemSlice{xdm.NodeItem{Node: doc}},
		Output:   &OutputDef{Method: "xhtml", MethodExplicit: true, ByteOrderMark: true},
	}
	if err := SerializeValue(ctx, w, result); !errors.Is(err, context.Canceled) || w.String() != "\ufeff" {
		t.Fatalf("canceled serialization wrote %q with %v; want only the BOM and context.Canceled", w.String(), err)
	}
}

func TestCopyOfFunctionDoesNotIndexDetachedCopyInCurrentDocument(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, "", `<xsl:variable name="d"><result xml:id="present"><xsl:value-of select="name(copy-of(/*))"/></result></xsl:variable><xsl:value-of select="(string($d/result), name(id('present', $d)), exists(id('source', $d)))" separator="|"/>`)
	for _, id := range []string{"source", "present"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			source := parseTestDocument(t, `<source xml:id="`+id+`"/>`)
			got, err := ss.Transform(source).Serialize(t.Context())
			if want := "source|result|false"; err != nil || got != want {
				t.Fatalf("id() saw a copy outside the selected document: got %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestChangedFocusClearsCurrentTemplateRule(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, body string }{
		{"for-each", `<xsl:for-each select="r/n">%s</xsl:for-each>`},
		{"for-each-group", `<xsl:for-each-group select="r/n" group-by="string(.)">%s</xsl:for-each-group>`},
		{"iterate", `<xsl:iterate select="r/n">%s</xsl:iterate>`},
		{"analyze-string", `<xsl:analyze-string select="'text'" regex="text"><xsl:matching-substring>%s</xsl:matching-substring></xsl:analyze-string>`},
		{"source-document", `<xsl:source-document href="https://source.example/input.xml">%s</xsl:source-document>`},
		{"merge", `<xsl:merge><xsl:merge-source select="r/n"><xsl:merge-key select="string(.)"/></xsl:merge-source><xsl:merge-action>%s</xsl:merge-action></xsl:merge>`},
		{"sort", `<xsl:for-each select="r/n"><xsl:sort>%s</xsl:sort><xsl:value-of select="."/></xsl:for-each>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, call := range []string{`<xsl:next-match/>`, `<xsl:apply-imports/>`} {
				ss := compileTestStylesheet(t, ``, strings.Replace(test.body, "%s", call, 1))
				source := parseTestDocument(t, `<r><n>one</n><n>two</n></r>`)
				got, err := ss.Transform(source).URIResolver(streamTestResolver{source: `<external/>`}).Serialize(t.Context())
				if !isXSLTError(err, errCodeXTDE0560) || got != "" {
					t.Fatalf("%s with changed focus returned %q, %v; want XTDE0560", call, got, err)
				}
			}
		})
	}
}

func TestChangedFocusRestoresCurrentTemplateRule(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, `<xsl:template match="/" priority="-10">outer</xsl:template><xsl:template match="n" priority="2"><xsl:next-match/></xsl:template><xsl:template match="n" priority="0">inner</xsl:template>`, `<xsl:for-each-group select="r/n" group-by="string(.)"><xsl:apply-templates select="."/></xsl:for-each-group><xsl:next-match/>`)
	if got, err := ss.Transform(parseTestDocument(t, `<r><n>one</n></r>`)).Serialize(t.Context()); err != nil || got != "innerouter" {
		t.Fatalf("nested and restored template rules returned %q, %v; want innerouter", got, err)
	}
}

type streamTestResolver struct {
	source string
}

func (r streamTestResolver) Resolve(ctx context.Context, _ string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return io.NopCloser(strings.NewReader(r.source)), nil
}

func TestStreamAvailableUsesDefaultParseOptions(t *testing.T) {
	t.Parallel()
	ss := compileTestStylesheet(t, "", `<xsl:text>unused</xsl:text>`)
	for _, test := range []struct {
		name, source string
		limit        int64
		want         bool
	}{
		{"XML", `<r/>`, 0, true},
		{"DTD rejected", `<!DOCTYPE r [<!ENTITY x "value">]><r>&x;</r>`, 0, false},
		{"byte limit", strings.Repeat(" ", 64) + `<r/>`, 8, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ec := &execContext{stylesheet: ss, transformConfig: &transformConfig{uriResolver: streamTestResolver{source: test.source}, maxResourceBytes: test.limit}}
			if ec.inputParseOptions() != nil {
				t.Fatal("test requires the default parse policy")
			}
			result, err := ec.fnStreamAvailable(t.Context(), []xdm.Sequence{xdm.SingleString("https://source.example/input.xml")})
			if err != nil {
				t.Fatal(err)
			}
			if xdm.SequenceLen(result) != 1 || !reflect.DeepEqual(result.Get(0), xdm.AtomicValue{TypeName: xdm.TypeBoolean, Value: test.want}) {
				t.Fatalf("stream-available = %v; want %v", result, test.want)
			}
		})
	}
}

func TestDocumentNodeFromAbsentNode(t *testing.T) {
	t.Parallel()
	var doc *xdm.Document
	var element *xdm.Element
	for _, node := range []xdm.Node{nil, doc, element} {
		if got := documentNodeFromNode(node); got != nil {
			t.Fatalf("absent node acquired document %v", got)
		}
	}
}
