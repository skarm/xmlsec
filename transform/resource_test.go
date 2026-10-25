package transform_test

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

type collectionResolverFixture struct {
	collection func(context.Context, string) (transform.Sequence, error)
	uris       func(context.Context, string) ([]string, error)
}

func TestPackageExposureContracts(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range []struct{ body, code string }{
		{`<xsl:variable name="v"/><xsl:expose component="variable" names="missing" visibility="public"/>`, errCodeXTSE3020},
		{`<xsl:param name="p"/><xsl:expose component="variable" names="p" visibility="private"/>`, errCodeXTSE3020},
		{`<xsl:template name="h"/><xsl:expose component="*" names="h" visibility="public"/>`, "XTSE3022"},
		{`<xsl:template name="h"/><xsl:expose component="template" names="h" visibility="hidden"/>`, errCodeXTSE0020},
		{`<xsl:template name="h"/><xsl:expose component="template" names="h#0" visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:function name="p:f"/><xsl:expose component="function" names="p:f#bad" visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:function name="p:f"/><xsl:expose component="function" names="p:f#-1" visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:expose component="template" names="foo:*" visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:expose component="template" names="foo:h" visibility="public"/>`, errCodeXTSE0280},
		{`<xsl:expose component="template" names="Q{{urn:bad}h" visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:expose component="template" names="  " visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:expose component="template" names="h&#160;other" visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:mode/><xsl:expose component="mode" names="#unnamed" visibility="public"/>`, errCodeXTSE0020},
		{`<xsl:template name="h" visibility="public"/><xsl:expose component="template" names="h" visibility="abstract"/>`, "XTSE3010"},
		{`<xsl:template name="h"/><xsl:expose component="template" names="h" visibility="abstract"/>`, "XTSE3025"},
	} {
		_, err := e.CompileXSLT(t.Context(), []byte(packageSheet("", test.body)), transform.XSLTOptions{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != test.code {
			t.Fatal(test.body, err, test.code)
		}
	}

	for _, body := range []string{
		`<xsl:template name="p:h">ok</xsl:template><xsl:expose component="template" names="p:h" visibility="public"/><xsl:expose component="*" names="*" visibility="private"/>`,
		`<xsl:template name="p:h">ok</xsl:template><xsl:expose component="template" names="p:*" visibility="public"/><xsl:expose component="*" names="*" visibility="private"/>`,
		`<xsl:template name="p:h" visibility="public">ok</xsl:template><xsl:expose component="template" names="*" visibility="private"/>`,
		`<xsl:template name="p:h">ok</xsl:template><xsl:expose component="template" names="p:h" visibility="private"/><xsl:expose component="template" names="p:h" visibility="public"/>`,
		`<xsl:template name="p:h">ok</xsl:template><xsl:expose component="template" names="*" visibility="private"/><xsl:expose component="template" names="p:h" visibility="public"/>`,
	} {
		result, err := stylesheet(t, e, packageSheet("", body)).CallTemplate(t.Context(), nil, transform.Name{Space: "urn:components", Local: "h"}, transform.XSLTContext{})
		if err != nil || text(t, result.Primary()) != "ok" {
			t.Fatal(body, result, err)
		}
	}

	for _, pattern := range []string{"p:f", "p:f#00", "Q{urn:components}f#0", "Q{urn:components}*"} {
		compiled := stylesheet(t, e, packageSheet("", `<xsl:function name="p:f"><xsl:sequence select="42"/></xsl:function><xsl:expose component="function" names="`+pattern+`" visibility="public"/>`))

		result, err := compiled.CallFunction(t.Context(), nil, transform.Name{Space: "urn:components", Local: "f"}, nil, transform.XSLTContext{})
		if err != nil || text(t, result.Primary()) != "42" {
			t.Fatal(pattern, result, err)
		}
	}

	for _, body := range []string{
		`<xsl:import-schema namespace="urn:unused" use-when="false()"/><xsl:template name="start" visibility="public">ok</xsl:template>`,
		`<xsl:template name="start" visibility="public">ok</xsl:template><xsl:expose use-when="false()" component="template" names="missing" visibility="public"/>`,
	} {
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, packageSheet("", body), nested)
			if err != nil || got != "ok" {
				t.Fatal(body, nested, got, err)
			}
		}
	}

	compiled := stylesheet(t, e, packageSheet("", `<xsl:template name="Q{urn:components#fragment}h">ok</xsl:template><xsl:expose component="template" names="Q{urn:components#fragment}*" visibility="public"/>`))

	result, err := compiled.CallTemplate(t.Context(), nil, transform.Name{Space: "urn:components#fragment", Local: "h"}, transform.XSLTContext{})
	if err != nil || text(t, result.Primary()) != "ok" {
		t.Fatal(result, err)
	}
}

func TestPackageRootShadowAttributes(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, test := range []struct{ attributes, version, code string }{
		{`_xmlns="urn:injected"`, "", errCodeXTSE0090},
		{`__version="3.0"`, "", errCodeXTSE0090},
		{`_="3.0"`, "", errCodeXTSE0090},
		{"", "", ""},
		{`package-version="2.0-valid"`, "", ""},
		{`package-version="invalid" _package-version="2.0-valid"`, "", ""},
		{`_version="3.0"`, invalidValue, ""},
		{`default-collation="urn:unavailable" _default-collation="http://www.w3.org/2005/xpath-functions/collation/codepoint"`, "", ""},
		{emptyPackageVersionAttribute, "", errCodeXTSE0020},
		{`package-version="1..0"`, "", errCodeXTSE0020},
		{`package-version="1-"`, "", errCodeXTSE0020},
		{`package-version="1" _package-version=""`, "", errCodeXTSE0020},
		{`package-version="1" _package-version="{1 div 0}"`, "", errCodeFOAR0001},
	} {
		source := packageSheet(test.attributes, `<xsl:template name="start" visibility="public">ok</xsl:template>`)
		if test.version != "" {
			source = strings.Replace(source, `version="3.0"`, `version="`+test.version+`"`, 1)
		}

		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if test.code == "" {
				if err != nil || got != "ok" {
					t.Fatal(test.attributes, nested, got, err)
				}

				continue
			}

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != test.code {
				t.Fatal(test.attributes, nested, err, test.code)
			}
		}
	}

	source := packageSheet(`package-version="invalid" _package-version="2"`, `<xsl:template name="start" visibility="public"><xsl:value-of select="document('')/*/@package-version"/></xsl:template>`)
	for _, nested := range []bool{false, true} {
		got, err := resourceStylesheetResult(t, e, source, nested)
		if err != nil || got != invalidValue {
			t.Fatal("shadow processing changed source document", nested, got, err)
		}
	}

	for _, attributes := range []string{emptyPackageVersionAttribute, `_package-version="1"`} {
		source := strings.ReplaceAll(packageSheet(attributes, `<xsl:template name="start" visibility="public">ok</xsl:template>`), "xsl:package", "xsl:stylesheet")
		_, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != errCodeXTSE0090 {
			t.Fatal(attributes, err)
		}
	}
}

func TestResolvedPackageShadowIdentity(t *testing.T) {
	for _, version := range []string{"2", "1"} {
		resolver := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, _, _ string) (transform.PackageResource, error) {
			return transform.PackageResource{BaseURI: "urn:effective", Reader: io.NopCloser(strings.NewReader(packageSheet(`name="urn:wrong" _name="urn:effective" package-version="invalid" _package-version="2"`, `<xsl:template name="helper" visibility="public">ok</xsl:template>`)))}, ctx.Err()
		})})

		source := sheet(version30, `<xsl:use-package name="urn:effective" package-version="`+version+`"/><xsl:template name="start"><xsl:call-template name="helper"/></xsl:template>`)
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, resolver, source, nested)
			if version == "2" {
				if err != nil || got != "ok" {
					t.Fatal(version, nested, got, err)
				}

				continue
			}

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != "XTSE3000" {
				t.Fatal(version, nested, err)
			}
		}
	}
}

type packageBindingCase struct{ name, library, using, want, oracleWant string }

func packageBindingCases() []packageBindingCase {
	var tests []packageBindingCase

	for _, component := range []struct{ kind, name, declaration, invoke string }{
		{"function", "p:f#0", `<xsl:function name="p:f" visibility="abstract" as="xs:integer"/>`, packageFunctionInvocation},
		{"template", "p:t", `<xsl:template name="p:t" visibility="abstract" as="xs:integer"/>`, packageTemplateInvocation},
		{"variable", "p:v", `<xsl:variable name="p:v" visibility="abstract" as="xs:integer"/>`, `<xsl:value-of select="$p:v"/>`},
		{"attribute-set", "p:a", `<xsl:attribute-set name="p:a" visibility="abstract"/>`, `<r xsl:use-attribute-sets="p:a"/>`},
	} {
		library := packageSheet(`name="urn:binding-library"`, component.declaration+`<xsl:template name="p:run" visibility="public">`+component.invoke+`</xsl:template>`)
		for _, acceptance := range []struct{ name, accept, want string }{
			{"default", "", errCodeXTDE3052},
			{"hidden", `<xsl:accept component="` + component.kind + `" names="` + component.name + `" visibility="hidden"/>`, errCodeXTDE3052},
			{"incompatible wildcard", `<xsl:accept component="*" names="*" visibility="public"/>`, errCodeXTDE3052},
			{"abstract", `<xsl:accept component="` + component.kind + `" names="` + component.name + `" visibility="abstract"/>`, "XTSE3080"},
			{"incompatible explicit", `<xsl:accept component="` + component.kind + `" names="` + component.name + `" visibility="public"/>`, "XTSE3040"},
		} {
			using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library">`+acceptance.accept+`</xsl:use-package><xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/></xsl:template>`)
			tests = append(tests, packageBindingCase{component.kind + " " + acceptance.name, library, using, acceptance.want, ""})
		}

		using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:template name="start" visibility="public">ok</xsl:template>`)
		tests = append(tests, packageBindingCase{component.kind + " unused", library, using, "ok", ""})
	}

	for _, invoke := range []string{`<xsl:value-of select="(p:f#0)()"/>`, `<xsl:value-of select="apply(p:f#0,[])"/>`} {
		library := packageSheet(`name="urn:binding-library"`, `<xsl:function name="p:f" visibility="abstract" as="xs:integer"/><xsl:template name="p:run" visibility="public">`+invoke+`</xsl:template>`)
		using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/></xsl:template>`)
		tests = append(tests, packageBindingCase{invoke, library, using, errCodeXTDE3052, "XPTY0004"})
	}

	const (
		privateBindings = `<xsl:function name="p:f" as="xs:string"><xsl:sequence select="'L'"/></xsl:function><xsl:variable name="p:v" select="'L'"/><xsl:template name="p:t">L</xsl:template><xsl:attribute-set name="p:a"><xsl:attribute name="value">L</xsl:attribute></xsl:attribute-set>`
		bindingProbe    = `<xsl:value-of select="p:f()||$p:v"/><xsl:call-template name="p:t"/><xsl:variable name="tree"><r xsl:use-attribute-sets="p:a"/></xsl:variable><xsl:value-of select="$tree/r/@value"/>`
	)

	library := packageSheet(`name="urn:binding-library"`, privateBindings+`<xsl:template name="p:run" visibility="public">`+bindingProbe+`</xsl:template>`)
	using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/>`+strings.ReplaceAll(privateBindings, "L", "U")+`<xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/>`+bindingProbe+`</xsl:template>`)

	tests = append(tests, packageBindingCase{"package-local homonyms", library, using, "LLLLUUUU", ""})
	for _, target := range []struct{ declaration, invoke string }{
		{`<xsl:function name="p:f" visibility="public" as="xs:string"><xsl:sequence select="'ok'"/></xsl:function>`, packageFunctionInvocation},
		{`<xsl:template name="p:t" visibility="public">ok</xsl:template>`, packageTemplateInvocation},
		{`<xsl:variable name="p:v" visibility="public" select="'ok'"/>`, `<xsl:value-of select="$p:v"/>`},
		{`<xsl:attribute-set name="p:a" visibility="public"><xsl:attribute name="value">ok</xsl:attribute></xsl:attribute-set>`, `<xsl:variable name="tree"><r xsl:use-attribute-sets="p:a"/></xsl:variable><xsl:value-of select="$tree/r/@value"/>`},
	} {
		library := packageSheet(`name="urn:binding-library"`, target.declaration+`<xsl:template name="p:run" visibility="public">`+target.invoke+`</xsl:template>`)
		for _, hidden := range []bool{false, true} {
			accept, body := "", target.invoke
			if hidden {
				accept = `<xsl:accept component="*" names="*" visibility="hidden"/><xsl:accept component="template" names="p:run" visibility="private"/>`
				body = `<xsl:call-template name="p:run"/>`
			}

			using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library">`+accept+`</xsl:use-package><xsl:template name="start" visibility="public">`+body+`</xsl:template>`)

			label := "accepted private "
			if hidden {
				label = "hidden concrete "
			}

			tests = append(tests, packageBindingCase{label + target.declaration, library, using, "ok", ""})
		}
	}

	library = packageSheet(`name="urn:binding-library"`, `<xsl:function name="p:f" visibility="abstract" as="xs:integer"/><xsl:template name="p:run" visibility="public"><xsl:value-of select="exists(function-lookup(QName('urn:components','f'),0))"/></xsl:template>`)
	using = packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/></xsl:template>`)

	tests = append(tests, packageBindingCase{"abstract dynamic lookup", library, using, nameFalse, ""})
	for _, each := range []string{"", ` new-each-time="yes"`, ` new-each-time="no"`} {
		library := packageSheet(`name="urn:binding-library"`, `<xsl:function name="p:f" cache="yes" as="element()"`+each+`><r/></xsl:function><xsl:template name="p:run" visibility="public"><xsl:value-of select="p:f() is p:f()"/></xsl:template>`)
		using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/></xsl:template>`)

		want := nameFalse
		if strings.Contains(each, `"no"`) {
			want = nameTrue
		}

		tests = append(tests, packageBindingCase{"function identity" + each, library, using, want, nameTrue})
	}

	for _, probe := range []string{`exists(function-lookup(QName('urn:components','f'),0))`, `function-available('p:f',0)`} {
		library := packageSheet(`name="urn:binding-library"`, `<xsl:function name="p:f" visibility="public"><xsl:sequence select="'L'"/></xsl:function>`)
		using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:template name="start" visibility="public"><xsl:value-of select="`+probe+`"/></xsl:template>`)
		tests = append(tests, packageBindingCase{"accepted dynamic " + probe, library, using, nameTrue, ""})
	}

	for _, declared := range []string{`<xsl:function name="p:f" visibility="public"><xsl:sequence select="'L'"/></xsl:function>`, `<xsl:function name="p:f" visibility="abstract"/>`} {
		library := packageSheet(`name="urn:binding-library"`, declared+`<xsl:template name="p:run" visibility="public"><xsl:value-of select="p:f()||':'||function-available('p:f',0)||':'||exists(function-lookup(QName('urn:components','f'),0))"/></xsl:template>`)
		using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"><xsl:override><xsl:function name="p:f"><xsl:sequence select="'U'"/></xsl:function></xsl:override></xsl:use-package><xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/></xsl:template>`)

		want := "U:true:true"
		if strings.Contains(declared, `visibility="abstract"`) {
			want = "U:false:false"
		}

		oracleWant := ""
		if want == "U:false:false" {
			oracleWant = "U:true:false"
		}

		tests = append(tests, packageBindingCase{"declared dynamic " + declared, library, using, want, oracleWant})
	}

	tests = append(tests, packageOverrideCases()...)
	tests = append(tests, lexicalModeCases()...)
	tests = append(tests, keyContractCases()...)
	tests = append(tests, packageGlobalCases()...)

	return tests
}

func keyContractCases() []packageBindingCase {
	const (
		documentValue = `<xsl:variable name="d" select="parse-xml('&lt;r>&lt;n id=&quot;1&quot; k=&quot;a&quot;/>&lt;n id=&quot;2&quot; k=&quot;b&quot;/>&lt;/r>')"/>`
		keyNameError  = "XTDE1260"
		ordinaryKey   = `<xsl:key name="k" match="n" use="@k"/>`
	)

	tests := make([]packageBindingCase, 0, 44)

	for _, test := range []struct{ name, declarations, expression, want string }{
		{"unknown key", "", `key('missing','a',$d)`, keyNameError},
		{"unknown key empty value", "", `key('missing',(),$d)`, keyNameError},
		{"invalid key name", ordinaryKey, `key('bad name','a',$d)`, keyNameError},
		{"unbound key name", ordinaryKey, `key('bad:k','a',$d)`, keyNameError},
		{"empty key name", ordinaryKey, `key((),'a',$d)`, errCodeXPTY0004},
		{"numeric key name", ordinaryKey, `key(1,'a',$d)`, errCodeXPTY0004},
		{"multiple key names", ordinaryKey, `key(('k','k'),'a',$d)`, errCodeXPTY0004},
		{"empty key root", ordinaryKey, `key('k','a',())`, errCodeXPTY0004},
		{"atomic key root", ordinaryKey, `key('k','a',1)`, errCodeXPTY0004},
		{"multiple key roots", ordinaryKey, `key('k','a',($d,$d))`, errCodeXPTY0004},
		{"atomic context", ordinaryKey, `1 ! key('k','a')`, "XTDE1270"},
		{"context document", ordinaryKey, `$d ! string-join(key('k','a') ! string(@id),',')`, "1"},
		{"request order and duplicates", ordinaryKey, `string-join(key('k',('b','a','b'),$d) ! string(@id),',')`, "1,2"},
		{"array key values", ordinaryKey, `string-join(key('k',[['b'],[],['a']],$d) ! string(@id),',')`, "1,2"},
		{"scoped key root", ordinaryKey, `string-join(key('k',('a','b'),$d/r/n[2]) ! string(@id),',')`, "2"},
		{"composite empty sequence", `<xsl:key name="k" match="n" use="()" composite="yes"/>`, `count(key('k',(),$d))`, "2"},
		{"composite NaN", `<xsl:key name="k" match="n" use="xs:double('NaN')" composite="yes"/>`, `count(key('k',xs:double('NaN'),$d))`, "2"},
		{"composite array specifier", `<xsl:key name="k" match="n" use="[@k,[]]" composite="yes"/>`, `count(key('k',['a'],$d))`, "1"},
		{"composite ignores backwards compatibility", `<xsl:key name="k" match="n" use="2" composite="yes" version="1.0"/>`, `count(key('k','2',$d))`, "0"},
		{"composite numeric duplicates", `<xsl:key name="k" match="n" use="16777217" composite="yes"/><xsl:key name="k" match="n" use="xs:float(16777216)" composite="yes"/>`, `count(key('k',xs:float(16777216),$d))`, "2"},
		{"ordinary empty sequence", ordinaryKey, `count(key('k',(),$d))`, "0"},
		{"ordinary NaN", `<xsl:key name="k" match="n" use="xs:double('NaN')"/>`, `count(key('k',xs:double('NaN'),$d))`, "0"},
		{"numeric bucket collision", `<xsl:key name="k" match="n" use="(9007199254740992,9007199254740993)"/>`, `count(key('k',9007199254740993,$d))`, "2"},
		{"numeric float promotion", `<xsl:key name="k" match="n" use="16777217"/>`, `count(key('k',xs:float(16777216),$d))`, "2"},
		{"numeric signed zero", `<xsl:key name="k" match="n" use="xs:double('-0')"/>`, `count(key('k',0,$d))`, "2"},
		{"nontransitive numeric equality", `<xsl:key name="k" match="n" use="(16777217,xs:float(16777216))"/>`, `count(key('k',16777216,$d))`, "2"},
		{"map key specifier", `<xsl:key name="k" match="n" use="map{}"/>`, `key('k','a',$d)`, "FOTY0013"},
		{"composite map specifier", `<xsl:key name="k" match="n" use="map{}" composite="yes"/>`, `key('k',(),$d)`, "FOTY0013"},
		{"array specifier", `<xsl:key name="k" match="n" use="[[@k],[],['z']]"/>`, `count(key('k','z',$d))`, "2"},
		{"key focus", `<xsl:key name="k" match="n" use="position() + last()"/>`, `(1 to 3) ! count(key('k',2,$d))`, "2 2 2"},
		{"key global variable scope", `<xsl:variable name="v" select="'a'"/><xsl:key name="k" match="n" use="$v"/>`, `let $v := 'b' return count(key('k','a',$d))`, "2"},
		{"key self-reference in use", `<xsl:key name="k" match="n" use="key('k',@k)"/>`, `count(key('k','a',$d))`, errCodeXTDE0640},
		{"key mutual use-reference", `<xsl:key name="k" match="n" use="key('other',@k)"/><xsl:key name="other" match="n" use="key('k',@k)"/>`, `count(key('k','a',$d))`, errCodeXTDE0640},
		{"key self-reference in body", `<xsl:key name="k" match="n"><xsl:sequence select="key('k',@k)"/></xsl:key>`, `count(key('k','a',$d))`, errCodeXTDE0640},
		{"key self-reference in match", `<xsl:key name="k" match="n[exists(key('k',@k))]" use="@k"/>`, `count(key('k','a',$d))`, errCodeXTDE0640},
		{"key reference through function", `<xsl:key name="k" match="n" use="p:key(.)"/><xsl:function name="p:key"><xsl:param name="n"/><xsl:sequence select="key('k',$n/@k,root($n))"/></xsl:function>`, `count(key('k','a',$d))`, errCodeXTDE0640},
		{"unevaluated key self-reference", `<xsl:key name="k" match="n" use="if (false()) then key('k',@k) else @k"/>`, `count(key('k','a',$d))`, "1"},
		{"unused circular key", `<xsl:key name="k" match="n" use="key('k',@k)"/>`, `'ok'`, "ok"},
		{"different document key reference", `<xsl:key name="k" match="n" use="if (@id) then key('k','a',parse-xml('&lt;r>&lt;n k=&quot;a&quot;/>&lt;/r>'))/@k else @k"/>`, `count(key('k','a',$d))`, "2"},
	} {
		using := packageSheet(`name="urn:binding-user"`, documentValue+test.declarations+`<xsl:template name="start" visibility="public"><xsl:value-of select="`+test.expression+`"/></xsl:template>`)

		var oracleWant string
		// REC §20.2.2 uses deep-equal for composite keys and excludes them
		// from backwards-compatible key conversion. Keep Saxon's differences visible.
		switch test.name {
		case "composite NaN":
			oracleWant = "0"
		case "composite ignores backwards compatibility":
			oracleWant = "2"
		case "numeric float promotion":
			oracleWant = "0"
		}

		tests = append(tests, packageBindingCase{test.name, packageSheet(`name="urn:binding-library"`, ""), using, test.want, oracleWant})
	}

	for _, function := range []string{`key#3`, `fn:key#3`, `key(?,?,?)`, `function-lookup(QName('http://www.w3.org/2005/xpath-functions','key'),3)`, `function($name,$value,$node){key($name,$value,$node)}`} {
		library := packageSheet(`name="urn:binding-library" xmlns:x="urn:library-key" xmlns:fn="http://www.w3.org/2005/xpath-functions"`, `<xsl:key name="x:k" match="n" use="'L'"/><xsl:function name="p:lookup" visibility="public"><xsl:sequence select="`+function+`"/></xsl:function>`)
		using := packageSheet(`name="urn:binding-user" xmlns:x="urn:other-key"`, `<xsl:use-package name="urn:binding-library"/>`+documentValue+`<xsl:key name="x:k" match="n" use="'U'"/><xsl:template name="start" visibility="public"><xsl:variable name="f" select="p:lookup()"/><xsl:value-of select="count($f('x:k','L',$d))"/></xsl:template>`)
		tests = append(tests, packageBindingCase{"key reference " + function, library, using, "2", ""})
	}

	for _, test := range []struct{ name, declarations, body, want string }{
		{"key declaration local namespaces", `<xsl:key name="k" match="n" xmlns:x="urn:local" use="x:v"/>`, `<xsl:value-of select="count(key('k','a',parse-xml('&lt;r xmlns:l=&quot;urn:local&quot;>&lt;n>&lt;l:v>a&lt;/l:v>&lt;/n>&lt;/r>')))"/>`, "1"},
		{"key use default namespace", `<xsl:key name="k" match="n" xpath-default-namespace="urn:local" use="v"/>`, `<xsl:value-of select="count(key('k','a',parse-xml('&lt;r xmlns=&quot;urn:local&quot;>&lt;n>&lt;v>a&lt;/v>&lt;/n>&lt;/r>')))"/>`, "1"},
		{"key lexical QName", `<xsl:key xmlns:x="urn:local" name="x:k" match="n" use="@k"/>`, `<xsl:value-of xmlns:x="urn:local" select="count(key('x:k','a',$d))"/>`, "1"},
		{"key ignores template locals", `<xsl:variable name="v" select="'a'"/><xsl:key name="k" match="n" use="$v"/>`, `<xsl:variable name="v" select="'b'"/><xsl:value-of select="count(key('k','a',$d))"/>`, "2"},
		{"key declaration base URI", `<xsl:key xml:base="https://example.org/keys/" name="k" match="n" use="static-base-uri()"/>`, `<xsl:value-of select="count(key('k','https://example.org/keys/',$d))"/>`, "2"},
		{"key missing current template", `<xsl:key name="k" match="n"><xsl:next-match/></xsl:key>`, `<xsl:value-of select="count(key('k','a',$d))"/>`, "XTDE0560"},
		{"undeclared standard prefix", ordinaryKey, `<xsl:value-of select="fn:count(key('k','a',$d))"/>`, errCodeXPST0081},
		{"sibling namespace does not leak", `<xsl:variable xmlns:z="urn:sibling" name="v" select="'a'"/>`, `<xsl:value-of select="z:missing()"/>`, errCodeXPST0081},
	} {
		using := packageSheet(`name="urn:binding-user" xmlns:x="urn:unrelated"`, documentValue+test.declarations+`<xsl:template name="start" visibility="public">`+test.body+`</xsl:template>`)
		tests = append(tests, packageBindingCase{test.name, packageSheet(`name="urn:binding-library"`, ""), using, test.want, ""})
	}

	return tests
}

func lexicalModeCases() []packageBindingCase {
	const (
		unknownMode = "#unknown"
		nbspMode    = "p:m&#160;"
		selectNode  = `<xsl:apply-templates select="parse-xml('&lt;n/>')/*" mode="#default"/>`
		localMode   = `<xsl:mode name="p:m"/>`
	)

	var tests []packageBindingCase

	add := func(name, attributes, body, want string) {
		tests = append(tests, packageBindingCase{name, packageSheet(`name="urn:binding-library"`, ""), packageSheet(`name="urn:binding-user" `+attributes, body), want, ""})
	}
	for _, token := range []string{"", ` mode="#default"`} {
		add("root default mode "+token, `default-mode="p:m"`, localMode+`<xsl:template match="n"`+token+`>L</xsl:template><xsl:template name="start" visibility="public">`+selectNode+`</xsl:template>`, "L")
	}

	add("default QName retains ancestor binding", `default-mode="p:m"`, localMode+`<xsl:template xmlns:p="urn:shadow" match="n" mode="#default">L</xsl:template><xsl:template name="start" visibility="public">`+selectNode+`</xsl:template>`, "L")
	add("literal result default retains binding", "", localMode+`<xsl:template match="n" mode="p:m">L</xsl:template><xsl:template name="start" visibility="public"><out xsl:default-mode="p:m"><xsl:apply-templates xmlns:p="urn:shadow" select="parse-xml('&lt;n/>')/*" mode="#default"/></out></xsl:template>`, "L")
	add("template default selects its own rule", "", localMode+`<xsl:template match="n" default-mode="p:m" mode="#default">L</xsl:template><xsl:template name="start" visibility="public" default-mode="p:m">`+selectNode+`</xsl:template>`, "L")
	add("URI qualified mode with colon", "", `<xsl:mode name="Q{urn:colon:mode}m"/><xsl:template match="n" mode="Q{urn:colon:mode}m">L</xsl:template><xsl:template name="start" visibility="public" default-mode="Q{urn:colon:mode}m">`+selectNode+`</xsl:template>`, "L")
	add("unnamed override of root default", `default-mode="p:m"`, localMode+`<xsl:mode/><xsl:template match="n" default-mode="#unnamed" mode="#default">L</xsl:template><xsl:template name="start" visibility="public" default-mode="#unnamed">`+selectNode+`</xsl:template>`, "L")

	for _, visibility := range []string{`abstract`, `hidden`, ""} {
		add("invalid mode visibility "+visibility, "", `<xsl:mode name="p:m" visibility="`+visibility+`"/><xsl:template name="start" visibility="public"/>`, errCodeXTSE0020)
	}

	for _, token := range []string{"", "#default", "#current", "#all", unknownMode, "bad name", nbspMode} {
		add("invalid default mode "+token, `default-mode="`+token+`"`, `<xsl:template name="start" visibility="public"/>`, errCodeXTSE0020)
		add("invalid declaration mode "+token, "", `<xsl:mode name="`+token+`"/><xsl:template name="start" visibility="public"/>`, errCodeXTSE0020)
	}

	for _, token := range []string{"", "#all", unknownMode, "p:m p:other", nbspMode} {
		add("invalid apply mode "+token, "", `<xsl:template name="start" visibility="public"><xsl:apply-templates select="()" mode="`+token+`"/></xsl:template>`, errCodeXTSE0020)
	}

	for _, token := range []string{"#current", unknownMode, nbspMode} {
		add("invalid template mode "+token, "", `<xsl:template match="n" mode="`+token+`"/><xsl:template name="start" visibility="public"/>`, "XTSE0550")
	}

	for _, attribute := range []string{`default-mode="bad:m"`, ""} {
		body := `<xsl:template name="start" visibility="public"/>`
		if attribute == "" {
			body = `<xsl:mode name="bad:m"/>` + body
		}

		add("undeclared mode prefix "+attribute, attribute, body, errCodeXTSE0280)
	}

	add("default mode requires declaration", `default-mode="p:missing"`, `<xsl:template name="start" visibility="public"/>`, "XTSE3085")
	add("literal default mode requires declaration", "", `<xsl:template name="start" visibility="public"><out xsl:default-mode="p:missing"/></xsl:template>`, "XTSE3085")

	return tests
}

func TestModuleDefaultModeScopes(t *testing.T) {
	for _, kind := range []string{"include", "import"} {
		for _, mode := range []string{"#unnamed", "part"} {
			part := strings.Replace(sheet(version30, `<xsl:template match="n">I</xsl:template>`), `version="3.0"`, `version="3.0" default-mode="`+mode+`"`, 1)
			if mode == "#unnamed" {
				part = strings.Replace(part, ` default-mode="#unnamed"`, "", 1)
			}

			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if uri != "urn:mode-part" {
					return nil, transform.ErrResource
				}

				return io.NopCloser(strings.NewReader(part)), ctx.Err()
			})})

			source := strings.Replace(sheet(version30, `<xsl:`+kind+` href="urn:mode-part"/><xsl:template match="n">U</xsl:template><xsl:template name="start"><xsl:variable name="n" select="parse-xml('&lt;n/>')/*"/><xsl:apply-templates select="$n" mode="`+mode+`"/><xsl:apply-templates select="$n" mode="#default"/></xsl:template>`), `version="3.0"`, `version="3.0" default-mode="main"`, 1)
			if kind == "import" {
				source = strings.Replace(source, `<xsl:output method="text"/><xsl:import href="urn:mode-part"/>`, `<xsl:import href="urn:mode-part"/><xsl:output method="text"/>`, 1)
			}

			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, source, nested)
				if err != nil || got != "IU" {
					t.Fatal(kind, mode, nested, got, err)
				}
			}
		}
	}
}

func packageOverrideCases() []packageBindingCase {
	tests := make([]packageBindingCase, 0, 18)

	for _, test := range []struct{ name, base, override, invoke, want string }{
		{"function argument", `<xsl:function name="p:f" as="xs:integer" visibility="public"><xsl:param name="x" as="xs:integer"/><xsl:sequence select="$x"/></xsl:function>`, `<xsl:function name="p:f" as="xs:integer"><xsl:param name="x" as="xs:string"/><xsl:sequence select="1"/></xsl:function>`, "", errCodeXTSE3070},
		{"function return", `<xsl:function name="p:f" as="xs:integer" visibility="public"><xsl:sequence select="1"/></xsl:function>`, `<xsl:function name="p:f" as="xs:string"><xsl:sequence select="'x'"/></xsl:function>`, "", errCodeXTSE3070},
		{"function missing arity", `<xsl:function name="p:f" visibility="public"><xsl:param name="x"/></xsl:function>`, emptyPackageFunction, "", "XTSE3058"},
		{"function return default", `<xsl:function name="p:f" as="xs:integer" visibility="public"><xsl:sequence select="1"/></xsl:function>`, emptyPackageFunction, "", errCodeXTSE3070},
		{"function new-each-time", `<xsl:function name="p:f" new-each-time="yes" visibility="public"/>`, `<xsl:function name="p:f" new-each-time="no"/>`, "", errCodeXTSE3070},
		{"function final", `<xsl:function name="p:f" visibility="final"/>`, emptyPackageFunction, "", "XTSE3060"},
		{"template missing parameter", `<xsl:template name="p:t" visibility="public"><xsl:param name="x"/></xsl:template>`, emptyPackageTemplate, "", errCodeXTSE3070},
		{"template tunnel parameter", `<xsl:template name="p:t" visibility="public"><xsl:param name="x"/></xsl:template>`, `<xsl:template name="p:t"><xsl:param name="x" tunnel="yes"/></xsl:template>`, "", errCodeXTSE3070},
		{"template required parameter", `<xsl:template name="p:t" visibility="public"><xsl:param name="x" required="yes"/></xsl:template>`, `<xsl:template name="p:t"><xsl:param name="x"/></xsl:template>`, "", errCodeXTSE3070},
		{"template return default", `<xsl:template name="p:t" visibility="public" as="xs:integer"><xsl:sequence select="1"/></xsl:template>`, emptyPackageTemplate, "", errCodeXTSE3070},
		{"template context", `<xsl:template name="p:t" visibility="public"><xsl:context-item use="required"/></xsl:template>`, emptyPackageTemplate, "", errCodeXTSE3070},
		{"template final", `<xsl:template name="p:t" visibility="final"/>`, emptyPackageTemplate, "", "XTSE3060"},
		{"template empty pattern", `<xsl:mode name="p:m" visibility="public"/><xsl:template name="p:t" visibility="public" match="n" mode="p:m"/>`, `<xsl:template name="p:t" match="" mode="p:m"/>`, "", "XTSE0340"},
		{"template invalid union pattern", `<xsl:mode name="p:m" visibility="public"/><xsl:template name="p:t" visibility="public" match="n" mode="p:m"/>`, `<xsl:template name="p:t" match="n |" mode="p:m"/>`, "", "XTSE0340"},
		{"template valid union pattern", `<xsl:mode name="p:m" visibility="public"/><xsl:template name="p:t" visibility="public" match="n" mode="p:m"/>`, `<xsl:template name="p:t" match="n | m" mode="p:m">ok</xsl:template>`, packageTemplateInvocation, "ok"},
		{"variable required type", `<xsl:variable name="p:v" as="xs:integer" visibility="public" select="1"/>`, `<xsl:variable name="p:v"/>`, "", errCodeXTSE3070},
		{"same type aliases", `<xsl:function xmlns:a="http://www.w3.org/2001/XMLSchema" name="p:f" as="a:integer" visibility="public"><xsl:sequence select="1"/></xsl:function>`, `<xsl:function xmlns:b="http://www.w3.org/2001/XMLSchema" name="p:f" as="b:integer"><xsl:sequence select="2"/></xsl:function>`, packageFunctionInvocation, "2"},
		{"template context defaults", `<xsl:template name="p:t" visibility="public"/>`, `<xsl:template name="p:t"><xsl:context-item as="item()" use="optional"/>ok</xsl:template>`, packageTemplateInvocation, "ok"},
	} {
		library := packageSheet(`name="urn:binding-library"`, test.base)
		using := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"><xsl:override>`+test.override+`</xsl:override></xsl:use-package><xsl:template name="start" visibility="public">`+test.invoke+`</xsl:template>`)
		tests = append(tests, packageBindingCase{test.name, library, using, test.want, ""})
	}

	return tests
}

func packageGlobalCases() []packageBindingCase {
	var tests []packageBindingCase
	add := func(name, base, override, body, want string) {
		library := packageSheet(`name="urn:binding-library"`, base+`<xsl:template name="p:run" visibility="public"><xsl:value-of select="$p:v"/></xsl:template>`)
		use := `<xsl:use-package name="urn:binding-library">`
		if override != "" {
			use += `<xsl:override>` + override + `</xsl:override>`
		}
		if body == "" {
			body = `<xsl:template name="start" visibility="public">accepted</xsl:template>`
		}
		using := packageSheet(`name="urn:binding-user"`, use+`</xsl:use-package>`+body)
		var oracleWant string
		// Separate REC 3.5.3.3/3.5.3.4/9.5 diagnostics from exact agreements.
		switch name {
		case "param original variable", "param original param", "param abstract original":
			oracleWant = errCodeXTSE0650
		case "variable abstract original":
			oracleWant = errCodeXTDE3052
		case "param overrides static":
			oracleWant = "accepted"
		case "static param remains local":
			oracleWant = "XTSE3050"
		case "override param conflicts local variable", "override param conflicts local param":
			oracleWant = "XTSE0630"
		case "inline function keeps original global":
			oracleWant = "diagnostic:java.lang.AssertionError: Target of component reference variable xsl:original is undefined"
		}
		tests = append(tests, packageBindingCase{name, library, using, want, oracleWant})
	}
	const startValue = `<xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/><xsl:value-of select="$p:v"/></xsl:template>`
	for _, baseKind := range []string{"variable", "param"} {
		visibility := ""
		if baseKind == "variable" {
			visibility = ` visibility="public"`
		}
		base := `<xsl:` + baseKind + ` name="p:v" as="xs:integer"` + visibility + ` select="1"/>`
		for _, kind := range []string{"variable", "param"} {
			add(kind+" overrides "+baseKind, base, `<xsl:`+kind+` name="p:v" as="xs:integer" select="2"/>`, startValue, "22")
			add(kind+" original "+baseKind, base, `<xsl:`+kind+` name="p:v" as="xs:integer" select="$xsl:original + 1"/>`, startValue, "22")
			add(kind+" incompatible "+baseKind, base, `<xsl:`+kind+` name="p:v" as="xs:string" select="'x'"/>`, "", errCodeXTSE3070)
		}
	}
	for _, visibility := range []string{"private", "final"} {
		add("param overrides "+visibility, `<xsl:variable name="p:v" as="xs:integer" visibility="`+visibility+`" select="1"/>`, `<xsl:param name="p:v" as="xs:integer" select="2"/>`, "", "XTSE3060")
	}
	add("param overrides static", `<xsl:param name="p:v" as="xs:integer" static="yes" select="1"/>`, `<xsl:param name="p:v" as="xs:integer" select="2"/>`, "", "XTSE3060")
	add("overridden required param removed", `<xsl:param name="p:v" as="xs:integer" required="yes"/>`, `<xsl:variable name="p:v" as="xs:integer" select="2"/>`, startValue, "22")
	add("original actual cycle", `<xsl:variable name="p:v" as="xs:integer" visibility="public" select="p:recursive()"/><xsl:function name="p:recursive"><xsl:sequence select="$p:v"/></xsl:function>`, `<xsl:variable name="p:v" as="xs:integer" select="$xsl:original + 1"/>`, startValue, "XTDE0640")
	for _, kind := range []string{"variable", "param"} {
		add(kind+" abstract original", `<xsl:variable name="p:v" as="xs:integer" visibility="abstract"/>`, `<xsl:`+kind+` name="p:v" as="xs:integer" select="$xsl:original"/>`, startValue, "XTSE3075")
	}
	add("param default private function", `<xsl:function name="p:value"><xsl:sequence select="'L'"/></xsl:function><xsl:param name="p:v" select="p:value()"/>`, "", `<xsl:function name="p:value"><xsl:sequence select="'U'"/></xsl:function>`+startValue, "LL")
	add("homonymous global dependency", `<xsl:variable name="p:v" select="'L'"/><xsl:function name="p:value" visibility="public"><xsl:sequence select="$p:v"/></xsl:function>`, "", `<xsl:variable name="p:v" select="p:value()||'U'"/>`+startValue, "LLU")
	add("static param remains local", `<xsl:param name="p:v" static="yes" select="'L'"/>`, "", `<xsl:param name="p:v" select="'U'"/>`+startValue, "LU")
	add("library parameter lacks position", `<xsl:param name="p:v" select="position()"/>`, "", startValue, "XPDY0002")
	add("library variable lacks size", `<xsl:global-context-item use="optional"/><xsl:variable name="p:v" visibility="public" select="last()"/>`, "", startValue, "XPDY0002")
	add("library cannot see caller globals", `<xsl:variable name="p:v" select="$p:leaked"/>`, "", `<xsl:variable name="p:leaked" select="'secret'"/>`+startValue, "XPST0008")
	add("accepted node identity", `<xsl:variable name="p:v" visibility="public" as="element()"><n/></xsl:variable><xsl:function name="p:get" visibility="public"><xsl:sequence select="$p:v"/></xsl:function>`, "", `<xsl:template name="start" visibility="public"><xsl:value-of select="p:get() is $p:v"/></xsl:template>`, nameTrue)
	add("original node identity", `<xsl:variable name="p:v" visibility="public" as="element()*"><n/></xsl:variable>`, `<xsl:variable name="p:v" as="element()*" select="($xsl:original,$xsl:original)"/>`, `<xsl:template name="start" visibility="public"><xsl:value-of select="$p:v[1] is $p:v[2]"/></xsl:template>`, nameTrue)
	add("global declaration type namespace", `<xsl:variable xmlns:a="http://www.w3.org/2001/XMLSchema" name="p:v" visibility="public" as="a:integer" select="1"/>`, "", startValue, "11")
	add("global declaration default namespace", `<xsl:variable name="p:v" visibility="public" as="element(n)" xpath-default-namespace="urn:local"><n xmlns="urn:local">L</n></xsl:variable>`, "", startValue, "LL")
	add("inline function keeps global package", `<xsl:variable name="p:v" select="'L'"/><xsl:function name="p:get" visibility="public"><xsl:sequence select="function(){ $p:v }"/></xsl:function>`, "", `<xsl:variable name="p:v" select="'U'"/><xsl:template name="start" visibility="public"><xsl:value-of select="(p:get())()"/></xsl:template>`, "L")
	add("inline function keeps original global", `<xsl:variable name="p:v" visibility="public" as="function(*)" select="function(){'L'}"/>`, `<xsl:variable name="p:v" as="function(*)" select="function(){ $xsl:original()||'U' }"/>`, `<xsl:template name="start" visibility="public"><xsl:value-of select="($p:v(),$p:v())"/></xsl:template>`, "LU LU")

	for _, kind := range []string{"variable", "param"} {
		base := `<xsl:` + kind + ` name="p:v" select="1"/>`
		if kind == "variable" {
			base = `<xsl:variable name="p:v" visibility="public" select="1"/>`
		}
		add("local param conflicts "+kind, base, "", `<xsl:param name="p:v" select="2"/>`, "XTSE3050")
		add("override param conflicts local "+kind, base, `<xsl:param name="p:v" select="2"/>`, `<xsl:`+kind+` name="p:v" select="3"/>`, "XTSE3055")
	}
	return tests
}

func TestApplicationFunctionTypes(t *testing.T) {
	calls := 0
	e := engine(t, transform.Config{Functions: []transform.Function{{Name: transform.Name{Space: "urn:callback", Local: "echo"}, Arity: 1, Call: func(_ context.Context, args []transform.Sequence) (transform.Sequence, error) {
		calls++
		return args[0], nil
	}}}})
	for _, reference := range []string{`Q{urn:callback}echo#1`, `Q{urn:callback}echo(?)`, `function-lookup(QName('urn:callback','echo'),1)`} {
		for _, test := range []struct{ result, want string }{{`item()*`, nameTrue}, {`xs:string`, nameFalse}} {
			expression := reference + ` instance of function(xs:string) as ` + test.result
			if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != test.want {
				t.Fatal(expression, got, test.want)
			}
			source := sheet(version30, `<xsl:template name="start">`+valueOfExpression(expression)+`</xsl:template>`)
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, source, nested)
				if err != nil || got != test.want {
					t.Fatal(expression, nested, got, err, test.want)
				}
			}
		}
	}
	if calls != 0 {
		t.Fatal("type inspection invoked the callback", calls)
	}
	expression := `(function($f as function(xs:string) as xs:string){$f('ok')})(Q{urn:callback}echo#1)`
	if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "ok" {
		t.Fatal(got)
	}
}

func TestProactiveFunctionCallback(t *testing.T) {
	for _, each := range []string{"", ` new-each-time="yes"`} {
		for _, nested := range []bool{false, true} {
			calls := 0
			e := engine(t, transform.Config{Functions: []transform.Function{{Name: transform.Name{Space: "urn:callback", Local: "next"}, Arity: 0, Call: func(context.Context, []transform.Sequence) (transform.Sequence, error) {
				calls++
				return transform.Values(transform.Integer(int64(calls))), nil
			}}}})

			source := packageSheet("", `<xsl:function name="p:f" cache="yes"`+each+`><xsl:sequence select="Q{urn:callback}next()"/></xsl:function><xsl:template name="start" visibility="public"><xsl:value-of select="(p:f(),p:f())"/></xsl:template>`)

			got, err := resourceStylesheetResult(t, e, source, nested)
			if err != nil || got != integerPairText || calls != 2 {
				t.Fatal(each, nested, got, calls, err)
			}
		}
	}
}

func TestProactiveOriginalFunctionBindings(t *testing.T) {
	for _, nested := range []bool{false, true} {
		calls := 0
		library := packageSheet(`name="urn:binding-library"`, `<xsl:function name="p:f" visibility="public" cache="yes" as="xs:integer"><xsl:param name="n" as="xs:integer"/><xsl:sequence select="if ($n=0) then 1 else p:f($n - 1)"/></xsl:function><xsl:function name="p:original" visibility="public"><xsl:sequence select="function-lookup(QName('urn:components','f'),1)"/></xsl:function>`)
		e := engine(t, transform.Config{Functions: []transform.Function{{Name: transform.Name{Space: "urn:callback", Local: "next"}, Arity: 0, Call: func(context.Context, []transform.Sequence) (transform.Sequence, error) {
			calls++
			return transform.Values(transform.Integer(int64(calls))), nil
		}}}, PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
			return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
		})})
		source := packageSheet("", `<xsl:use-package name="urn:binding-library"><xsl:override><xsl:function name="p:f" as="xs:integer"><xsl:param name="n" as="xs:integer"/><xsl:sequence select="Q{urn:callback}next()"/></xsl:function></xsl:override></xsl:use-package><xsl:template name="start" visibility="public"><xsl:variable name="original" select="p:original()"/><xsl:value-of select="($original(2),$original(2))"/></xsl:template>`)

		got, err := resourceStylesheetResult(t, e, source, nested)
		if err != nil || got != integerPairText || calls != 2 {
			t.Fatal(nested, got, calls, err)
		}
	}
}

func TestPackageBindings(t *testing.T) {
	for _, test := range packageBindingCases() {
		t.Run(test.name, func(t *testing.T) {
			e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
				if name != "urn:binding-library" {
					return transform.PackageResource{}, transform.ErrResource
				}

				return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(test.library))}, ctx.Err()
			})})
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, test.using, nested)
				if !comparisonErrorCode(test.want) {
					if err != nil || got != test.want {
						t.Fatal(nested, got, err)
					}

					continue
				}

				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

type packageGlobalChainCase struct {
	name, using, want, oracleWant string
	libraries                     map[string]string
}

func packageGlobalChainCases() []packageGlobalChainCase {
	const base = `<xsl:function name="p:secret"><xsl:sequence select="'L'"/></xsl:function><xsl:variable name="p:v" visibility="public" as="xs:string" select="p:secret()"/><xsl:template name="p:run" visibility="public"><xsl:value-of select="$p:v"/></xsl:template>`
	const accept = `<xsl:accept component="template" names="p:run" visibility="public"/>`
	const body = `<xsl:function name="p:secret"><xsl:sequence select="'U'"/></xsl:function><xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/><xsl:value-of select="$p:v"/></xsl:template>`
	tests := make([]packageGlobalChainCase, 0, 4)
	for _, test := range []struct{ name, middle, main, want, oracle string }{
		{"reexport preserves lexical owner", `<xsl:accept component="variable" names="p:v" visibility="public"/>`, "", "LL", ""},
		{"three variable overrides", `<xsl:override><xsl:variable name="p:v" visibility="public" as="xs:string" select="$xsl:original||'M'"/></xsl:override>`, `<xsl:override><xsl:variable name="p:v" as="xs:string" select="$xsl:original||'U'"/></xsl:override>`, "LMULMU", ""},
		{"three mixed overrides", `<xsl:override><xsl:param name="p:v" as="xs:string" select="$xsl:original||'M'"/></xsl:override>`, `<xsl:override><xsl:variable name="p:v" as="xs:string" select="$xsl:original||'U'"/></xsl:override>`, "LMULMU", errCodeXTSE0650},
		{"override defaults private", `<xsl:override><xsl:variable name="p:v" as="xs:string" select="$xsl:original||'M'"/></xsl:override>`, "", "LMU", ""},
	} {
		middle := packageSheet(`name="urn:binding-middle"`, `<xsl:use-package name="urn:binding-library">`+accept+test.middle+`</xsl:use-package>`)
		usingBody := `<xsl:use-package name="urn:binding-middle">` + test.main + `</xsl:use-package>` + body
		if test.name == "override defaults private" {
			usingBody += `<xsl:variable name="p:v" select="'U'"/>`
		}
		tests = append(tests, packageGlobalChainCase{test.name, packageSheet(`name="urn:binding-user"`, usingBody), test.want, test.oracle, map[string]string{"urn:binding-library": packageSheet(`name="urn:binding-library"`, base), "urn:binding-middle": middle}})
	}
	return tests
}

func TestPackageGlobalChains(t *testing.T) {
	for _, test := range packageGlobalChainCases() {
		e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
			source, ok := test.libraries[name]
			if !ok {
				return transform.PackageResource{}, transform.ErrResource
			}
			return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(source))}, ctx.Err()
		})})
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, test.using, nested)
			if err != nil || got != test.want {
				t.Fatal(test.name, nested, got, err, test.want)
			}
		}
	}
}

func TestPackageGlobalParameters(t *testing.T) {
	library := packageSheet(`name="urn:binding-library"`, `<xsl:param xmlns:a="http://www.w3.org/2001/XMLSchema" name="p:v" as="a:string" select="'L'"/><xsl:template name="p:run" visibility="public"><xsl:value-of select="$p:v"/></xsl:template>`)
	e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
		return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
	})})
	for _, override := range []string{"", `<xsl:override><xsl:param name="p:v" as="xs:string" select="$xsl:original||'M'"/></xsl:override>`} {
		source := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library">`+override+`</xsl:use-package><xsl:template name="start" visibility="public"><xsl:call-template name="p:run"/><xsl:value-of select="$p:v"/></xsl:template>`)
		compiled := stylesheet(t, e, source)
		for _, value := range []string{"A", "B"} {
			result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Space: "urn:components", Local: "v"}: transform.Values(transform.String(value))}})
			if err != nil || string(result.Primary) != value+value {
				t.Fatal(override, value, result, err)
			}
			q := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('','start'),'stylesheet-params':map{QName('urn:components','v'):$value},'delivery-format':'serialized'})?output`, transform.XPath31)
			resultValue, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source)), {Local: "value"}: transform.Values(transform.String(value))}})
			if err != nil || text(t, resultValue) != value+value {
				t.Fatal(override, value, resultValue, err)
			}
		}
	}
}

type packageModeCase struct {
	name, using, want string
	libraries         map[string]string
	oracleWant        string
	oracleDiagnostic  string
}

func packageModeCases() []packageModeCase {
	const (
		libraryName = "urn:mode-library"
		middleName  = "urn:mode-middle"
		publicMode  = `<xsl:mode name="p:m" visibility="public"/>`
		nodeCall    = `<xsl:apply-templates select="parse-xml('&lt;n>&lt;i/>&lt;/n>')/*" mode="p:m"/>`
		runCall     = `<xsl:call-template name="p:run"/>`
		libraryRule = `<xsl:template match="n" mode="p:m" priority="1000">L</xsl:template>`
	)

	var tests []packageModeCase

	add := func(name, library, use, local, body, want string) {
		tests = append(tests, packageModeCase{
			name: name, using: packageSheet(`name="urn:mode-user"`, `<xsl:use-package name="`+libraryName+`">`+use+`</xsl:use-package>`+local+`<xsl:template name="start" visibility="public">`+body+`</xsl:template>`), want: want,
			libraries: map[string]string{libraryName: packageSheet(`name="`+libraryName+`"`, library)},
		})
	}

	for _, visibility := range []string{visibilityPrivate, "public"} {
		accept := ""
		if visibility == "public" {
			accept = `<xsl:accept component="template" names="p:t" visibility="hidden"/>`
		}

		add("named "+visibility+" match", publicMode+`<xsl:template name="p:t" visibility="`+visibility+`" match="n" mode="p:m">L</xsl:template>`, accept, "", nodeCall, "L")
	}

	add("named override retains original rule", publicMode+`<xsl:template name="p:t" visibility="public" match="n" mode="p:m">L</xsl:template>`, `<xsl:override><xsl:template name="p:t">U</xsl:template></xsl:override>`, "", nodeCall+packageTemplateInvocation, "LU")

	for _, mode := range []string{"", ` name="p:m"`} {
		attribute := ""
		if mode != "" {
			attribute = ` mode="p:m"`
		}

		rules := `<xsl:mode` + mode + `/><xsl:template match="n"` + attribute + `>L</xsl:template>`
		probe := strings.ReplaceAll(nodeCall, ` mode="p:m"`, attribute)
		add("private mode"+mode, rules+`<xsl:template name="p:run" visibility="public">`+probe+`</xsl:template>`, "", strings.ReplaceAll(rules, ">L<", ">U<"), runCall+probe, "LU")
	}

	add("hidden mode homonym", publicMode+libraryRule+`<xsl:template name="p:run" visibility="public">`+nodeCall+`</xsl:template>`, `<xsl:accept component="mode" names="p:m" visibility="hidden"/>`, `<xsl:mode name="p:m"/><xsl:template match="n" mode="p:m">U</xsl:template>`, runCall+nodeCall, "LU")
	add("all modes stay in their declaring package", `<xsl:mode/>`+publicMode+`<xsl:template match="n" mode="#all">L</xsl:template>`, "", `<xsl:mode/><xsl:mode name="p:u"/><xsl:template match="n" mode="#all">U</xsl:template>`, nodeCall+strings.ReplaceAll(nodeCall, "p:m", "p:u"), "LU")

	tests[len(tests)-1].oracleDiagnostic = "java.lang.IllegalArgumentException: #all is not a real mode"

	add("package precedence before priority", publicMode+libraryRule, `<xsl:override><xsl:template match="n" mode="p:m" priority="50">H<xsl:next-match/></xsl:template><xsl:template match="n" mode="p:m" priority="-100">U<xsl:next-match/></xsl:template></xsl:override>`, "", nodeCall, "HUL")
	add("next-match from a used helper", publicMode+libraryRule+`<xsl:template name="p:next" visibility="public"><xsl:next-match/></xsl:template>`, `<xsl:override><xsl:template match="n" mode="p:m">U<xsl:call-template name="p:next"/></xsl:template></xsl:override>`, "", nodeCall, "UL")
	add("apply-imports within an override", publicMode+libraryRule, `<xsl:override><xsl:template match="n" mode="p:m">U<xsl:apply-imports/></xsl:template></xsl:override>`, "", nodeCall, "XTSE3460")
	add("current mode through a used helper", publicMode+`<xsl:template name="p:walk" visibility="public"><xsl:apply-templates mode="#current"/></xsl:template><xsl:template match="i" mode="p:m">L</xsl:template>`, `<xsl:override><xsl:template match="n" mode="p:m">U<xsl:call-template name="p:walk"/></xsl:template><xsl:template match="i" mode="p:m">I<xsl:next-match/></xsl:template></xsl:override>`, "", nodeCall, "UIL")
	add("built-in rules retain the bound mode", publicMode+`<xsl:template match="i" mode="p:m">L</xsl:template>`, `<xsl:override><xsl:template match="n" mode="p:m">U<xsl:next-match/></xsl:template></xsl:override>`, "", nodeCall, "UL")
	add("atomic rule lexical function scope", publicMode+`<xsl:function name="p:f"><xsl:sequence select="'L'"/></xsl:function><xsl:template name="p:t" match=".[. instance of xs:integer]" mode="p:m"><xsl:value-of select="p:f()"/></xsl:template>`, "", `<xsl:function name="p:f"><xsl:sequence select="'U'"/></xsl:function>`, `<xsl:apply-templates select="(1,2)" mode="p:m"/>`, "LL")
	add("predicate lexical function scope", publicMode+`<xsl:function name="p:f"><xsl:sequence select="true()"/></xsl:function><xsl:template match="n[p:f()]" mode="p:m">L</xsl:template>`, "", `<xsl:function name="p:f"><xsl:sequence select="false()"/></xsl:function>`, nodeCall, "L")
	add("apply-imports in an external helper", publicMode+libraryRule+`<xsl:template name="p:imports" visibility="public"><xsl:apply-imports/></xsl:template>`, `<xsl:override><xsl:template match="n" mode="p:m">U<xsl:call-template name="p:imports"/></xsl:template></xsl:override>`, "", nodeCall, "U")

	tests[len(tests)-1].oracleWant = "UL"

	add("hidden current mode across an overridden helper", publicMode+`<xsl:template name="p:walk" visibility="public"/><xsl:template name="p:run" visibility="public">`+nodeCall+`</xsl:template><xsl:template match="n" mode="p:m"><xsl:call-template name="p:walk"/></xsl:template><xsl:template match="i" mode="p:m">L</xsl:template>`, `<xsl:accept component="mode" names="p:m" visibility="hidden"/><xsl:override><xsl:template name="p:walk"><xsl:apply-templates mode="#current"/></xsl:template></xsl:override>`, `<xsl:mode name="p:m"/><xsl:template match="n" mode="p:m">U</xsl:template>`, runCall+nodeCall, "LU")

	for _, visibility := range []string{visibilityPrivate, "final"} {
		add("cannot extend "+visibility+" mode", strings.ReplaceAll(publicMode, `visibility="public"`, `visibility="`+visibility+`"`), `<xsl:override><xsl:template match="n" mode="p:m">U</xsl:template></xsl:override>`, "", nodeCall, "XTSE3060")
	}

	add("rebuild accepted mode index", publicMode+strings.Repeat(`<xsl:template match="n[false()]" mode="p:m"/>`, 20)+libraryRule, `<xsl:override><xsl:template match="n" mode="p:m" priority="-100">U<xsl:next-match/></xsl:template></xsl:override>`, "", nodeCall, "UL")

	for _, next := range []string{`<xsl:next-match/>`, `<xsl:apply-imports/>`} {
		declarations := func(value string) string {
			return `<xsl:function name="p:f"><xsl:sequence select="'` + value + `'"/></xsl:function>`
		}
		override := `<xsl:override><xsl:template match="n" mode="p:m"><xsl:value-of select="p:f()"/>` + next + `</xsl:template></xsl:override>`
		library := packageSheet(`name="`+libraryName+`"`, publicMode+declarations("Q")+`<xsl:template match="n" mode="p:m"><xsl:value-of select="p:f()"/></xsl:template><xsl:template name="p:run" visibility="public">`+nodeCall+`</xsl:template>`)
		middle := packageSheet(`name="`+middleName+`"`, `<xsl:use-package name="`+libraryName+`"><xsl:accept component="mode" names="p:m" visibility="public"/><xsl:accept component="template" names="p:run" visibility="public"/>`+override+`</xsl:use-package>`+declarations("P"))
		using := packageSheet(`name="urn:mode-user"`, `<xsl:use-package name="`+middleName+`">`+override+`</xsl:use-package>`+declarations("R")+`<xsl:template name="start" visibility="public">`+runCall+`</xsl:template>`)

		want := "RPQ"
		if next == `<xsl:apply-imports/>` {
			want = "XTSE3460"
		}

		tests = append(tests, packageModeCase{name: "three-package chain " + next, using: using, want: want, libraries: map[string]string{libraryName: library, middleName: middle}})
	}

	tests = append(tests, packageModeCase{name: "homonymous accepted modes", using: packageSheet(`name="urn:mode-user"`, `<xsl:use-package name="`+libraryName+`"><xsl:accept component="mode" names="p:m" visibility="public"/></xsl:use-package><xsl:use-package name="`+middleName+`"><xsl:accept component="mode" names="p:m" visibility="public"/></xsl:use-package><xsl:template name="start" visibility="public">`+nodeCall+`</xsl:template>`), want: "XTSE3050", libraries: map[string]string{
		libraryName: packageSheet(`name="`+libraryName+`"`, publicMode+libraryRule), middleName: packageSheet(`name="`+middleName+`"`, publicMode+libraryRule),
	}})
	tests[len(tests)-1].oracleWant = "L"

	return tests
}

func TestPackageModeBindings(t *testing.T) {
	for _, test := range packageModeCases() {
		t.Run(test.name, func(t *testing.T) {
			e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
				if source, ok := test.libraries[name]; ok {
					return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(source))}, ctx.Err()
				}

				return transform.PackageResource{}, transform.ErrResource
			})})
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, test.using, nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}

					continue
				}

				if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

func TestPackageTemplateBindingVisibility(t *testing.T) {
	e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
		if name != "urn:template-library" {
			return transform.PackageResource{}, transform.ErrResource
		}

		return transform.PackageResource{BaseURI: "urn:template-source", Reader: io.NopCloser(strings.NewReader(`<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform" name="urn:template-library" package-version="1" version="3.0"><xsl:template name="helper" visibility="public">ok</xsl:template></xsl:package>`))}, ctx.Err()
	})})

	for _, hidden := range []bool{false, true} {
		source := sheet(version30, `<xsl:use-package name="urn:template-library"><xsl:accept component="template" names="helper" visibility="private"/></xsl:use-package><xsl:template name="start"><xsl:call-template name="helper"/></xsl:template>`)
		if hidden {
			source = strings.Replace(source, `visibility="private"`, `visibility="hidden"`, 1)
		}

		for _, nested := range []bool{false, true} {
			if !hidden {
				got, err := resourceStylesheetResult(t, e, source, nested)
				if err != nil || got != "ok" {
					t.Fatal(nested, got, err)
				}

				continue
			}

			var err error
			if nested {
				_, err = resourceStylesheetResult(t, e, source, true)
			} else {
				_, err = e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{})
			}

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXTSE0650 {
				t.Fatal(nested, err)
			}
		}
	}
}

func (f collectionResolverFixture) ResolveCollection(ctx context.Context, uri string) (transform.Sequence, error) {
	return f.collection(ctx, uri)
}

func (f collectionResolverFixture) ResolveURICollection(ctx context.Context, uri string) ([]string, error) {
	if f.uris == nil {
		return nil, transform.ErrResource
	}

	return f.uris(ctx, uri)
}

func TestErrorSourceLinesInModules(t *testing.T) {
	const module = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
<xsl:template name="raise">
<xsl:sequence select="1 idiv 0"/>
</xsl:template>
</xsl:stylesheet>`
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(module)), ctx.Err()
	})})
	for _, declaration := range []string{"include", "import"} {
		body := `<xsl:` + declaration + ` href="urn:line-module"/><xsl:template name="start"><xsl:try><xsl:call-template name="raise"/><xsl:catch xmlns:err="http://www.w3.org/2005/xqt-errors"><xsl:value-of select="concat($err:module, ':', $err:line-number)"/></xsl:catch></xsl:try></xsl:template>`
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, sheet(version30, body), nested)
			if err != nil || got != "urn:line-module:3" {
				t.Fatal(declaration, nested, got, err)
			}
		}
	}
}

func TestUseWhenDocumentAvailability(t *testing.T) {
	for _, version := range []string{version20, version30} {
		loads := 0
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
			loads++
			return io.NopCloser(strings.NewReader(`<r/>`)), ctx.Err()
		})})
		body := `<xsl:template name="start"><xsl:text use-when="doc-available('urn:probe')">static:</xsl:text><xsl:value-of select="doc-available('urn:probe')"/></xsl:template>`
		for _, nested := range []bool{false, true} {
			before := loads
			got, err := resourceStylesheetResult(t, e, sheet(version, body), nested)
			want, reads := "static:true", 2
			if version == version20 && !nested {
				want, reads = nameTrue, 1
			}
			if err != nil || got != want || loads-before != reads {
				t.Fatal(version, nested, got, err, loads-before, want, reads)
			}
		}
	}
}

func TestSourceDocumentIdentity(t *testing.T) {
	for _, uri := range []string{"urn:source-document", "file:///virtual/source.xml", "file:/virtual/source.xml", "file:///virtual/space%20name.xml"} {
		t.Run(uri, func(t *testing.T) {
			loads := 0
			loader := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				loads++
				return io.NopCloser(strings.NewReader(`<r/>`)), ctx.Err()
			})})
			value, ok := evaluate(t, loader, `doc('`+uri+`')`, transform.XPath31).At(0)
			if !ok {
				t.Fatal("missing source document")
			}
			node, ok := value.Node()
			if !ok {
				t.Fatal("source is not a node")
			}
			source := node.Document()
			for _, version := range []string{version20, version30} {
				program := sheet(version, `<xsl:template match="/"><xsl:value-of select="doc(document-uri(.)) is ."/><xsl:value-of select="document(document-uri(.)) is ."/></xsl:template>`)
				out, err := stylesheet(t, loader, program).Transform(t.Context(), source, transform.XSLTContext{})
				if err != nil || string(out.Primary) != "truetrue" || loads != 1 {
					t.Fatal(version, out, err, loads)
				}
				expression := `transform(map{'stylesheet-text':$stylesheet,'source-node':$source,'delivery-format':'serialized'})?output`
				result, err := query(t, loader, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
					{Local: variableStylesheet}: transform.Values(transform.String(program)),
					{Local: sourceName}:         transform.Values(value),
				}})
				if err != nil || text(t, result) != "truetrue" || loads != 1 {
					t.Fatal(version, result, err, loads)
				}
			}
		})
	}
}

func TestCollectionDocumentIdentity(t *testing.T) {
	const memberURI = "urn:collection-member"

	loader := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if uri != memberURI {
			return nil, transform.ErrResource
		}

		return io.NopCloser(strings.NewReader(`<r/>`)), ctx.Err()
	})})
	first := evaluate(t, loader, `doc('`+memberURI+`')`, transform.XPath31)
	second := evaluate(t, loader, `doc('`+memberURI+`')`, transform.XPath31)
	child := evaluate(t, loader, `doc('`+memberURI+`')/r`, transform.XPath31)
	firstValue, _ := first.At(0)
	secondValue, _ := second.At(0)
	loads, calls := 0, 0
	e := engine(t, transform.Config{
		Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
			loads++
			return io.NopCloser(strings.NewReader(`<r/>`)), ctx.Err()
		}),
		CollectionResolver: collectionResolverFixture{collection: func(ctx context.Context, uri string) (transform.Sequence, error) {
			calls++

			switch uri {
			case "urn:child":
				return child, ctx.Err()
			case "urn:conflict":
				return transform.Values(firstValue, secondValue), ctx.Err()
			default:
				return first, ctx.Err()
			}
		}},
	})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, expression := range []string{
			`collection('urn:members') is collection('urn:members')`,
			`for $d in collection('urn:members') return doc(document-uri($d)) is $d`,
			`for $n in collection('urn:child') return doc(document-uri(root($n))) is root($n)`,
			`for $f in collection#1 return $f('urn:members') is $f('urn:members')`,
		} {
			if version == transform.XPath20 && strings.Contains(expression, "#") {
				continue
			}

			before := calls
			if got := text(t, evaluate(t, e, expression, version)); got != nameTrue || calls != before+1 || loads != 0 {
				t.Fatal(version, expression, got, calls, loads)
			}
		}

		for _, expression := range []string{
			`collection('urn:conflict')`,
			`for $d in doc('` + memberURI + `') return count(collection('urn:members'))`,
		} {
			_, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != "FODC0003" {
				t.Fatal(version, expression, err)
			}
		}

		loads = 0
	}

	for _, version := range []string{version20, version30} {
		source := sheet(version, `<xsl:template name="start"><xsl:sequence select="collection('urn:conflict')"/></xsl:template>`)
		for _, nested := range []bool{false, true} {
			_, err := resourceStylesheetResult(t, e, source, nested)

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != "FODC0003" {
				t.Fatal(version, nested, err)
			}
		}
	}
}

func TestCollectionStabilityAcrossXSLT(t *testing.T) {
	loader := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r> <a/> </r>`)), ctx.Err()
	})})
	members := evaluate(t, loader, `doc('urn:member')`, transform.XPath31)
	collections, uris, loads := 0, 0, 0

	e := engine(t, transform.Config{
		CollectionResolver: collectionResolverFixture{
			collection: func(ctx context.Context, _ string) (transform.Sequence, error) {
				collections++
				return members, ctx.Err()
			},
			uris: func(ctx context.Context, _ string) ([]string, error) {
				uris++
				return []string{"urn:member"}, ctx.Err()
			},
		},
		Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			loads++
			return nil, transform.ErrResource
		}),
	})
	for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
		before := uris
		if got := text(t, evaluate(t, e, `deep-equal(uri-collection('urn:members'), uri-collection('urn:members'))`, version)); got != nameTrue || uris != before+1 {
			t.Fatal(version, got, uris, before)
		}
	}

	for _, version := range []string{version20, version30} {
		for _, strip := range []string{"", `<xsl:strip-space elements="*"/>`} {
			body := `<xsl:variable name="first" select="collection('urn:members')"/><xsl:value-of select="$first is collection('urn:members')"/><xsl:value-of select="doc(document-uri($first)) is $first"/>`
			want, uriCalls := "truetrue", 0

			if version == version30 {
				body += `<xsl:variable name="uris" select="uri-collection('urn:members')"/><xsl:value-of select="deep-equal($uris,uri-collection('urn:members'))"/>`
				want += nameTrue
				uriCalls = 1
			}

			source := sheet(version, strip+`<xsl:output method="text"/><xsl:template name="start">`+body+`</xsl:template>`)

			for _, nested := range []bool{false, true} {
				beforeCollections, beforeURIs := collections, uris

				got, err := resourceStylesheetResult(t, e, source, nested)
				if err != nil {
					t.Fatal(version, strip, nested, err)
				}

				if got != want || collections != beforeCollections+1 || uris != beforeURIs+uriCalls || loads != 0 {
					t.Fatal(version, strip, nested, got, collections, uris, loads)
				}
			}
		}
	}
}

func resourceStylesheetResult(t *testing.T, e *transform.Engine, source string, nested bool, assertions ...bool) (string, error) {
	t.Helper()

	if nested {
		option := ""
		if len(assertions) > 0 && assertions[0] {
			option = ",'enable-assertions':true()"
		}

		q := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('', 'start'),'delivery-format':'serialized'`+option+`})?output`, transform.XPath31)

		result, err := q.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
		if err != nil {
			return "", err
		}

		return text(t, result), nil
	}

	compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{})
	if err != nil {
		return "", err
	}

	result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		return "", err
	}

	return string(result.Primary), nil
}

func TestXPathTransformResources(t *testing.T) {
	source := sheet(version30, `<xsl:template name="start"><xsl:value-of select="unparsed-text('urn:payload')"/></xsl:template>`)

	for _, maxResources := range []int{1, 2} {
		var readers []*lifecycleReader

		e := engine(t, transform.Config{Limits: transform.Limits{MaxResources: maxResources}, Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			body := source

			switch uri {
			case "mem://suite/styles/main.xsl":
			case "urn:payload":
				body = "payload"
			default:
				return nil, transform.ErrResource
			}

			r := &lifecycleReader{Reader: strings.NewReader(body)}
			readers = append(readers, r)

			return r, ctx.Err()
		})})

		program, err := e.CompileXPath(t.Context(), `transform(map{'stylesheet-location':'styles/main.xsl','initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`, transform.XPathOptions{BaseURI: "mem://suite/query.xq"})
		if err != nil {
			t.Fatal(err)
		}

		result, err := program.Evaluate(t.Context(), nil, transform.XPathContext{})
		if maxResources == 1 {
			if !errors.Is(err, transform.ErrLimit) || result.Len() != 0 {
				t.Fatal("nested resource budget", result, err)
			}
		} else if err != nil || text(t, result) != "payload" {
			t.Fatal(result, err)
		}

		for _, reader := range readers {
			if !reader.closed {
				t.Fatal("resource reader was not closed")
			}
		}
	}

	failure := errors.New("stylesheet resolver failure")
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return nil, failure })})

	_, err := query(t, e, `transform(map{'stylesheet-location':'urn:missing'})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
	if !errors.Is(err, failure) || !errors.Is(err, transform.ErrResource) {
		t.Fatal("resolver cause was lost", err)
	}
}

func readWriteConflictCases() []struct{ name, body, data string } {
	return []struct{ name, body, data string }{
		{"doc", `<xsl:value-of select="doc('urn:shared')/r"/>`, `<r>1</r>`},
		{"doc reference", `<xsl:value-of select="(doc#1)('urn:shared')/r"/>`, `<r>1</r>`},
		{"document", `<xsl:value-of select="document('urn:shared')/r"/>`, `<r>1</r>`},
		{"doc available", `<xsl:value-of select="doc-available('urn:shared')"/>`, `<r>1</r>`},
		{"text", `<xsl:value-of select="unparsed-text('urn:shared')"/>`, "text"},
		{"text lookup", `<xsl:value-of select="function-lookup(QName('http://www.w3.org/2005/xpath-functions','unparsed-text'),1)('urn:shared')"/>`, "text"},
		{"text apply", `<xsl:value-of select="apply(unparsed-text#1,['urn:shared'])"/>`, "text"},
		{"text lines", `<xsl:value-of select="unparsed-text-lines('urn:shared')"/>`, "text\n"},
		{"text available", `<xsl:value-of select="unparsed-text-available('urn:shared')"/>`, "text"},
		{"JSON", `<xsl:value-of select="json-doc('urn:shared')?k"/>`, `{"k":1}`},
		{"source document", `<xsl:source-document href="urn:shared"><xsl:value-of select="r"/></xsl:source-document>`, `<r>1</r>`},
		{"evaluate text", `<xsl:evaluate xpath="&quot;unparsed-text('urn:shared')&quot;"/>`, "text"},
		{"parameter document", `<xsl:variable name="uri" select="'urn:shared'"/><xsl:result-document href="urn:other" parameter-document="{$uri}"><out/></xsl:result-document>`, `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"><indent value="no"/></serialization-parameters>`},
	}
}

func TestXSLTReadWriteConflicts(t *testing.T) {
	for _, test := range readWriteConflictCases() {
		for _, readFirst := range []bool{false, true} {
			for _, nested := range []bool{false, true} {
				var readers []*lifecycleReader
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
					if uri != "urn:shared" {
						return nil, transform.ErrResource
					}
					r := &lifecycleReader{Reader: strings.NewReader(test.data)}
					readers = append(readers, r)
					return r, ctx.Err()
				})})
				const write = `<xsl:result-document href="urn:shared"><out/></xsl:result-document>`
				body := write + test.body
				if readFirst {
					body = test.body + write
				}
				got, err := resourceStylesheetResult(t, e, sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`), nested)
				var detail *transform.Error
				if got != "" || !errors.As(err, &detail) || detail.Code != "XTDE1500" {
					t.Fatal(test.name, readFirst, nested, got, err)
				}
				for _, reader := range readers {
					if !reader.closed {
						t.Fatal(test.name, "reader not closed", reader.closed)
					}
				}
			}
		}
	}
}

func TestXSLTReadWriteRecovery(t *testing.T) {
	const catchCode = `<xsl:catch><xsl:value-of xmlns:err="http://www.w3.org/2005/xqt-errors" select="local-name-from-QName($err:code)"/></xsl:catch>`
	for _, test := range []struct{ name, body, data, want string }{
		{"cache survives rejected output", `<xsl:variable name="d" select="doc('urn:shared')"/><xsl:value-of select="$d/r"/><xsl:try><xsl:result-document href="urn:shared"><out/></xsl:result-document>` + catchCode + `</xsl:try><xsl:value-of select="$d is doc('urn:shared')"/>`, `<r>1</r>`, "1XTDE1500true"},
		{"failed retrieval", `<xsl:try><xsl:value-of select="doc('urn:missing')"/><xsl:catch/></xsl:try><xsl:result-document href="urn:missing"><out/></xsl:result-document>ok`, `<r>1</r>`, "ok"},
		{"failed source retrieval", `<xsl:try><xsl:source-document href="urn:missing"><xsl:sequence select="."/></xsl:source-document><xsl:catch/></xsl:try><xsl:result-document href="urn:missing"><out/></xsl:result-document>ok`, `<r>1</r>`, "ok"},
		{"failed output releases URI", `<xsl:try><xsl:result-document href="urn:shared"><xsl:sequence select="error()"/></xsl:result-document><xsl:catch/></xsl:try><xsl:value-of select="doc('urn:shared')/r"/>`, `<r>1</r>`, "1"},
		{"malformed input was read", `<xsl:try><xsl:value-of select="doc('urn:shared')"/><xsl:catch/></xsl:try><xsl:try><xsl:result-document href="urn:shared"><out/></xsl:result-document>` + catchCode + `</xsl:try>`, `<r>`, "XTDE1500"},
		{"read rejection preserves output reservation", `<xsl:result-document href="urn:shared"><out/></xsl:result-document><xsl:try><xsl:value-of select="unparsed-text('urn:shared')"/>` + catchCode + `</xsl:try>|<xsl:try><xsl:result-document href="urn:shared"><out/></xsl:result-document>` + catchCode + `</xsl:try>`, "text", "XTDE1500|XTDE1490"},
	} {
		for _, nested := range []bool{false, true} {
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if uri != "urn:shared" {
					return nil, transform.ErrResource
				}
				return io.NopCloser(strings.NewReader(test.data)), ctx.Err()
			})})
			got, err := resourceStylesheetResult(t, e, sheet(version30, `<xsl:template name="start">`+test.body+`</xsl:template>`), nested)
			if err != nil || got != test.want {
				t.Fatal(test.name, nested, got, err)
			}
		}
	}
}

func TestXSLTCollectionReadWriteConflicts(t *testing.T) {
	var members transform.Sequence
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r>1</r>`)), ctx.Err()
	}), CollectionResolver: collectionResolverFixture{collection: func(ctx context.Context, _ string) (transform.Sequence, error) {
		return members, ctx.Err()
	}, uris: func(ctx context.Context, _ string) ([]string, error) {
		return []string{"urn:shared"}, ctx.Err()
	}}})
	members = evaluate(t, e, `doc('urn:shared')`, transform.XPath31)
	const write = `<xsl:result-document href="urn:shared"><out/></xsl:result-document>`
	for _, read := range []string{`<xsl:value-of select="collection('urn:c')/r"/>`, `<xsl:value-of select="collection('urn:c')/r"/><xsl:value-of select="collection('urn:c')/r"/>`} {
		for _, body := range []string{read + write, write + read} {
			for _, nested := range []bool{false, true} {
				_, err := resourceStylesheetResult(t, e, sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`), nested)
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != "XTDE1500" {
					t.Fatal(nested, body, err)
				}
			}
		}
	}
	for _, nested := range []bool{false, true} {
		got, err := resourceStylesheetResult(t, e, sheet(version30, `<xsl:template name="start"><xsl:value-of select="count(uri-collection('urn:c'))"/>`+write+`</xsl:template>`), nested)
		if err != nil || got != "1" {
			t.Fatal(nested, got, err)
		}
	}
}

func TestXSLTPrimaryReadWriteConflicts(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r>1</r>`)), ctx.Err()
	})})
	for _, body := range []string{`<xsl:value-of select="doc('urn:shared')/r"/>`, `prefix<xsl:value-of select="doc('urn:shared')/r"/>`} {
		source := sheet(version30, `<xsl:template name="start">`+body+`</xsl:template>`)
		result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, BaseOutputURI: "urn:shared"})
		var detail *transform.Error
		if result != nil || !errors.As(err, &detail) || detail.Code != "XTDE1500" {
			t.Fatal(body, result, err)
		}
	}
	for _, entry := range []string{`'initial-template':QName('', 'start')`, `'initial-function':QName('urn:f','start'),'function-params':[]`} {
		source := sheet(version30, `<xsl:template name="start"><xsl:sequence select="'ok'"/></xsl:template><xsl:function xmlns:f="urn:f" name="f:start" visibility="public"><xsl:sequence select="'ok'"/></xsl:function>`)
		expression := `let $source := doc('urn:shared') return transform(map{'stylesheet-text':$stylesheet,'source-node':$source,'base-output-uri':'urn:shared','delivery-format':'serialized',` + entry + `})`
		values, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
		var detail *transform.Error
		if values.Len() != 0 || !errors.As(err, &detail) || detail.Code != "XTDE1500" {
			t.Fatal(entry, values, err)
		}
	}
}

func TestXSLTNestedResourceScopes(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r>1</r>`)), ctx.Err()
	})})
	const (
		read  = `<xsl:value-of select="doc('urn:shared')/r"/>`
		write = `<xsl:result-document href="urn:shared"><out/></xsl:result-document>`
	)
	for _, test := range []struct{ outer, inner, want string }{
		{read, write + `inner`, "1inner"},
		{write, read, "1"},
	} {
		var escaped strings.Builder
		if err := xml.EscapeText(&escaped, []byte(sheet(version30, `<xsl:template name="start">`+test.inner+`</xsl:template>`))); err != nil {
			t.Fatal(err)
		}
		source := sheet(version30, `<xsl:variable name="inner" as="xs:string"><xsl:text>`+escaped.String()+`</xsl:text></xsl:variable><xsl:template name="start">`+test.outer+`<xsl:value-of select="transform(map{'stylesheet-text':$inner,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output"/></xsl:template>`)
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if err != nil || got != test.want {
				t.Fatal(nested, test.outer, got, err)
			}
		}
	}
}

func TestEscapedFunctionResourceScopes(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r>1</r>`)), ctx.Err()
	})})
	producer := sheet(version30, `<xsl:function name="Q{urn:f}read" as="xs:string"><xsl:sequence select="string(doc('urn:shared')/r)"/></xsl:function><xsl:template name="start"><xsl:sequence select="Q{urn:f}read#0"/></xsl:template>`)
	result, err := stylesheet(t, e, producer).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: transform.ResultRaw})
	if err != nil {
		t.Fatal(err)
	}
	const (
		read  = `<xsl:value-of select="$reader()"/>`
		write = `<xsl:result-document href="urn:shared"><out/></xsl:result-document>`
	)
	for _, body := range []string{read + write, write + read} {
		source := sheet(version30, `<xsl:param name="reader" as="function() as xs:string"/><xsl:template name="start">`+body+`</xsl:template>`)
		got, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Local: "reader"}: result.Primary()}})
		var detail *transform.Error
		if got != nil || !errors.As(err, &detail) || detail.Code != "XTDE1500" {
			t.Fatal(body, got, err)
		}
		values, err := query(t, e, `transform(map{'stylesheet-text':$stylesheet,'stylesheet-params':map{QName('', 'reader'):$reader},'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source)), {Local: "reader"}: result.Primary()}})
		if values.Len() != 0 || !errors.As(err, &detail) || detail.Code != "XTDE1500" {
			t.Fatal("nested", body, values, err)
		}
	}
}

func documentFunctionContractCases() []struct{ expression, want string } {
	tests := make([]struct{ expression, want string }, 0, 24)
	for _, call := range []string{`doc`, `(doc#1)`, `function-lookup(QName('http://www.w3.org/2005/xpath-functions','doc'),1)`, `doc(?)`} {
		for _, test := range []struct{ argument, want string }{
			{`42`, errCodeXPTY0004},
			{`('urn:shared','urn:other')`, errCodeXPTY0004},
			{`'urn:shared#id'`, "FODC0005"},
			{`':/'`, "FODC0005"},
			{`[]`, ""},
			{`xs:untypedAtomic('urn:shared')`, "1"},
		} {
			tests = append(tests, struct{ expression, want string }{call + `(` + test.argument + `)/r`, test.want})
		}
	}
	return tests
}

func valueOfExpression(expression string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(expression))
	return `<xsl:value-of select="` + escaped.String() + `"/>`
}

func TestXSLTDocumentFunctionContracts(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r>1</r>`)), ctx.Err()
	})})
	for _, test := range documentFunctionContractCases() {
		t.Run(test.expression, func(t *testing.T) {
			source := sheet(version30, `<xsl:template name="start">`+valueOfExpression(test.expression)+`</xsl:template>`)
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, source, nested)
				if comparisonErrorCode(test.want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				} else if err != nil || got != test.want {
					t.Fatal(nested, got, err, test.want)
				}
			}
		})
	}
}

func TestXSLTDocumentSelections(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if uri != "urn:shared" {
			return nil, transform.ErrResource
		}
		return io.NopCloser(strings.NewReader(`<r><a xml:id="a"/><b xml:id="b"/></r>`)), ctx.Err()
	})})
	for _, call := range []string{`document`, `(document#1)`, `function-lookup(QName('http://www.w3.org/2005/xpath-functions','document'),1)`, `document(?)`} {
		for _, test := range []struct{ argument, want string }{
			{`42`, errCodeXPTY0004},
			{`[]`, errCodeXPTY0004},
			{`map{}`, errCodeXPTY0004},
			{`('urn:shared#b','urn:shared#a','urn:shared#a')`, "a,b"},
			{`('urn:shared#missing','urn:shared#b')`, "b"},
			{`('urn:shared','urn:shared#a','urn:shared')`, ",a"},
		} {
			expression := `string-join(for $n in ` + call + `(` + test.argument + `) return local-name($n),',')`
			t.Run(expression, func(t *testing.T) {
				source := sheet(version30, `<xsl:template name="start">`+valueOfExpression(expression)+`</xsl:template>`)
				for _, nested := range []bool{false, true} {
					got, err := resourceStylesheetResult(t, e, source, nested)
					if comparisonErrorCode(test.want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != test.want {
							t.Fatal(nested, got, err, test.want)
						}
					} else if err != nil || got != test.want {
						t.Fatal(nested, got, err, test.want)
					}
				}
			})
		}
	}
}

func xsltFunctionTypeCases() map[string]string {
	return map[string]string{
		`current-output-uri#0 instance of function() as xs:anyURI?`:    nameTrue,
		`current-output-uri#0 instance of function() as xs:integer`:    nameFalse,
		`current-group#0 instance of function() as xs:string`:          nameFalse,
		`current-grouping-key#0 instance of function() as xs:integer`:  nameFalse,
		`regex-group#1 instance of function(xs:integer) as xs:string`:  nameTrue,
		`regex-group(?) instance of function(xs:integer) as xs:string`: nameTrue,
		`(regex-group#1)(1.5)`: errCodeXPTY0004,
		`function-lookup(QName('http://www.w3.org/2005/xpath-functions','regex-group'),1)('1')`: errCodeXPTY0004,
		`regex-group(())`:                    errCodeXPTY0004,
		`regex-group(xs:untypedAtomic('1'))`: "",
		`key#2 instance of function(xs:string,xs:anyAtomicType*) as node()*`:    nameTrue,
		`key#2 instance of function(xs:string,xs:anyAtomicType*) as xs:integer`: nameFalse,
		`document#2 instance of function(item()*,node()) as node()*`:            nameTrue,
		`document((),())`: errCodeXPTY0004,
		`current-merge-group#1 instance of function(xs:string) as item()*`: nameTrue,
		`current-merge-group(1)`:                                           errCodeXPTY0004,
		`current-merge-key#0 instance of function() as xs:integer`:         nameFalse,
		`unparsed-entity-uri('x',parse-xml('<r/>')) instance of xs:anyURI`: nameTrue,
		`unparsed-entity-uri('x')`:                                         "XPDY0002",
		`(1 to 1)!unparsed-entity-public-id('x')`:                          errCodeXPTY0004,
		`unparsed-entity-uri('x',())`:                                      errCodeXPTY0004,
		`unparsed-entity-public-id((),parse-xml('<r/>'))`:                  errCodeXPTY0004,
		`(current#0)()`: "XTDE1360",
	}
}

func TestXSLTFunctionTypes(t *testing.T) {
	e := engine(t, transform.Config{})
	for expression, want := range xsltFunctionTypeCases() {
		t.Run(expression, func(t *testing.T) {
			source := sheet(version30, `<xsl:template name="start">`+valueOfExpression(expression)+`</xsl:template>`)
			for _, nested := range []bool{false, true} {
				got, err := resourceStylesheetResult(t, e, source, nested)
				if comparisonErrorCode(want) {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != want {
						t.Fatal(nested, got, err, want)
					}
				} else if err != nil || got != want {
					t.Fatal(nested, got, err, want)
				}
			}
		})
	}
}

func TestSingleByteXMLResources(t *testing.T) {
	var readers []*lifecycleReader

	e := engine(t, transform.Config{AllowSingleByteEncodings: true, Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		var source string

		switch uri {
		case "urn:latin-document":
			source = `<?xml version="1.0" encoding="ISO-8859-1"?><r>caf` + "\xe9" + `</r>`
		case "urn:latin-stylesheet":
			source = `<?xml version="1.0" encoding="ISO-8859-1"?>` + sheet(version30, `<xsl:template name="latin"><xsl:text>caf`+"\xe9"+`</xsl:text></xsl:template>`)
		default:
			return nil, transform.ErrResource
		}

		reader := &lifecycleReader{Reader: strings.NewReader(source)}
		readers = append(readers, reader)

		return reader, ctx.Err()
	})})

	if value := text(t, evaluate(t, e, `string(doc('urn:latin-document')/r)`, transform.XPath31)); value != xmlLatinText {
		t.Fatal(value)
	}

	source := `<?xml version="1.0" encoding="US-ASCII"?>` + sheet(version30, `<xsl:include href="urn:latin-stylesheet"/><xsl:template name="start"><xsl:call-template name="latin"/><xsl:text>:</xsl:text><xsl:value-of select="doc('urn:latin-document')/r"/></xsl:template>`)

	compiled, err := e.CompileXSLTReader(t.Context(), strings.NewReader(source), transform.XSLTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(result.Primary) != "café:café" {
		t.Fatal(result, err)
	}

	for _, reader := range readers {
		if !reader.closed {
			t.Fatal("encoded XML resource was not closed")
		}
	}

	unicodeStylesheet := `<?xml version="1.0" encoding="ISO-8859-1"?>` + sheet(version30, `<xsl:template name="start"><xsl:text>café 中</xsl:text></xsl:template>`)
	for _, configured := range []*transform.Engine{e, engine(t, transform.Config{})} {
		value, err := query(t, configured, `transform(map{'stylesheet-text':$source,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(unicodeStylesheet))}})
		if err != nil || text(t, value) != xmlCharacters {
			t.Fatal("stylesheet text was reinterpreted as bytes", value, err)
		}

		bad := strings.Replace(unicodeStylesheet, `encoding="ISO-8859-1"`, `encoding="1bad"`, 1)
		_, err = query(t, configured, `transform(map{'stylesheet-text':$source,'initial-template':QName('', 'start')})`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: sourceName}: transform.Values(transform.String(bad))}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FOXT0003" {
			t.Fatal("malformed stylesheet declaration accepted", err)
		}
	}
}

func TestXMLIDResources(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if uri != "urn:xmlid" {
			return nil, transform.ErrResource
		}

		return io.NopCloser(strings.NewReader(`<r xml:id=" &#x9;root&#xD; "/>`)), ctx.Err()
	})})
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		expression := `for $d in doc('urn:xmlid') return string($d/r/@xml:id) eq 'root' and id('root',$d) is $d/r`
		if got := text(t, evaluate(t, e, expression, version)); got != nameTrue {
			t.Fatal(version, got)
		}
	}
	for _, read := range []string{`doc('urn:xmlid')`, `document('urn:xmlid')`} {
		for _, nested := range []bool{false, true} {
			source := sheet(version30, `<xsl:template name="start"><xsl:variable name="d" select="`+read+`"/><xsl:value-of select="string($d/r/@xml:id) eq 'root' and id('root',$d) is $d/r"/></xsl:template>`)
			got, err := resourceStylesheetResult(t, e, source, nested)
			if err != nil || got != nameTrue {
				t.Fatal(read, nested, got, err)
			}
		}
	}
}

func TestCollectionVersionContracts(t *testing.T) {
	e := engine(t, transform.Config{CollectionResolver: collectionResolverFixture{collection: func(ctx context.Context, _ string) (transform.Sequence, error) {
		return transform.Values(transform.Integer(42)), ctx.Err()
	}}})
	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		value, err := query(t, e, `collection('urn:items')`, version).Evaluate(t.Context(), nil, transform.XPathContext{})
		if version == transform.XPath31 {
			if err != nil || text(t, value) != "42" {
				t.Fatal(version, value, err)
			}
		} else {
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
				t.Fatal(version, value, err)
			}
		}
	}
}

func TestStreamAvailableXMLValidation(t *testing.T) {
	for _, test := range []struct{ data, want string }{
		{`<r/>`, nameTrue},
		{`<r><unfinished`, nameTrue},
		{`<r/><s/>`, nameTrue},
		{strings.Repeat(" ", 512) + `<r/>`, nameTrue},
		{`<`, nameFalse},
		{`<>`, nameFalse},
		{`<!--unfinished`, nameFalse},
		{`<r a=>`, nameFalse},
		{`<r a="1" a="2"/>`, nameFalse},
		{`<p:r/>`, nameFalse},
		{`<!DOCTYPE r><r/>`, nameFalse},
		{`text`, nameFalse},
	} {
		t.Run(test.data, func(t *testing.T) {
			var readers []*lifecycleReader
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				reader := &lifecycleReader{Reader: strings.NewReader(test.data)}
				readers = append(readers, reader)
				return reader, ctx.Err()
			})})
			for expression, want := range map[string]string{
				`stream-available('urn:stream')`:     test.want,
				`(stream-available#1)('urn:stream')`: test.want,
				`stream-available(?)('urn:stream')`:  test.want,
				`stream-available([])`:               nameFalse,
				`stream-available(42)`:               errCodeXPTY0004,
				`stream-available(':/')`:             "FODC0005",
			} {
				source := sheet(version30, `<xsl:template name="start">`+valueOfExpression(expression)+`</xsl:template>`)
				for _, nested := range []bool{false, true} {
					got, err := resourceStylesheetResult(t, e, source, nested)
					if comparisonErrorCode(want) {
						var detail *transform.Error
						if !errors.As(err, &detail) || detail.Code != want {
							t.Fatal(expression, nested, got, err, want)
						}
					} else if err != nil || got != want {
						t.Fatal(expression, nested, got, err, want)
					}
				}
			}
			for _, reader := range readers {
				if !reader.closed {
					t.Fatal("stream availability reader was not closed")
				}
			}
		})
	}
}

func TestDocumentResourceURIValidation(t *testing.T) {
	var calls int

	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return nil, transform.ErrResource
	})})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for _, uri := range []string{":/", "http://[", "http://example.org/%zz", "relative.xml"} {
			want := "FODC0005"
			if uri == "relative.xml" {
				want = "FODC0002"
			}

			_, err := query(t, e, `doc($uri)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableURI}: transform.Values(transform.String(uri))}})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != want {
				t.Errorf("XPath %d doc(%q): %v; want %s", version, uri, err, want)
			}

			value, err := query(t, e, `doc-available($uri)`, version).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableURI}: transform.Values(transform.String(uri))}})
			if want == "FODC0005" && version != transform.XPath31 {
				if !errors.As(err, &detail) || detail.Code != want {
					t.Fatal(version, uri, value, err, want)
				}
			} else if err != nil || text(t, value) != nameFalse {
				t.Fatal("doc-available did not suppress the retrieval error", uri, value, err)
			}
		}
	}

	if calls != 0 {
		t.Fatal("invalid or unresolved URI reached the resolver", calls)
	}
}

const (
	textLatinMediaType = "text/plain; charset=iso-8859-1"
	textUTF8Encoding   = "utf-8"
	textEncodingError  = "FOUT1190"
)

func TestTextResourceMediaType(t *testing.T) {
	for _, tc := range []struct {
		name, input, mediaType, encoding, want, code string
	}{
		{"transport", "\xe9", textLatinMediaType, "", "é", ""},
		{"transport-before-argument", "\xe9", textLatinMediaType, textUTF8Encoding, "é", ""},
		{"transport-with-bom", "\xfe\xff\x00x", "text/plain; charset=utf-16", "ascii", "x", ""},
		{"xml-before-argument", "<?xml version='1.0' encoding='iso-8859-1'?><r>\xe9</r>", "application/example+xml", textUTF8Encoding, "<?xml version='1.0' encoding='iso-8859-1'?><r>é</r>", ""},
		{"plain-argument", "<?xml version='1.0' encoding='iso-8859-1'?><r>\xe9</r>", "text/plain", textUTF8Encoding, "", textEncodingError},
		{"unknown-transport", "x", "text/plain; charset=unknown-codec", "", "", textEncodingError},
		{"malformed-utf16", "\xd8\x00", "text/plain; charset=utf-16be", "", "", textEncodingError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, version := range []transform.XPathVersion{transform.XPath30, transform.XPath31} {
				reader := &typedTextReader{Reader: strings.NewReader(tc.input), mediaType: tc.mediaType}
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return reader, nil })})

				expression := `unparsed-text('urn:text')`
				if tc.encoding != "" {
					expression = `unparsed-text('urn:text', '` + tc.encoding + `')`
				}

				value, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})
				if !reader.closed {
					t.Fatal("text stream not closed")
				}

				if tc.code == "" {
					if err != nil || text(t, value) != tc.want {
						t.Fatal(version, value, err)
					}
				} else {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != tc.code || value.Len() != 0 {
						t.Fatal(version, value, err)
					}
				}
			}
		})
	}
}

func TestXSLTTextResourceMediaType(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		reader := &typedTextReader{Reader: strings.NewReader("\xe9"), mediaType: textLatinMediaType}
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return reader, nil })})
		source := sheet(version30, `<xsl:template name="start"><xsl:sequence select="unparsed-text('urn:text', 'utf-8')"/></xsl:template>`)

		var (
			value transform.Sequence
			err   error
		)
		if dynamic {
			value, err = query(t, e, `transform(map{'stylesheet-text':$stylesheet,'initial-template':QName('','start'),'delivery-format':'raw'})?output`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableStylesheet}: transform.Values(transform.String(source))}})
		} else {
			result, runErr := stylesheet(t, e, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			err = runErr

			if result != nil {
				value = result.Primary()
			}
		}

		if err != nil || text(t, value) != "é" || !reader.closed {
			t.Fatal("XSLT text metadata", dynamic, value, err, reader.closed)
		}
	}
}

type typedTextReader struct {
	lifecycleReader
	mediaType string
}

func (r *typedTextReader) MediaType() string { return r.mediaType }

func TestXPathTransformProgramBudget(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxProgramBytes: 512}})

	source := sheet(version30, `<xsl:template name="start"><xsl:text>`+strings.Repeat("x", 600)+`</xsl:text></xsl:template>`)
	for _, expression := range []string{
		transformSerializedQuery,
		`transform(map{'stylesheet-node':parse-xml($stylesheet),'initial-template':QName('', 'start')})`,
	} {
		result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{
			{Local: variableStylesheet}: transform.Values(transform.String(source)),
		}})
		if !errors.Is(err, transform.ErrLimit) || result.Len() != 0 {
			t.Fatal("dynamic stylesheet program budget", result, err)
		}
	}
}

func TestJSONDocResourceErrorCodes(t *testing.T) {
	for _, uri := range []string{"urn:missing", "https://invalid.example/%gg", "urn:json#fragment"} {
		e := engine(t, transform.Config{})
		_, err := query(t, e, `json-doc($uri)`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: variableURI}: transform.Values(transform.String(uri))}})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "FOUT1170" {
			t.Errorf("%s: %v", uri, err)
		}
	}

	for _, test := range []struct{ body, code string }{{`{"value":7}`, ""}, {`{`, "FOJS0001"}} {
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(test.body)), ctx.Err()
		})})

		result, err := query(t, e, `json-doc('urn:json')?value`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		if test.code == "" {
			if err != nil || text(t, result) != "7" {
				t.Fatal(result, err)
			}
		} else {
			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != test.code || result.Len() != 0 {
				t.Fatal("JSON parse error was reclassified", result, err)
			}
		}
	}

	e := engine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: 8}, Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`{"value":123456789}`)), ctx.Err()
	})})

	result, err := query(t, e, `json-doc('urn:json')`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrLimit) || result.Len() != 0 {
		t.Fatal("resource budget lost", result, err)
	}
}

func TestResolverClosesReaderOnFailure(t *testing.T) {
	failure := errors.New("resolver failed after opening resource")
	r := &lifecycleReader{Reader: strings.NewReader("untrusted")}

	e, err := transform.NewEngine(transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return r, failure
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `doc('urn:failed')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Evaluate(context.Background(), nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrResource) || !errors.Is(err, failure) || !r.closed {
		t.Fatalf("closed=%v, error=%v", r.closed, err)
	}
}

func TestResolverTypedNilReader(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("typed-nil reader caused panic: %v", p)
		}
	}()

	var r *lifecycleReader

	e, err := transform.NewEngine(transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return r, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `doc('urn:nil')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := q.Evaluate(context.Background(), nil, transform.XPathContext{}); !errors.Is(err, transform.ErrResource) {
		t.Fatalf("error=%v", err)
	}
}

func TestNilResolverFunction(t *testing.T) {
	var resolver transform.ResolverFunc
	if _, err := resolver.Resolve(context.Background(), "urn:nil"); !errors.Is(err, transform.ErrResource) {
		t.Fatal(err)
	}

	e, err := transform.NewEngine(transform.Config{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `doc('urn:nil')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := q.Evaluate(context.Background(), nil, transform.XPathContext{}); err == nil {
		t.Fatal("nil resolver allowed a resource lookup")
	}
}

func TestResolverStopsReadingAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &cancelReadResource{Reader: strings.NewReader(`<r/>`), cancel: cancel}

	e, err := transform.NewEngine(transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return r, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(ctx, `doc('urn:cancel')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.Evaluate(ctx, nil, transform.XPathContext{})
	if !errors.Is(err, context.Canceled) || r.reads != 1 || !r.closed {
		t.Fatalf("reads=%d closed=%v error=%v", r.reads, r.closed, err)
	}
}

func TestMaximumInputBudgetDoesNotOverflowResourceRead(t *testing.T) {
	e, err := transform.NewEngine(transform.Config{Limits: transform.Limits{MaxInputBytes: int(^uint(0) >> 1)}, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`<r/>`)), nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	q, err := e.CompileXPath(context.Background(), `count(doc('urn:small')/r)`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out, err := q.Evaluate(context.Background(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}

	if got, err := out.Text(); err != nil || got != "1" {
		t.Fatalf("got %q: %v", got, err)
	}
}

func TestImportedModulesAndResourceLimits(t *testing.T) {
	ctx := context.Background()
	closed := false
	included := sheet(version20, `<xsl:template name="included"><xsl:text>included</xsl:text></xsl:template>`)
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if uri != "https://example.invalid/module.xsl" {
			return nil, errors.New("unexpected URI")
		}

		return trackedReader{Reader: strings.NewReader(included), closed: &closed}, ctx.Err()
	})})
	main := sheet(version30, `<xsl:include href="module.xsl"/><xsl:template name="start"><xsl:call-template name="included"/></xsl:template>`)

	s, err := e.CompileXSLT(ctx, []byte(main), transform.XSLTOptions{BaseURI: "https://example.invalid/main.xsl"})
	if err != nil || !closed {
		t.Fatal(closed, err)
	}

	out, err := s.Transform(ctx, nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || string(out.Primary) != "included" {
		t.Fatal(out, err)
	}

	closed = false
	capped := engine(t, transform.Config{Limits: transform.Limits{MaxInputBytes: 32}, Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
		return trackedReader{Reader: strings.NewReader(`<r>` + strings.Repeat("x", 100) + `</r>`), closed: &closed}, ctx.Err()
	})})

	_, err = query(t, capped, `doc('urn:large')`, transform.XPath31).Evaluate(ctx, nil, transform.XPathContext{})
	if !errors.Is(err, transform.ErrLimit) || !closed {
		t.Fatal(closed, err)
	}
}

func TestXSLTImportOrder(t *testing.T) {
	for _, test := range []struct {
		prefix, importAttribute string
		invalid                 bool
	}{
		{`<xsl:template name="earlier"/>`, "", true},
		{`<xsl:include href="urn:include"/>`, "", true},
		{`<d:data xmlns:d="urn:data"/>`, "", true},
		{`<!--comment--><?test pi?>`, "", false},
		{`<xsl:template name="earlier" use-when="false()"/>`, "", false},
		{`<d:data xmlns:d="urn:data" xsl:use-when="false()"/>`, "", false},
		{`<xsl:template name="earlier"/>`, ` use-when="false()"`, false},
	} {
		for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
			calls := 0
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
				calls++
				return io.NopCloser(strings.NewReader(sheet(version20, ""))), ctx.Err()
			})})
			source := sheetStart + version20 + `">` + test.prefix + `<xsl:import href="urn:base"` + test.importAttribute + `/><xsl:output method="text"/><xsl:template name="start">ok</xsl:template></xsl:stylesheet>`
			compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: processor})
			if test.invalid && processor == transform.XSLT20 {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != "XTSE0200" || calls != 0 {
					t.Fatal(processor, test, calls, err)
				}
				continue
			}
			if err != nil {
				t.Fatal(processor, test, err)
			}
			result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil || string(result.Primary) != "ok" {
				t.Fatal(processor, test, result, err)
			}
		}
	}
	for _, kind := range []string{nameInclude, nameImport} {
		calls := 0
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			calls++
			body := ""
			if uri == "urn:outer" {
				body = `<xsl:template name="earlier"/><xsl:import href="urn:base"/>`
			}
			return io.NopCloser(strings.NewReader(sheet(version20, body))), ctx.Err()
		})})
		source := sheetStart + version20 + `"><xsl:` + kind + ` href="urn:outer"/><xsl:output method="text"/><xsl:template name="start">ok</xsl:template></xsl:stylesheet>`
		_, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: transform.XSLT20})
		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != "XTSE0200" || calls != 1 {
			t.Fatal(kind, calls, err)
		}
	}
}

func TestExcludedModuleDeclarations(t *testing.T) {
	for _, kind := range []string{nameImport, nameInclude, "use-package"} {
		calls := 0
		module := sheet(version30, `<xsl:use-package name="urn:missing" use-when="false()" bogus="ignored"/><xsl:template name="included">ok</xsl:template>`)
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
			calls++
			return io.NopCloser(strings.NewReader(module)), ctx.Err()
		})})
		attributes := `href="urn:missing"`
		if kind == "use-package" {
			attributes = `name="urn:missing"`
		}
		source := sheet(version30, `<xsl:`+kind+` `+attributes+` use-when="false()" bogus="ignored"/><xsl:template name="start">ok</xsl:template>`)
		got, err := resourceStylesheetResult(t, e, source, false)
		if err != nil || got != "ok" || calls != 0 {
			t.Fatal(kind, got, err, calls)
		}
		source = sheet(version30, `<xsl:import href="urn:module"/><xsl:template name="start"><xsl:call-template name="included"/></xsl:template>`)
		got, err = resourceStylesheetResult(t, e, source, false)
		if err != nil || got != "ok" || calls != 1 {
			t.Fatal(kind, got, err, calls)
		}
	}
}

func TestXSLT20IgnoresFutureDeclarations(t *testing.T) {
	for _, future := range []string{`<xsl:mode bogus="ignored"/>`, `<xsl:mode use-when="map{}"/>`, `<xsl:use-package name="urn:missing" package-version="1"/>`, `<xsl:future><not-well-formed-xslt/></xsl:future>`} {
		calls := 0
		e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
			calls++
			return io.NopCloser(strings.NewReader(sheet(version20, ""))), ctx.Err()
		})})
		source := sheetStart + version30 + `">` + future + `<xsl:import href="urn:base"/><xsl:output method="text"/><xsl:template name="start">ok</xsl:template></xsl:stylesheet>`
		compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{ProcessorVersion: transform.XSLT20})
		if err != nil || calls != 1 {
			t.Fatal(future, calls, err)
		}
		result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil || string(result.Primary) != "ok" {
			t.Fatal(future, result, err)
		}
	}
}

func moduleUseWhenNamespaceSources(kind string, rootCondition bool) (string, string) {
	condition := ` xmlns:t="http://www.w3.org/2001/XMLSchema" use-when="t:integer('1') eq 1"`
	module := sheet(version20, `<xsl:template name="included">42</xsl:template>`)
	main := sheetStart + version20 + `"><xsl:` + kind + ` href="urn:module"` + condition + `/><xsl:output method="text"/><xsl:template name="start"><xsl:call-template name="included"/>:<xsl:value-of select="type-available('t:integer')"/></xsl:template></xsl:stylesheet>`
	main = strings.Replace(main, `xmlns:xs=`, `xmlns:t="urn:wrong" xmlns:xs=`, 1)
	if rootCondition {
		module = strings.Replace(module, ` version=`, condition+` version=`, 1)
		main = strings.Replace(main, ` href="urn:module"`+condition, ` href="urn:module"`, 1)
	}
	return main, module
}

func TestXSLTModuleUseWhenNamespaces(t *testing.T) {
	for _, kind := range []string{nameInclude, nameImport} {
		for _, rootCondition := range []bool{false, true} {
			for _, processor := range []transform.XSLTVersion{transform.XSLT20, transform.XSLT30} {
				main, module := moduleUseWhenNamespaceSources(kind, rootCondition)
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, _ string) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(module)), ctx.Err()
				})})
				compiled, err := e.CompileXSLT(t.Context(), []byte(main), transform.XSLTOptions{ProcessorVersion: processor})
				if err != nil {
					t.Fatal(kind, rootCondition, processor, err)
				}
				result, err := compiled.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
				if err != nil || string(result.Primary) != "42:false" {
					t.Fatal(kind, rootCondition, processor, result, err)
				}
			}
		}
	}
}

func TestXSLTProcessorVersionModules(t *testing.T) {
	for _, kind := range []string{nameInclude, nameImport} {
		t.Run(kind, func(t *testing.T) {
			closed := false
			module := sheet(version20, `<xsl:template name="included"><xsl:value-of select="map{'value':42}?value"/></xsl:template>`)
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if uri != "https://example.invalid/module.xsl" {
					return nil, transform.ErrResource
				}

				return trackedReader{Reader: strings.NewReader(module), closed: &closed}, ctx.Err()
			})})
			main := sheet(version20, `<xsl:`+kind+` href="module.xsl"/><xsl:output method="text"/><xsl:template name="start"><xsl:call-template name="included"/></xsl:template>`)

			s, err := e.CompileXSLT(t.Context(), []byte(main), transform.XSLTOptions{ProcessorVersion: transform.XSLT30, BaseURI: "https://example.invalid/main.xsl"})
			if err != nil || !closed {
				t.Fatal(closed, err)
			}

			out, err := s.Transform(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
			if err != nil || string(out.Primary) != "42" {
				t.Fatal(out, err)
			}
		})
	}
}

type lifecycleReader struct {
	io.Reader
	closed bool
}

func (r *lifecycleReader) Close() error {
	r.closed = true
	return nil
}

type cancelReadResource struct {
	lifecycleReader
	cancel context.CancelFunc
	reads  int
}

func (r *cancelReadResource) Read(p []byte) (int, error) {
	r.reads++
	n, err := r.Reader.Read(p)
	r.cancel()

	return n, err
}

type trackedReader struct {
	io.Reader
	closed *bool
}

func (r trackedReader) Close() error { *r.closed = true; return nil }

func TestXPathFunctionConversionBudgets(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 1000}})
	for _, expression := range []string{`function-arity(concat#1000000000)`, `function-arity(function-lookup(xs:QName('fn:concat'),1000000000))`} {
		if got := text(t, evaluate(t, e, expression, transform.XPath31)); got != "1000000000" {
			t.Fatal("variadic function metadata was not compact", expression, got)
		}
	}

	for _, expression := range []string{
		`(1 to 10000) || 'a'`,
		`(function($x as xs:integer*) {true()})(1 to 10000)`,
		`codepoints-to-string(33 to 10033)`,
		`codepoints-to-string#1(33 to 10033)`,
		`function-lookup(xs:QName('fn:codepoints-to-string'),1)(33 to 10033)`,
	} {
		value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		if !errors.Is(err, transform.ErrLimit) || value.Len() != 0 {
			t.Fatal("function conversion ignored the operation budget", expression, value, err)
		}
	}
}

func TestTextResourceArgumentValidation(t *testing.T) {
	reads := 0
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		reads++
		return io.NopCloser(strings.NewReader("ok")), nil
	})})

	for _, name := range []string{functionUnparsedText, "unparsed-text-lines", "unparsed-text-available"} {
		for _, arguments := range []string{`'urn:text', ()`, `'urn:text', 1`, `(), ()`, `(), ('UTF-8','UTF-16')`} {
			_, err := query(t, e, name+"("+arguments+")", transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})

			var detail *transform.Error
			if !errors.As(err, &detail) || detail.Code != errCodeXPTY0004 {
				t.Fatal("text resource signature", name, arguments, err)
			}
		}
	}

	if reads != 0 {
		t.Fatal("invalid arguments reached the resource resolver", reads)
	}

	got := text(t, evaluate(t, e, `unparsed-text(xs:anyURI('urn:text'), xs:untypedAtomic('UTF-8'))`, transform.XPath31))
	if got != "ok" || reads != 1 {
		t.Fatal("valid function conversion did not reach the resource", got, reads)
	}
}

func TestXSLTFunctionConversionBudgets(t *testing.T) {
	e := engine(t, transform.Config{})
	bounded := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 1000}})
	argument := evaluate(t, e, `1 to 10000`, transform.XPath31)
	for _, declaration := range []string{`as="xs:integer*"`, `as="function(xs:integer*) as xs:boolean"`} {
		t.Run(declaration, func(t *testing.T) {
			test := functionArgumentCase{declaration: declaration, check: `true()`}
			value := argument
			if strings.Contains(declaration, "function(") {
				value = evaluate(t, e, `function($v as xs:double*) {true()}`, transform.XPath31)
				test.check = `$v(1 to 10000)`
			}
			result, err := stylesheet(t, bounded, functionArgumentSheet(test)).CallFunction(t.Context(), nil, transform.Name{Space: "urn:function", Local: "check"}, []transform.Sequence{value}, transform.XSLTContext{})
			if result != nil || !errors.Is(err, transform.ErrLimit) {
				t.Fatal(result, err)
			}
		})
	}
}

func TestXSLTStaticParameterBudgets(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 1000}})
	for _, nested := range []bool{false, true} {
		for _, size := range []string{"10", "10000"} {
			source := sheet(version30, `<xsl:output method="text"/><xsl:param name="p" static="yes" as="xs:integer*" select="1 to `+size+`"/><xsl:template name="start">kept</xsl:template>`)
			got, err := resourceStylesheetResult(t, e, source, nested)
			if size == "10" {
				if err != nil || got != nameKept {
					t.Fatal(nested, size, got, err)
				}
			} else if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("static conversion lost its shared operation limit", nested, got, err)
			}
		}
	}
}

func TestXSLTStaticParameterModules(t *testing.T) {
	for _, relation := range []string{nameInclude, nameImport} {
		for _, test := range []struct{ declaration, argument, check, want string }{
			{`as="xs:double"`, `41`, `$p instance of xs:double and $p eq 41`, nameTrue},
			{`required="yes"`, "", `true()`, "XTDE0050"},
			{`required="yes" use-when="false()"`, "", `true()`, nameTrue},
		} {
			module := sheet(version30, `<xsl:param name="p" static="yes" `+test.declaration+`/>`)
			e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
				if uri != "urn:static-module" {
					return nil, errors.New("unexpected module URI")
				}
				return io.NopCloser(strings.NewReader(module)), ctx.Err()
			})})
			source := sheet(version30, `<xsl:`+relation+` href="urn:static-module"/><xsl:template name="start"><xsl:value-of select="`+test.check+`"/></xsl:template>`)
			for _, nested := range []bool{false, true} {
				got, err := staticParameterResult(t, e, source, test.argument, nested)
				if test.want == nameTrue {
					if err != nil || got != nameTrue {
						t.Fatal(relation, nested, test.declaration, got, err)
					}
				} else {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != test.want {
						t.Fatal(relation, nested, test.declaration, err, test.want)
					}
				}
			}
		}
	}
}

func TestXSLTStaticParameterShadowImports(t *testing.T) {
	for _, relation := range []string{nameInclude, nameImport} {
		for _, nested := range []bool{false, true} {
			for _, argument := range []string{"", "41"} {
				reads := 0
				e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
					reads++
					if uri != "urn:typed-static-module" {
						return nil, errors.New("static parameter was not converted before shadow-attribute evaluation")
					}
					return io.NopCloser(strings.NewReader(sheet(version30, `<xsl:template name="module">kept</xsl:template>`))), ctx.Err()
				})})
				source := sheet(version30, `<xsl:param name="p" static="yes" as="xs:double"/><xsl:`+relation+` _href="{if($p instance of xs:double) then 'urn:typed-static-module' else 'urn:wrong-module'}"/><xsl:template name="start"><xsl:call-template name="module"/></xsl:template>`)
				got, err := staticParameterResult(t, e, source, argument, nested)
				if argument == "" {
					var detail *transform.Error
					if !errors.As(err, &detail) || detail.Code != "XTDE0050" || reads != 0 {
						t.Fatal(relation, nested, reads, err)
					}
				} else if err != nil || got != nameKept || reads == 0 {
					t.Fatal(relation, nested, reads, got, err)
				}
			}
		}
	}
}

func TestDynamicXPathBudgets(t *testing.T) {
	source := sheet(version30, `<xsl:param name="code"/><xsl:template name="start"><xsl:evaluate xpath="$code"/></xsl:template>`)
	for _, limits := range []transform.Limits{{MaxProgramBytes: 512}, {MaxOperations: 512}} {
		e := engine(t, transform.Config{Limits: limits})
		compiled := stylesheet(t, e, source)
		result, err := compiled.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "code"}: transform.Values(transform.String("1" + strings.Repeat(" ", 1000)))}})
		if result != nil || !errors.Is(err, transform.ErrLimit) {
			t.Fatal(limits, result, err)
		}
	}
}

func TestDynamicXPathDocumentIdentity(t *testing.T) {
	reads := 0
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if uri != "urn:document" {
			return nil, errors.New("unexpected resource")
		}
		reads++
		return io.NopCloser(strings.NewReader(`<r/>`)), ctx.Err()
	})})
	source := sheet(version30, `<xsl:template name="start"><xsl:variable name="a" select="doc('urn:document')"/><xsl:variable name="b" as="node()"><xsl:evaluate xpath="'doc(''urn:document'')'"/></xsl:variable><xsl:sequence select="$a is $b"/></xsl:template>`)
	for _, nested := range []bool{false, true} {
		before := reads
		got, err := resourceStylesheetResult(t, e, source, nested)
		if err != nil || got != nameTrue || reads != before+1 {
			t.Fatal(nested, got, err, reads, before)
		}
	}
}

func TestDynamicEvaluationPackagePolicy(t *testing.T) {
	library := packageSheet(`name="urn:dynamic-library"`, `<xsl:function name="p:f" visibility="public"><xsl:evaluate xpath="'42'"><xsl:fallback>package disabled</xsl:fallback></xsl:evaluate></xsl:function>`)
	source := packageSheet(`name="urn:dynamic-user"`, `<xsl:use-package name="urn:dynamic-library"/><xsl:template name="start" visibility="public"><xsl:sequence select="p:f()"/></xsl:template>`)
	for _, disabled := range []bool{false, true} {
		e := engine(t, transform.Config{DisableXSLTDynamicEvaluation: disabled, PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, version string) (transform.PackageResource, error) {
			if name != "urn:dynamic-library" {
				return transform.PackageResource{}, errors.New("unexpected package")
			}
			return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
		})})
		want := "42"
		if disabled {
			want = "package disabled"
		}
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if err != nil || got != want {
				t.Fatal(disabled, nested, got, err, want)
			}
		}
	}
}

func TestMapMergeWorkBudget(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 4000}})
	for _, call := range []string{"map:merge", "(map:merge#1)", "function-lookup(QName('http://www.w3.org/2005/xpath-functions/map','merge'),1)"} {
		for _, repetitions := range []string{"1", "100"} {
			expression := `let $m := map:merge(for $i in 1 to 100 return map{$i:$i}) return map:size(` + call + `(for $i in 1 to ` + repetitions + ` return $m))`
			result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
			if repetitions == "1" {
				if err != nil || text(t, result) != "100" {
					t.Fatal(call, result, err)
				}
			} else if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("map entries bypassed shared work budget", call, result, err)
			}
		}
	}
}

func TestMapMergeIntermediateSizeLimit(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxNodes: 32, MaxOperations: 4000}})
	for _, distinct := range []bool{false, true} {
		second := `$a`
		if distinct {
			second = `map:merge(for $i in 21 to 40 return map{$i:$i})`
		}
		expression := `let $a := map:merge(for $i in 1 to 20 return map{$i:$i}) return map:size(map:merge(($a,` + second + `)))`
		value, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
		if distinct {
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal("intermediate XPath map exceeded size limit", value, err)
			}
		} else if err != nil || text(t, value) != "20" {
			t.Fatal(value, err)
		}
		maps := `$a`
		if distinct {
			maps = `map:merge(for $i in 21 to 40 return map{$i:$i})`
		}
		source := mapInstructionSheet(`<xsl:variable name="a" select="map:merge(for $i in 1 to 20 return map{$i:$i})"/><xsl:map><xsl:sequence select="$a,`+maps+`"/></xsl:map>`, `map:size($m)`)
		// Repeated keys are rejected by xsl:map; the successful control uses one map.
		if !distinct {
			source = mapInstructionSheet(`<xsl:map><xsl:sequence select="map:merge(for $i in 1 to 20 return map{$i:$i})"/></xsl:map>`, `map:size($m)`)
		}
		for _, nested := range []bool{false, true} {
			got, err := resourceStylesheetResult(t, e, source, nested)
			if distinct {
				if !errors.Is(err, transform.ErrLimit) {
					t.Fatal("intermediate XSLT map exceeded size limit", nested, got, err)
				}
			} else if err != nil || got != "20" {
				t.Fatal(nested, got, err)
			}
		}
	}
}

func TestMapMergeCombinedValueBudgets(t *testing.T) {
	for _, test := range []struct {
		name               string
		limit              transform.Limits
		repetitions, count string
	}{
		{"size", transform.Limits{MaxNodes: 32, MaxOperations: 4000}, "2", "20"},
		{"copy work", transform.Limits{MaxOperations: 4000}, "100", "100"},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := engine(t, transform.Config{Limits: test.limit})
			for _, repeats := range []string{"1", test.repetitions} {
				expression := `let $m := map:entry('k',1 to ` + test.count + `) return map:size(map:merge(for $i in 1 to ` + repeats + ` return $m,map{'duplicates':'combine'}))`
				result, err := query(t, e, expression, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{})
				if repeats == "1" {
					if err != nil || text(t, result) != "1" {
						t.Fatal(result, err)
					}
				} else if !errors.Is(err, transform.ErrLimit) {
					t.Fatal("combined values bypassed shared budget", result, err)
				}
			}
		})
	}
}

func mapMergeCombinedExpressions() []struct{ name, expression string } {
	return []struct{ name, expression string }{
		{"singleton values", `let $v := map:merge((1 to 2000)!map:entry('z',.),map{'duplicates':'combine'})?z return count($v) eq 2000 and $v[1] eq 1 and $v[last()] eq 2000`},
		{"input ownership", `let $a := map:entry('k',1 to 3), $b := map:merge(for $i in 1 to 2000 return $a,map{'duplicates':'combine'}) return deep-equal($a?k,1 to 3) and deep-equal($b?k,for $i in 1 to 2000 return 1 to 3)`},
	}
}

func TestMapMergeManyCombinedValues(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, test := range mapMergeCombinedExpressions() {
		if got := text(t, evaluate(t, e, test.expression, transform.XPath31)); got != nameTrue {
			t.Fatal(test.name, got)
		}
	}
}

func TestConditionalContentBudgets(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 1000}})
	for _, size := range []int{8, 4000} {
		value := transform.Array(make([]transform.Sequence, size)...)
		for _, filter := range []bool{false, true} {
			body := `<xsl:sequence select="0"/>`
			if filter {
				body = `<xsl:where-populated><xsl:sequence select="$v"/></xsl:where-populated><xsl:sequence select="0"/>`
			}
			source := sheet(version30, `<xsl:param name="v"/><xsl:template name="start">`+body+`</xsl:template>`)
			result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Local: "v"}: transform.Values(value)}})
			if filter && size == 4000 {
				if !errors.Is(err, transform.ErrLimit) {
					t.Fatal(size, filter, result, err)
				}
			} else if err != nil || text(t, result.Primary()) != "0" {
				t.Fatal(size, filter, result, err)
			}
		}
	}
}

func TestConditionalContentResources(t *testing.T) {
	requests := 0
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		requests++
		if uri != "mem://suite/style/alternate/payload.txt" {
			t.Fatalf("deferred action lost its static base URI: %s", uri)
		}
		return io.NopCloser(strings.NewReader("payload")), nil
	})})
	source := sheet(version30, `<xsl:param name="run"/><xsl:template name="start"><xsl:on-non-empty xml:base="alternate/" select="unparsed-text('payload.txt')"/><xsl:sequence xml:base="other/" select="if ($run) then 'body' else ()"/></xsl:template>`)
	compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{BaseURI: "mem://suite/style/main.xsl"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []transform.ResultMode{transform.ResultDefault, transform.ResultRaw, transform.ResultDocument} {
		for _, run := range []bool{false, true, false} {
			before := requests
			result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, ResultMode: mode, Parameters: transform.Bindings{{Local: "run"}: transform.Values(transform.Boolean(run))}})
			if err != nil {
				t.Fatal(mode, run, err)
			}
			output, err := result.Serialize(t.Context())
			want := ""
			if run {
				want = "payload body"
			}
			if err != nil || string(output.Primary) != want || requests-before != map[bool]int{false: 0, true: 1}[run] {
				t.Fatal(mode, run, output, requests-before, err)
			}
		}
	}
}

func TestCatchControlFailures(t *testing.T) {
	bounded := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 500}})
	canceled := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return nil, context.Canceled })})
	for _, rollback := range []string{"yes", "no"} {
		for _, prefix := range []string{"", `<xsl:text>partial</xsl:text>`} {
			source := sheet(version30, `<xsl:template name="start"><xsl:try rollback-output="`+rollback+`">`+prefix+`<xsl:sequence select="sum(1 to 10000)"/><xsl:catch/></xsl:try></xsl:template>`)
			_, err := resourceStylesheetResult(t, bounded, source, false)
			if !errors.Is(err, transform.ErrLimit) {
				t.Fatal(rollback, prefix, err)
			}
			source = sheet(version30, `<xsl:template name="start"><xsl:try rollback-output="`+rollback+`">`+prefix+`<xsl:sequence select="doc('urn:canceled')"/><xsl:catch/></xsl:try></xsl:template>`)
			_, err = resourceStylesheetResult(t, canceled, source, false)
			if !errors.Is(err, context.Canceled) {
				t.Fatal(rollback, prefix, err)
			}
		}
	}
}

func TestCatchModuleMetadata(t *testing.T) {
	e := engine(t, transform.Config{Resolver: transform.ResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		if uri != "mem://errors/child.xsl" {
			t.Fatal(uri)
		}
		return io.NopCloser(strings.NewReader(sheet(version30, `<xsl:template name="child"><xsl:sequence select="error()"/></xsl:template>`))), nil
	})})
	source := sheet(version30, `<xsl:include href="child.xsl"/><xsl:template xmlns:err="http://www.w3.org/2005/xqt-errors" name="start"><xsl:try><xsl:call-template name="child"/><xsl:catch select="$err:module"/></xsl:try></xsl:template>`)
	compiled, err := e.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{BaseURI: "mem://errors/main.xsl"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil || text(t, result.Primary()) != "mem://errors/child.xsl" {
		t.Fatal(result, err)
	}
}
