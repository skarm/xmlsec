package transform_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform"
)

func TestTypedValues(t *testing.T) {
	if value, err := transform.Values(transform.Integer(1), transform.Integer(2)).EffectiveBoolean(); err == nil {
		t.Fatal(value)
	}

	m, err := transform.Map(transform.MapEntry{Key: transform.String("a"), Value: transform.Values(transform.Integer(1))})
	if err != nil {
		t.Fatal(err)
	}

	entry, ok := m.Lookup(transform.String("a"))
	if !ok || text(t, entry) != "1" {
		t.Fatal(entry, ok)
	}

	a := transform.Array(entry)

	member, err := a.Member(0)
	if err != nil || text(t, member) != "1" {
		t.Fatal(member, err)
	}

	if _, err = a.Member(1); err == nil {
		t.Fatal("index accepted")
	}

	date := transform.DateTime(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	if date.Type().Local != "dateTime" {
		t.Fatal(date.Type())
	}

	if _, err = transform.Map(transform.MapEntry{Key: transform.String("a")}, transform.MapEntry{Key: transform.String("a")}); err == nil {
		t.Fatal("duplicate key")
	}
}

func TestFunctionValuesConcurrentReuse(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, source := range []string{`function($n){sum(1 to $n)}`, `sum#1`, `function-lookup(QName("http://www.w3.org/2005/xpath-functions","sum"),1)`} {
		callable := evaluate(t, e, source, transform.XPath31)

		q := query(t, e, `$f(1 to 10)`, transform.XPath31)
		if strings.HasPrefix(source, "function(") {
			q = query(t, e, `$f(10)`, transform.XPath31)
		}

		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				out, err := q.Evaluate(context.Background(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: callable}})
				if err != nil {
					t.Error(err)
					return
				}

				got, err := out.Text()
				if err != nil || got != "55" {
					t.Error(got, err)
				}
			})
		}

		wg.Wait()
	}
}

func TestReturnedPackageGlobalBindings(t *testing.T) {
	library := packageSheet(`name="urn:binding-library"`, `<xsl:variable name="p:v" as="map(*)"><xsl:message select="'lazy global'"/><xsl:sequence select="map{'total':sum(1 to 100),'year':year-from-date(current-date()),'lang':default-language(),'zone':implicit-timezone()}"/></xsl:variable><xsl:function name="p:get" visibility="public"><xsl:sequence select="function($n){ string-join(($p:v?total + sum(1 to $n),$p:v?year,$p:v?lang,string($p:v?zone)) ! string(),'|') }"/></xsl:function>`)
	e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
		return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
	})})
	source := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:variable name="p:v" select="9999"/><xsl:template name="start" visibility="public" as="function(*)"><xsl:sequence select="p:get()"/></xsl:template>`)
	result, err := stylesheet(t, e, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Context: transform.DynamicContext{CurrentTime: time.Date(1999, 12, 31, 22, 0, 0, 0, time.UTC), ImplicitTimezone: time.FixedZone("producer", 3*60*60), DefaultLanguage: "fr"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Messages()) != 1 {
		t.Fatal(result.Messages())
	}
	callable := result.Primary()
	q := query(t, e, `$f(10)`, transform.XPath31)
	options := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: callable}}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			value, err := q.Evaluate(t.Context(), nil, options)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := value.Text()
			if err != nil || got != "5105|2000|fr|PT3H" {
				t.Error(got, err)
			}
		})
	}
	wg.Wait()
	consumer := stylesheet(t, e, sheet(version30, `<xsl:param name="f" as="function(*)"/><xsl:template name="start"><xsl:sequence select="$f(10)"/></xsl:template>`))
	consumed, err := consumer.CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "f"}: callable}})
	if err != nil || text(t, consumed.Primary()) != "5105|2000|fr|PT3H" || len(consumed.Messages()) != 0 {
		t.Fatal(consumed, err)
	}
	bounded := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 32}})
	_, err = query(t, bounded, `$f(10000)`, transform.XPath31).Evaluate(t.Context(), nil, options)
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("returned function retained producer budget", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = q.Evaluate(cancelled, nil, options)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReturnedFunctionsKeepProducingParameters(t *testing.T) {
	for _, reference := range []string{`function(){ $p:v }`, `p:read#0`} {
		library := packageSheet(`name="urn:binding-library"`, `<xsl:param name="p:v" as="xs:string"/><xsl:function name="p:read" visibility="public"><xsl:sequence select="$p:v"/></xsl:function><xsl:function name="p:get" visibility="public"><xsl:sequence select="`+reference+`"/></xsl:function>`)
		e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
			return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
		})})
		source := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:param name="f" as="function(*)?"/><xsl:template name="start" visibility="public"><xsl:sequence select="if(exists($f)) then $f() else p:get()"/></xsl:template>`)
		compiled := stylesheet(t, e, source)
		options := transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: transform.Bindings{{Space: "urn:components", Local: "v"}: transform.Values(transform.String("A"))}}
		first, err := compiled.Execute(t.Context(), nil, options)
		if err != nil {
			t.Fatal(err)
		}
		options.Parameters = transform.Bindings{{Space: "urn:components", Local: "v"}: transform.Values(transform.String("B")), {Local: "f"}: first.Primary()}
		second, err := compiled.Execute(t.Context(), nil, options)
		if err != nil || text(t, second.Primary()) != "A" {
			t.Fatal(reference, second, err)
		}
	}
}

func TestReturnedInlineGlobalNodeIdentity(t *testing.T) {
	library := packageSheet(`name="urn:binding-library"`, `<xsl:variable name="p:v" as="element()"><node/></xsl:variable><xsl:function name="p:get" visibility="public"><xsl:sequence select="function(){ $p:v }"/></xsl:function>`)
	e := engine(t, transform.Config{PackageResolver: transform.PackageResolverFunc(func(ctx context.Context, name, _ string) (transform.PackageResource, error) {
		return transform.PackageResource{BaseURI: name, Reader: io.NopCloser(strings.NewReader(library))}, ctx.Err()
	})})
	source := packageSheet(`name="urn:binding-user"`, `<xsl:use-package name="urn:binding-library"/><xsl:template name="start" visibility="public" as="function(*)"><xsl:sequence select="p:get()"/></xsl:template>`)
	result, err := stylesheet(t, e, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
	if err != nil {
		t.Fatal(err)
	}
	bindings := transform.Bindings{{Local: "f"}: result.Primary()}
	node, err := query(t, e, `$f()`, transform.XPath31).Evaluate(t.Context(), nil, transform.XPathContext{Variables: bindings})
	if err != nil {
		t.Fatal(err)
	}
	bindings[transform.Name{Local: "n"}] = node
	comparison := query(t, e, `$f() is $n`, transform.XPath31)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			value, err := comparison.Evaluate(t.Context(), nil, transform.XPathContext{Variables: bindings})
			if err != nil || text(t, value) != "true" {
				t.Error(value, err)
			}
		})
	}
	wg.Wait()
}

func TestCopyOfRetainsNonNodeItems(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		source := sheet(version, `<xsl:template name="start"><xsl:copy-of select="(1,2)"/><xsl:sequence select="3"/></xsl:template>`)
		result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil {
			t.Fatal(err)
		}
		check := query(t, e, `deep-equal($v,(1,2,3))`, transform.XPath31)
		got, err := check.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "v"}: result.Primary()}})
		if err != nil || text(t, got) != nameTrue {
			t.Fatal(version, got, err)
		}
	}
	source := sheet(version30, `<xsl:template name="start"><xsl:copy-of select="(map{'v':42},[1,[2]],function(){3})"/></xsl:template>`)
	result, err := stylesheet(t, e, source).Execute(t.Context(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
	if err != nil {
		t.Fatal(err)
	}
	check := query(t, e, `count($v) eq 3 and $v[1]?v eq 42 and $v[2] instance of array(*) and $v[2]?2 instance of array(*) and $v[3]() eq 3`, transform.XPath31)
	got, err := check.Evaluate(t.Context(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "v"}: result.Primary()}})
	if err != nil || text(t, got) != nameTrue {
		t.Fatal(got, err)
	}
}

func TestCoercedFunctionStaticContext(t *testing.T) {
	e := engine(t, transform.Config{})
	producer, err := e.CompileXPath(t.Context(), `(function($f as function(a:float) as a:double){$f})(function($v as a:double) as a:float {a:float($v)})`, transform.XPathOptions{Version: transform.XPath31, Namespaces: map[string]string{"a": "http://www.w3.org/2001/XMLSchema"}})
	if err != nil {
		t.Fatal(err)
	}
	callable, err := producer.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := e.CompileXPath(t.Context(), `$f(2) instance of xs:double and $f(2) eq 2`, transform.XPathOptions{Version: transform.XPath31, Namespaces: map[string]string{"a": "urn:shadow"}})
	if err != nil {
		t.Fatal(err)
	}
	options := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: callable}}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			value, err := consumer.Evaluate(t.Context(), nil, options)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := value.Text()
			if err != nil || got != nameTrue {
				t.Error(got, err)
			}
		})
	}
	wg.Wait()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := consumer.Evaluate(cancelled, nil, options); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReturnedFunctionDynamicEvaluationPolicy(t *testing.T) {
	consumer := engine(t, transform.Config{})
	q := query(t, consumer, `$f()`, transform.XPath31)
	inner := sheet(version30, `<xsl:template name="start"><xsl:evaluate xpath="'42'"><xsl:fallback>inner disabled</xsl:fallback></xsl:evaluate></xsl:template>`)
	source := sheet(version30, `<xsl:param name="code"/><xsl:template name="start" as="function(*)"><xsl:sequence select="function(){string-join((string(element-available('xsl:evaluate')),system-property('xsl:supports-dynamic-evaluation'),transform(map{'stylesheet-text':$code,'initial-template':QName('', 'start'),'delivery-format':'serialized'})?output),'|')}"/></xsl:template>`)
	for _, disabled := range []bool{false, true} {
		producer := engine(t, transform.Config{DisableXSLTDynamicEvaluation: disabled})
		result, err := stylesheet(t, producer, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{Parameters: transform.Bindings{{Local: "code"}: transform.Values(transform.String(inner))}, ResultMode: transform.ResultRaw})
		if err != nil {
			t.Fatal(err)
		}
		options := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: result.Primary()}}
		want := "true|yes|42"
		if disabled {
			want = "false|no|inner disabled"
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				got, err := q.Evaluate(t.Context(), nil, options)
				if err != nil {
					t.Error(err)
					return
				}
				value, err := got.Text()
				if err != nil || value != want {
					t.Error(value, err, want)
				}
			})
		}
		wg.Wait()
	}
}

func TestReturnedIntrospectionStaticContexts(t *testing.T) {
	producer := engine(t, transform.Config{})
	consumer := engine(t, transform.Config{})
	for _, static := range []bool{false, true} {
		for _, reference := range []string{`element-available#1`, `function-lookup(QName('http://www.w3.org/2005/xpath-functions','element-available'),1)`} {
			global, body := "", `<xsl:sequence select="`+reference+`"/>`
			if static {
				global = `<xsl:variable static="yes" xmlns="http://www.w3.org/1999/XSL/Transform" name="f" select="` + reference + `"/>`
				body = `<xsl:sequence select="$f"/>`
			}
			source := sheet(version30, global+`<xsl:template xmlns="http://www.w3.org/1999/XSL/Transform" name="start" as="function(xs:string) as xs:boolean">`+body+`</xsl:template>`)
			value, err := stylesheet(t, producer, source).CallTemplate(t.Context(), nil, transform.Name{Local: nameStart}, transform.XSLTContext{})
			if err != nil {
				t.Fatal(static, reference, err)
			}
			invoke := query(t, consumer, `$f('evaluate')`, transform.XPath31)
			bindings := transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: value.Primary()}}
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() {
					result, err := invoke.Evaluate(t.Context(), nil, bindings)
					if err != nil || text(t, result) != nameTrue {
						t.Error(static, reference, result, err)
					}
				})
			}
			group.Wait()
		}
	}
}
