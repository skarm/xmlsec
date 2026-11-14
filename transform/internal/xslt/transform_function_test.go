package xslt //nolint:testpackage // Exercises fn:transform option handling and result delivery directly.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

func TestTransformRejectsInvalidOptionsBeforeResolvingStylesheet(t *testing.T) {
	t.Parallel()
	location := xdm.SingleString("https://styles.example/report.xsl")
	const xsl = "http://www.w3.org/1999/XSL/Transform"
	for _, tc := range []struct {
		name, code string
		typeError  bool
		options    []xdm.MapEntry
	}{
		{name: "missing_stylesheet_source", code: "FOXT0002"},
		{name: "conflicting_stylesheet_sources", code: "FOXT0002", options: []xdm.MapEntry{
			{Key: stringItem("stylesheet-location"), Value: location},
			{Key: stringItem("stylesheet-text"), Value: xdm.SingleString("<unused/>")},
		}},
		{name: "competing_entry_points", code: "FOXT0002", options: []xdm.MapEntry{
			{Key: stringItem("stylesheet-location"), Value: location},
			{Key: stringItem("initial-template"), Value: xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Local: "start"}})},
			{Key: stringItem("initial-mode"), Value: xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Local: "process"}})},
		}},
		{name: "unsupported_delivery_format", code: "FOXT0002", options: []xdm.MapEntry{
			{Key: stringItem("stylesheet-location"), Value: location},
			{Key: stringItem("delivery-format"), Value: xdm.SingleString("items")},
		}},
		{name: "global_context_must_be_singleton", code: "XPTY0004", typeError: true, options: []xdm.MapEntry{
			{Key: stringItem("stylesheet-location"), Value: location},
			{Key: stringItem("global-context-item"), Value: xdm.ItemSlice{stringItem("first"), stringItem("second")}},
		}},
		{name: "unsupported_processor_version", code: "FOXT0001", options: []xdm.MapEntry{
			{Key: stringItem("stylesheet-location"), Value: location},
			{Key: stringItem("xslt-version"), Value: xdm.SingleInteger(4)},
		}},
		{name: "streaming_unavailable", code: "FOXT0001", options: []xdm.MapEntry{
			{Key: stringItem("stylesheet-location"), Value: location},
			{Key: stringItem("requested-properties"), Value: xdm.ItemSlice{xdm.SingleEntryMap(xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{URI: xsl, Local: "supports-streaming"}}, xdm.SingleBoolean(true))}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls int
			resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
				calls++
				return nil, fmt.Errorf("unexpected stylesheet request to %q", uri)
			})
			result, err := TransformFunction(WithTransformURIResolver(resolver)).Call(t.Context(), []xdm.Sequence{xdm.ItemSlice{xdm.NewMap(tc.options)}})
			var detail *XSLTError
			matches := errors.As(err, &detail) && detail.Code == tc.code
			if tc.typeError {
				matches = errors.Is(err, &xdm.Error{Code: tc.code})
			}
			if xdm.SequenceLen(result) != 0 || !matches || calls != 0 {
				t.Fatalf("transform returned %v, error=%v, resolver calls=%d, want no result, %s and no resolution", result, err, calls, tc.code)
			}
		})
	}
}

func TestTransformLoadsStylesheetAndPostProcessesRawResults(t *testing.T) {
	t.Parallel()
	const location = "https://styles.example/sheets/report.xsl"
	const primary = "https://output.example/daily/main"
	const secondary = "https://output.example/daily/side"
	const stylesheet = `<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
		<xsl:template name="start">
			<xsl:sequence select="(2,3)"/>
			<xsl:result-document href="side" method="adaptive" build-tree="no"><xsl:sequence select="7"/></xsl:result-document>
		</xsl:template>
	</xsl:stylesheet>`
	reader := &closeTrackingReader{reader: strings.NewReader(stylesheet)}
	var opens int
	resolver := contractURIResolver(func(_ context.Context, uri string) (io.ReadCloser, error) {
		opens++
		if uri != location || opens != 1 {
			return nil, fmt.Errorf("stylesheet open %d with URI %q, want one open at %q", opens, uri, location)
		}
		return reader, nil
	})
	processed := map[string]int{}
	callback := xdm.FunctionItem{Arity: 2, Invoke: func(_ context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
		if len(args) != 2 || xdm.SequenceLen(args[0]) != 1 {
			return nil, fmt.Errorf("post-process arguments = %v, want URI and result sequence", args)
		}
		uri, ok := args[0].Get(0).(xdm.AtomicValue)
		if !ok || uri.TypeName != xdm.TypeString {
			return nil, fmt.Errorf("post-process URI argument = %v, want one string", args[0])
		}
		var total int64
		for item := range xdm.SequenceItems(args[1]) {
			value, ok := item.(xdm.AtomicValue)
			if !ok || value.TypeName != xdm.TypeInteger {
				return nil, fmt.Errorf("post-process item = %v, want integer", item)
			}
			total += value.IntegerVal()
		}
		processed[uri.StringVal()]++
		return xdm.SingleInteger(total), nil
	}}
	options := xdm.NewMap([]xdm.MapEntry{
		{Key: stringItem("stylesheet-location"), Value: xdm.SingleString("sheets/report.xsl")},
		{Key: stringItem("initial-template"), Value: xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Local: "start"}})},
		{Key: stringItem("base-output-uri"), Value: xdm.SingleString(primary)},
		{Key: stringItem("delivery-format"), Value: xdm.SingleString("raw")},
		{Key: stringItem("post-process"), Value: xdm.ItemSlice{callback}},
	})
	result, err := TransformFunction(WithTransformBaseURI("https://styles.example/main.xsl"), WithTransformURIResolver(resolver)).Call(t.Context(), []xdm.Sequence{xdm.ItemSlice{options}})
	if err != nil || xdm.SequenceLen(result) != 1 {
		t.Fatalf("transform returned %v, %v, want one map", result, err)
	}
	outputs, ok := result.Get(0).(xdm.MapItem)
	if !ok || outputs.Size() != 2 {
		t.Fatalf("transform result = %v, want a map with two results", result)
	}
	for uri, want := range map[string]int64{primary: 5, secondary: 7} {
		value, found := outputs.Get(stringItem(uri))
		if !found || xdm.SequenceLen(value) != 1 || value.Get(0) != (xdm.AtomicValue{TypeName: xdm.TypeInteger, Value: want}) {
			t.Errorf("post-processed result %q = %v, want integer %d", uri, value, want)
		}
	}
	if opens != 1 || reader.closed != 1 || !maps.Equal(processed, map[string]int{primary: 1, secondary: 1}) {
		t.Errorf("stylesheet opened=%d, closed=%d, processed=%v, want one open/close and one callback per output", opens, reader.closed, processed)
	}
}

func TestTransformFunctionSerializedDelivery(t *testing.T) {
	t.Parallel()
	const source = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
		<xsl:param name="label" select="'default'"/>
		<xsl:output method="text"/>
		<xsl:template name="start">
			<xsl:value-of select="upper-case($label)"/>
			<xsl:result-document href="secondary"><xsl:text>side</xsl:text></xsl:result-document>
		</xsl:template>
	</xsl:stylesheet>`
	const secondaryURI = "https://output.example/secondary"
	stringEntry := func(key, value string) xdm.MapEntry {
		return xdm.MapEntry{Key: stringItem(key), Value: xdm.SingleString(value)}
	}
	entries := []xdm.MapEntry{
		stringEntry("stylesheet-text", source),
		stringEntry("delivery-format", "serialized"),
		stringEntry("base-output-uri", "https://output.example/primary"),
		{Key: stringItem("initial-template"), Value: xdm.SingleAtomic(xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Local: "start"}})},
		{Key: stringItem("stylesheet-params"), Value: xdm.ItemSlice{xdm.SingleEntryMap(xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{Local: "label"}}, xdm.SingleString("bound"))}},
	}
	fn := TransformFunction()
	value, err := fn.Call(t.Context(), []xdm.Sequence{xdm.ItemSlice{xdm.NewMap(entries)}})
	if err != nil || xdm.SequenceLen(value) != 1 {
		t.Fatalf("transform returned %v, %v; want one result map", value, err)
	}
	results, ok := value.Get(0).(xdm.MapItem)
	if !ok || results.Size() != 2 {
		t.Fatalf("transform result = %v; want map with exactly two results", value)
	}
	for key, want := range map[string]string{"https://output.example/primary": "BOUND", secondaryURI: "side"} {
		items, found := results.Get(stringItem(key))
		if !found || xdm.SequenceLen(items) != 1 || items.Get(0) != stringItem(want) {
			t.Errorf("result %q = %v; want serialized string %q", key, items, want)
		}
	}
}

func TestTransformFunctionUsesEmbeddedStylesheetContext(t *testing.T) {
	t.Parallel()
	const source = `<wrapper xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:f="urn:unit" xml:base="outer/" xml:space="preserve">
		<xsl:stylesheet version="3.0" xml:base="inner/">
			<xsl:output method="text"/>
			<xsl:template name="f:start"><xsl:value-of select="static-base-uri()"/> <xsl:value-of select="name(document('')/*)"/></xsl:template>
		</xsl:stylesheet>
	</wrapper>`
	for _, tc := range []struct {
		name, explicitBase, want string
	}{
		{name: "inherits_base_and_space", want: "https://styles.example/outer/inner/ xsl:stylesheet"},
		{name: "explicit_base_overrides_ancestors", explicitBase: "override/", want: "https://caller.example/override/inner/ xsl:stylesheet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, source)
			doc.SetURL("https://styles.example/main.xml")
			root := doc.DocumentElement()
			var stylesheet *xdm.Element
			for child := range xdm.Children(root) {
				if element, ok := child.(*xdm.Element); ok {
					stylesheet = element
					break
				}
			}
			if stylesheet == nil {
				t.Fatal("embedded stylesheet element missing from fixture")
			}
			entries := []xdm.MapEntry{
				{Key: stringItem("stylesheet-node"), Value: xdm.ItemSlice{xdm.NodeItem{Node: stylesheet}}},
				{Key: stringItem("initial-template"), Value: xdm.ItemSlice{transformTestQName("urn:unit", "start")}},
				{Key: stringItem("delivery-format"), Value: xdm.SingleString("serialized")},
			}
			if tc.explicitBase != "" {
				entries = append(entries, xdm.MapEntry{Key: stringItem("stylesheet-base-uri"), Value: xdm.SingleString(tc.explicitBase)})
			}
			outputs := transformTestOutputs(t, TransformFunction(WithTransformBaseURI("https://caller.example/main.xsl")), entries)
			requireTransformString(t, outputs, "output", tc.want)
			if stylesheet.Parent() != root {
				t.Fatal("embedded stylesheet was detached from the source document")
			}
			if value, found := stylesheet.GetAttributeNS("space", "http://www.w3.org/XML/1998/namespace"); found {
				t.Errorf("source stylesheet unexpectedly got xml:space=%q", value)
			}
		})
	}
}

func TestTransformFunctionCompilesNamedPackage(t *testing.T) {
	t.Parallel()
	const packageName = "urn:unit:package"
	const location = "https://packages.example/library.xsl"
	const packageSource = `<xsl:package xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		name="urn:unit:package" package-version="2.1" version="3.0">
		<xsl:output method="text"/>
		<xsl:template name="start" visibility="public">
			<xsl:value-of select="static-base-uri()"/>
		</xsl:template>
	</xsl:package>`
	unavailable := errors.New("package is unavailable")
	for _, tc := range []struct {
		name, source, version, wantCode string
		resolveErr                      error
		wantCalls, wantClose            int
	}{
		{name: "matching_package", source: packageSource, version: "2.*", wantCalls: 1, wantClose: 1},
		{name: "invalid_constraint", source: packageSource, version: "2..1", wantCode: "FOXT0002"},
		{name: "resolver_failure", version: "2.*", resolveErr: unavailable, wantCode: "FOXT0003", wantCalls: 1},
		{name: "wrong_version", source: packageSource, version: "3.*", wantCode: "XTSE3000", wantCalls: 1, wantClose: 1},
		{name: "wrong_name", source: strings.Replace(packageSource, packageName, "urn:unit:other", 1), version: "2.*", wantCode: "XTSE3000", wantCalls: 1, wantClose: 1},
		{name: "invalid_xml", source: "<xsl:package>", version: "2.*", wantCode: "FOXT0003", wantCalls: 1, wantClose: 1},
		{name: "invalid_stylesheet", source: strings.Replace(packageSource, "static-base-uri()", "1 +", 1), version: "2.*", wantCode: "XPST0003", wantCalls: 1, wantClose: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			reader := &closeTrackingReader{reader: strings.NewReader(tc.source)}
			resolve := contractPackageResolver(func(_ context.Context, name, version string) (io.ReadCloser, string, error) {
				calls++
				if name != packageName || version != tc.version {
					t.Errorf("package resolution = %q version %q, want %q version %q", name, version, packageName, tc.version)
				}
				if tc.resolveErr != nil {
					return nil, "", tc.resolveErr
				}
				return reader, location, nil
			})
			fn := TransformFunction(WithTransformPackageResolver(resolve))
			opts := xdm.NewMap([]xdm.MapEntry{
				{Key: stringItem("package-name"), Value: xdm.SingleString(packageName)},
				{Key: stringItem("package-version"), Value: xdm.SingleString(tc.version)},
				{Key: stringItem("initial-template"), Value: xdm.ItemSlice{transformTestQName("", "start")}},
				{Key: stringItem("delivery-format"), Value: xdm.SingleString("serialized")},
			})
			result, err := fn.Call(t.Context(), []xdm.Sequence{xdm.ItemSlice{opts}})
			if tc.wantCode == "" {
				if err != nil {
					t.Fatal(err)
				}
				requireTransformString(t, requireTransformResultMap(t, result), "output", location)
			} else {
				var detail *XSLTError
				if xdm.SequenceLen(result) != 0 || !errors.As(err, &detail) || detail.Code != tc.wantCode {
					t.Fatalf("result = %v, error = %v, want no result and error %s", result, err, tc.wantCode)
				}
				if tc.resolveErr != nil && !errors.Is(err, tc.resolveErr) {
					t.Errorf("resolution error = %v, want cause %v", err, tc.resolveErr)
				}
			}
			if calls != tc.wantCalls || reader.closed != tc.wantClose {
				t.Errorf("resolver calls = %d, reader closes = %d, want %d/%d", calls, reader.closed, tc.wantCalls, tc.wantClose)
			}
		})
	}
}

func TestTransformFunctionBindsStaticParametersAndDeliversDocument(t *testing.T) {
	t.Parallel()
	const sheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:f="urn:unit" version="3.0">
		<xsl:param name="f:enabled" static="yes" select="false()"/>
		<xsl:output method="text" build-tree="no"/>
		<xsl:template match="r" use-when="$f:enabled">
			<xsl:sequence select="('selected', string(@label))"/>
		</xsl:template>
	</xsl:stylesheet>`
	source := parseTestDocument(t, `<r label="payload"/>`)
	options := []xdm.MapEntry{
		{Key: stringItem("stylesheet-text"), Value: xdm.SingleString(sheet)},
		{Key: stringItem("source-node"), Value: xdm.ItemSlice{xdm.NodeItem{Node: source.DocumentElement()}}},
		{Key: stringItem("delivery-format"), Value: xdm.SingleString("document")},
		{Key: stringItem("static-params"), Value: xdm.ItemSlice{xdm.SingleEntryMap(transformTestQName("urn:unit", "enabled"), xdm.SingleBoolean(true))}},
	}
	outputs := transformTestOutputs(t, TransformFunction(), options)
	result, found := outputs.Get(stringItem("output"))
	if !found || xdm.SequenceLen(result) != 1 {
		t.Fatalf("output = %v, want one document", result)
	}
	node, ok := result.Get(0).(xdm.NodeItem)
	if !ok || node.Node.Type() != xdm.DocumentNode || xdm.StringValue(node.Node) != "selected payload" {
		t.Fatalf("output = %v, want document containing %q", result, "selected payload")
	}
}

func TestTransformFunctionAppliesSerializationParametersOnlyToPrimary(t *testing.T) {
	t.Parallel()
	const sheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
		<xsl:character-map name="primary"><xsl:output-character character="a" string="A"/></xsl:character-map>
		<xsl:output method="text" item-separator="|" use-character-maps="primary" byte-order-mark="yes"/>
		<xsl:template name="start">
			<xsl:sequence select="('ab', 'a')"/>
			<xsl:result-document href="secondary" byte-order-mark="no"><xsl:sequence select="('ab', 'a')"/></xsl:result-document>
		</xsl:template>
	</xsl:stylesheet>`
	const base = "https://output.example/primary"
	params := xdm.NewMap([]xdm.MapEntry{
		{Key: stringItem("item-separator"), Value: nil},
		{Key: stringItem("byte-order-mark"), Value: xdm.SingleBoolean(false)},
		{Key: stringItem("use-character-maps"), Value: xdm.ItemSlice{xdm.SingleEntryMap(stringItem("b"), xdm.SingleString("B"))}},
	})
	outputs := transformTestOutputs(t, TransformFunction(), []xdm.MapEntry{
		{Key: stringItem("stylesheet-text"), Value: xdm.SingleString(sheet)},
		{Key: stringItem("delivery-format"), Value: xdm.SingleString("serialized")},
		{Key: stringItem("base-output-uri"), Value: xdm.SingleString(base)},
		{Key: stringItem("initial-template"), Value: xdm.ItemSlice{transformTestQName("", "start")}},
		{Key: stringItem("serialization-params"), Value: xdm.ItemSlice{params}},
	})
	if outputs.Size() != 2 {
		t.Fatalf("result contains %d outputs, want two", outputs.Size())
	}
	requireTransformString(t, outputs, base, "AB A")
	requireTransformString(t, outputs, "https://output.example/secondary", "Ab|A")
}

func transformTestQName(uri, local string) xdm.AtomicValue {
	return xdm.AtomicValue{TypeName: xdm.TypeQName, Value: xdm.QNameValue{URI: uri, Local: local}}
}

func transformTestOutputs(t *testing.T, fn xpath.TypedFunctionByArity, options []xdm.MapEntry) xdm.MapItem {
	t.Helper()
	result, err := fn.Call(t.Context(), []xdm.Sequence{xdm.ItemSlice{xdm.NewMap(options)}})
	if err != nil {
		t.Fatal(err)
	}
	return requireTransformResultMap(t, result)
}

func requireTransformResultMap(t *testing.T, result xdm.Sequence) xdm.MapItem {
	t.Helper()
	if xdm.SequenceLen(result) != 1 {
		t.Fatalf("transform result = %v, want one map", result)
	}
	outputs, ok := result.Get(0).(xdm.MapItem)
	if !ok {
		t.Fatalf("transform result = %v, want a map", result)
	}
	return outputs
}

func requireTransformString(t *testing.T, outputs xdm.MapItem, key, want string) {
	t.Helper()
	value, found := outputs.Get(stringItem(key))
	if !found || xdm.SequenceLen(value) != 1 || value.Get(0) != stringItem(want) {
		t.Errorf("result %q = %v, want string %q", key, value, want)
	}
}
