package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/transform"
)

func TestReadBindingsPreservesTypesAndExpandedNames(t *testing.T) {
	t.Parallel()

	path := testutil.WriteFile(t, t.TempDir(), "bindings.json", []byte(`[
		{"name":{"Space":"urn:first","Local":"v"},"type":"string","value":"text"},
		{"name":{"Space":"urn:second","Local":"v"},"type":"integer","value":"9223372036854775808"},
		{"name":{"Local":"price"},"type":"decimal","value":"2.50"},
		{"name":{"Local":"enabled"},"type":"boolean","value":"true"},
		{"name":{"Local":"disabled"},"type":"boolean","value":"false"},
		{"name":{"Local":"time"},"type":"dateTime","value":"2026-01-02T03:04:05.125Z"}
	]`))
	got, err := readBindings(t.Context(), path)
	if err != nil || len(got) != 6 {
		t.Fatalf("readBindings = %d bindings, %v; want six bindings", len(got), err)
	}
	for _, tc := range []struct {
		name          transform.Name
		kind, lexical string
	}{
		{transform.Name{Space: "urn:first", Local: "v"}, "string", "text"},
		{transform.Name{Space: "urn:second", Local: "v"}, "integer", "9223372036854775808"},
		{transform.Name{Local: "price"}, "decimal", "2.5"},
		{transform.Name{Local: "enabled"}, "boolean", "true"},
		{transform.Name{Local: "disabled"}, "boolean", "false"},
		{transform.Name{Local: "time"}, "dateTime", "2026-01-02T03:04:05.125Z"},
	} {
		item, err := got[tc.name].Single()
		if err != nil {
			t.Errorf("binding %v must contain one item: %v", tc.name, err)
			continue
		}
		text, err := item.Text()
		wantType := transform.Name{Space: "http://www.w3.org/2001/XMLSchema", Local: tc.kind}
		if err != nil || text != tc.lexical || item.Type() != wantType {
			t.Errorf("binding %v = (%v, %q, %v), want (%v, %q, nil)", tc.name, item.Type(), text, err, wantType, tc.lexical)
		}
	}
}

func TestReadBindingsRejectsInvalidEntriesWithoutPartialResult(t *testing.T) {
	t.Parallel()

	const good = `{"name":{"Local":"x"},"type":"string","value":"ok"}`
	for _, tc := range []struct {
		name, bad, message string
		usage              bool
	}{
		{"duplicate_name", good, "duplicate variable x", true},
		{"invalid_integer", `{"name":{"Local":"y"},"type":"integer","value":"2.5"}`, "invalid integer", true},
		{"invalid_boolean", `{"name":{"Local":"y"},"type":"boolean","value":"1"}`, "requires true or false", true},
		{"invalid_decimal", `{"name":{"Local":"y"},"type":"decimal","value":"1e2"}`, "decimal", false},
		{"invalid_datetime", `{"name":{"Local":"y"},"type":"dateTime","value":"today"}`, "cannot parse", false},
		{"unsupported_type", `{"name":{"Local":"y"},"type":"array","value":"[]"}`, "binding type must be", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := testutil.WriteFile(t, t.TempDir(), "bindings.json", []byte("["+good+","+tc.bad+"]"))
			got, err := readBindings(t.Context(), path)
			var usage usageFailure
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.message) || errors.As(err, &usage) != tc.usage {
				t.Errorf("readBindings = (%v, %v), want nil result and error containing %q (usage: %t)", got, err, tc.message, tc.usage)
			}
		})
	}
}

func TestReadBindingsEnforcesCountLimit(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		count int
	}{
		{"exact_limit", 256},
		{"one_over_limit", 257},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			values := make([]bindingValue, 0, tc.count)
			for i := range tc.count {
				value := strconv.Itoa(i)
				values = append(values, bindingValue{Name: transform.Name{Local: "v" + value}, Type: "integer", Value: value})
			}
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			path := testutil.WriteFile(t, t.TempDir(), "bindings.json", raw)
			got, err := readBindings(t.Context(), path)
			if tc.count == 257 {
				if got != nil || exitCode(err) != cliExitUsage {
					t.Errorf("readBindings over limit = (%d bindings, %v), want nil and a usage error", len(got), err)
				}
				return
			}
			if err != nil || len(got) != 256 {
				t.Fatalf("readBindings at limit = (%d bindings, %v), want 256", len(got), err)
			}
			if text, err := got[transform.Name{Local: "v255"}].Text(); err != nil || text != "255" {
				t.Errorf("final binding = (%q, %v), want 255", text, err)
			}
		})
	}
}

func TestXPathCLIUsesDefaultNamespace(t *testing.T) {
	t.Parallel()

	const src = `<root xmlns="urn:catalog"><item>one</item><item>two</item></root>`
	got := cli(t, []byte(src), "transform", "xpath", "-namespace", "=urn:catalog", "-expression", "count(/root/item)")
	if string(got) != "2\n" {
		t.Errorf("XPath result = %q, want 2 with a final newline", got)
	}
}

func TestXPathCLIJSONPreservesNodesAndAtomicTypes(t *testing.T) {
	t.Parallel()

	const src = `<root><item xmlns="urn:catalog">one</item></root>`
	got := cli(t, []byte(src), "transform", "xpath", "-expression", `(/root/*, [true(), 'last'])`, "-format", "json")
	const want = `[{"kind":"element","name":{"Space":"urn:catalog","Local":"item"},"value":"one"},
		[[{"type":{"Space":"http://www.w3.org/2001/XMLSchema","Local":"boolean"},"value":"true"}],
		 [{"type":{"Space":"http://www.w3.org/2001/XMLSchema","Local":"string"},"value":"last"}]]]`
	var actual, expected any
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatalf("invalid result JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatalf("invalid expected JSON: %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("XPath JSON = %s, want %s", got, want)
	}
}

func TestTransformCLIRejectsInvalidOptionsWithoutOutput(t *testing.T) {
	t.Parallel()

	sheet := testutil.WriteFile(t, t.TempDir(), "sheet.xsl", []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"/>`))
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing_expression", []string{"xpath"}},
		{"missing_stylesheet", []string{"xslt"}},
		{"invalid_xpath_version", []string{"xpath", "-expression", "1", "-version", "4.0"}},
		{"invalid_xslt_version", []string{"xslt", "-stylesheet", sheet, "-version", "3.1"}},
		{"invalid_format", []string{"xpath", "-expression", "1", "-format", "xml"}},
		{"empty_namespace_uri", []string{"xpath", "-expression", "1", "-namespace", "p="}},
		{"duplicate_namespace", []string{"xpath", "-expression", "1", "-namespace", "p=urn:first", "-namespace", "p=urn:second"}},
		{"unserialized_function", []string{"xpath", "-expression", "count#1", "-format", "json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			args := append(append([]string{"transform"}, tc.args...), "-in", "")
			err := run(t.Context(), args, nil, &stdout, io.Discard)
			if exitCode(err) != cliExitUsage || stdout.Len() != 0 {
				t.Errorf("run(%v) = exit %d (%v), output %q; want usage error and no output", args, exitCode(err), err, &stdout)
			}
		})
	}
}

func TestXSLTCLIRunsNamedTemplateWithStaticBindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sheet := testutil.WriteFile(t, dir, "sheet.xsl", []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:test" version="3.0">
		<xsl:param name="p:enabled" static="yes" required="yes"/>
		<xsl:output method="text"/>
		<xsl:template name="p:start" use-when="$p:enabled"><xsl:text>done</xsl:text></xsl:template>
	</xsl:stylesheet>`))
	bindings := testutil.WriteFile(t, dir, "static.json", []byte(`[{"name":{"Space":"urn:test","Local":"enabled"},"type":"boolean","value":"true"}]`))
	got := cli(t, nil, "transform", "xslt", "-in", "", "-stylesheet", sheet, "-template", "{urn:test}start", "-static-bindings", bindings, "-format", "json")
	var result struct {
		Primary []byte
	}
	if err := json.Unmarshal(got, &result); err != nil || string(result.Primary) != "done" {
		t.Errorf("XSLT JSON = %s (%v), want primary result %q", got, err, "done")
	}
}

func TestXSLTCLIDoesNotSubstituteDefaultForMalformedName(t *testing.T) {
	t.Parallel()

	sheet := testutil.WriteFile(t, t.TempDir(), "sheet.xsl", []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">
		<xsl:output method="text"/><xsl:template match="/">default</xsl:template>
	</xsl:stylesheet>`))
	for _, flag := range []string{"-template", "-mode"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			args := []string{"transform", "xslt", "-stylesheet", sheet, flag, "{urn:example}"}
			if err := run(t.Context(), args, strings.NewReader("<r/>"), &out, io.Discard); exitCode(err) != cliExitUsage || out.Len() != 0 {
				t.Errorf("run with malformed %s published %q and returned %v", flag, &out, err)
			}
		})
	}
}
