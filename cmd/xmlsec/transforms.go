package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
)

type bindingValue struct {
	Name  transform.Name `json:"name"`
	Type  string         `json:"type"`
	Value string         `json:"value"`
}

func readBindings(ctx context.Context, path string) (transform.Bindings, error) {
	b := transform.Bindings{}
	if path == "" {
		return b, nil
	}

	var values []bindingValue
	if err := readJSONFile(ctx, path, &values); err != nil {
		return nil, err
	}

	if len(values) > 256 {
		return nil, usageError("too many variables")
	}

	for _, v := range values {
		if _, ok := b[v.Name]; ok {
			return nil, usageError("duplicate variable %s", v.Name.Local)
		}

		var (
			item transform.Value
			err  error
		)

		switch v.Type {
		case "string":
			item = transform.String(v.Value)
		case "integer":
			n, ok := new(big.Int).SetString(v.Value, 10)
			if !ok {
				return nil, usageError("invalid integer variable")
			}

			item = transform.BigInteger(n)
		case "decimal":
			item, err = transform.Decimal(v.Value)
		case "boolean":
			if v.Value != valueTrue && v.Value != valueFalse {
				return nil, usageError("boolean variable requires true or false")
			}

			item = transform.Boolean(v.Value == valueTrue)
		case "dateTime":
			var t time.Time

			t, err = time.Parse(time.RFC3339Nano, v.Value)
			item = transform.DateTime(t)
		default:
			return nil, usageError("binding type must be string, integer, decimal, boolean or dateTime")
		}

		if err != nil {
			return nil, err
		}

		b[v.Name] = transform.Values(item)
	}

	return b, nil
}

func namespaces(values []string) (map[string]string, error) {
	out := map[string]string{}

	for _, s := range values {
		prefix, uri, ok := strings.Cut(s, "=")
		if !ok || uri == "" {
			return nil, usageError("-namespace requires PREFIX=URI (empty prefix allowed)")
		}

		if _, exists := out[prefix]; exists {
			return nil, usageError("duplicate namespace prefix %q", prefix)
		}

		out[prefix] = uri
	}

	return out, nil
}

func runTransform(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("transform "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "source XML; empty string for a context-free expression/template")
	output := fs.String("out", "-", "output path")
	expression := fs.String("expression", "", "XPath expression")
	sheetFile := fs.String("stylesheet", "", "local XSLT stylesheet")
	version := fs.String("version", "", "XPath 1.0/2.0/3.0/3.1 or XSLT 1.0/2.0/3.0; empty uses library default")
	format := fs.String("format", "text", "XPath output: text (singleton) or json (typed sequence); XSLT: text or json (all result documents)")
	variables := fs.String("bindings", "", "trusted JSON typed variable/parameter array")
	static := fs.String("static-bindings", "", "trusted JSON XSLT 3.0 static parameter array")
	resources := fs.String("resources", "", "trusted URI/path allowlist for imports and URI functions")
	baseURI := fs.String("base-uri", "", "explicit base URI")
	template := fs.String("template", "", "named XSLT template, Clark name {URI}local or local")
	mode := fs.String("mode", "", "XSLT mode, Clark name {URI}local or local")
	programBytes := fs.Int("max-program-bytes", 64<<10, "maximum expression/stylesheet bytes")
	operations := fs.Int("max-operations", 2_000_000, "XPath/XSLT operation budget")
	engineTimeout := fs.Duration("engine-timeout", 3*time.Second, "maximum duration per engine invocation")

	var nsFlags repeatedFlag
	fs.Var(&nsFlags, "namespace", "PREFIX=URI static namespace; repeatable")

	specific := "in out version format bindings resources base-uri max-program-bytes max-operations engine-timeout"
	if cmd == nameXPath {
		specific += " expression namespace"
	} else {
		specific += " stylesheet static-bindings template mode"
	}

	fs = commandFlags(fs, specific, false)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	ns, err := namespaces(nsFlags)
	if err != nil {
		return err
	}

	bindings, err := readBindings(ctx, *variables)
	if err != nil {
		return err
	}

	config := transform.Config{Limits: transform.Limits{MaxInputBytes: exec.xml.MaxBytes, MaxProgramBytes: *programBytes, MaxOutputBytes: exec.output, MaxNodes: exec.xml.MaxNodes, MaxDepth: exec.xml.MaxDepth, MaxOperations: *operations, Timeout: *engineTimeout}}

	config.Resolver, err = transformResolver(ctx, *resources)
	if err != nil {
		return err
	}

	if cmd == nameXPath && *expression == "" {
		return usageError("-expression is required")
	}

	if cmd != nameXPath && *sheetFile == "" {
		return usageError("-stylesheet is required")
	}

	engine, err := transform.NewEngine(config)
	if err != nil {
		return err
	}

	var doc *transform.Document

	if *input != "" {
		raw, err := readInputContext(ctx, *input, stdin, exec.xml.MaxBytes)
		if err != nil {
			return err
		}

		doc, err = engine.Parse(ctx, raw)
		if err != nil {
			return err
		}
	}

	if cmd == nameXPath {
		return (xpathCommand{expression: *expression, version: *version, baseURI: *baseURI, format: *format, output: *output, namespaces: ns, bindings: bindings}).run(ctx, engine, doc, stdout)
	}

	if *sheetFile == "" {
		return usageError("-stylesheet is required")
	}

	raw, err := readInputContext(ctx, *sheetFile, nil, *programBytes)
	if err != nil {
		return err
	}

	versions := map[string]transform.XSLTVersion{"": 0, version10: transform.XSLT10, version20: transform.XSLT20, version30: transform.XSLT30}

	v, ok := versions[*version]
	if !ok {
		return usageError("invalid XSLT version")
	}

	staticBindings, err := readBindings(ctx, *static)
	if err != nil {
		return err
	}

	sheet, err := engine.CompileXSLT(ctx, raw, transform.XSLTOptions{Version: v, BaseURI: *baseURI, StaticParameters: staticBindings})
	if err != nil {
		return err
	}

	result, err := sheet.Transform(ctx, doc, transform.XSLTContext{Parameters: bindings, Template: parseQName(*template), Mode: parseQName(*mode), BaseOutputURI: *baseURI})
	if err != nil {
		return err
	}

	if *format == "json" {
		return jsonOutput(ctx, *output, stdout, result)
	}

	if *format != "text" {
		return usageError("-format must be text or json")
	}

	if len(result.Secondary) > 0 {
		return usageError("stylesheet produced secondary documents; use -format json to retain all results")
	}

	return writeOutputContext(ctx, *output, stdout, result.Primary)
}

func parseQName(s string) transform.Name {
	if strings.HasPrefix(s, "{") {
		uri, local, ok := strings.Cut(s[1:], "}")
		if ok {
			return document.Name{Space: uri, Local: local}
		}
	}

	return document.Name{Local: s}
}

func canonicalizeXPath(ctx context.Context, doc *document.Document, expression string, ns map[string]string, opt c14n.Options) ([]byte, error) {
	tr := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: expression, Namespaces: ns}}}
	e := execution(ctx)

	engine, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}, Limits: transform.Limits{MaxInputBytes: e.xml.MaxBytes, MaxOutputBytes: e.output, MaxNodes: e.xml.MaxNodes, MaxDepth: e.xml.MaxDepth, MaxOperations: e.nodeVisits}})
	if err != nil {
		return nil, err
	}

	set, err := doc.AllNodes(ctx)
	if err != nil {
		return nil, err
	}

	data, err := reference.Nodes(set)
	if err != nil {
		return nil, err
	}

	output, err := reference.Process(ctx, data, []reference.Transform{tr, {Algorithm: opt.Algorithm, InclusivePrefixes: opt.InclusivePrefixes}}, reference.Options{Extension: engine, AllowedTransforms: []string{reference.XPath, opt.Algorithm}, MaxInputBytes: e.xml.MaxBytes, MaxOutputBytes: e.output, MaxProducedBytes: e.output, MaxNodeVisits: e.nodeVisits, XMLLimits: e.xml})
	if err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

type xpathCommand struct {
	expression, version, baseURI, format, output string
	namespaces                                   map[string]string
	bindings                                     transform.Bindings
}

func (c xpathCommand) run(ctx context.Context, engine *transform.Engine, doc *transform.Document, stdout io.Writer) error {
	if c.expression == "" {
		return usageError("-expression is required")
	}

	versions := map[string]transform.XPathVersion{"": transform.XPath31, version10: transform.XPath10, version20: transform.XPath20, version30: transform.XPath30, version31: transform.XPath31}

	v, ok := versions[c.version]
	if !ok {
		return usageError("invalid XPath version")
	}

	q, err := engine.CompileXPath(ctx, c.expression, transform.XPathOptions{Version: v, Namespaces: c.namespaces, BaseURI: c.baseURI})
	if err != nil {
		return err
	}

	result, err := q.Evaluate(ctx, doc, transform.XPathContext{Variables: c.bindings})
	if err != nil {
		return err
	}

	if c.format == "text" {
		value, err := result.Text()
		if err != nil {
			return err
		}

		return writeOutputContext(ctx, c.output, stdout, []byte(value+"\n"))
	}

	if c.format != "json" {
		return usageError("-format must be text or json")
	}

	value, err := sequenceJSON(result, 0)
	if err != nil {
		return err
	}

	return jsonOutput(ctx, c.output, stdout, value)
}

func sequenceJSON(sequence transform.Sequence, depth int) (any, error) {
	if depth > 128 {
		return nil, errors.New("result nesting exceeds 128")
	}

	out := make([]any, 0, sequence.Len())
	for i := 0; i < sequence.Len(); i++ {
		value, _ := sequence.At(i)

		item, err := itemJSON(value, depth)
		if err != nil {
			return nil, err
		}

		out = append(out, item)
	}

	return out, nil
}

func itemJSON(value transform.Value, depth int) (any, error) {
	switch value.Kind() {
	case transform.AtomicValue:
		text, err := value.Text()
		if err != nil {
			return nil, err
		}

		return map[string]any{fieldType: value.Type(), fieldValue: text}, nil
	case transform.NodeValue:
		node, _ := value.Node()
		return map[string]any{fieldKind: node.Kind(), "name": node.Name(), fieldValue: node.StringValue()}, nil
	case transform.ArrayValue:
		size, err := value.Size()
		if err != nil {
			return nil, err
		}

		out := make([]any, size)
		for i := range out {
			member, err := value.Member(i)
			if err != nil {
				return nil, err
			}

			out[i], err = sequenceJSON(member, depth+1)
			if err != nil {
				return nil, err
			}
		}

		return out, nil
	case transform.MapValue:
		return mapJSON(value, depth)
	default:
		return nil, usageError("function items require explicit serialization in the XPath expression")
	}
}

func mapJSON(value transform.Value, depth int) (any, error) {
	keys, err := value.Keys()
	if err != nil {
		return nil, err
	}

	entries := make([]any, 0, len(keys))
	for _, key := range keys {
		text, err := key.Text()
		if err != nil {
			return nil, err
		}

		sequence, _ := value.Lookup(key)

		item, err := sequenceJSON(sequence, depth+1)
		if err != nil {
			return nil, err
		}

		entries = append(entries, map[string]any{"key": text, fieldType: key.Type(), fieldValue: item})
	}

	return entries, nil
}

func transformResolver(ctx context.Context, path string) (transform.Resolver, error) {
	if path == "" {
		return nil, nil
	}

	entries, resolver, err := loadResourcesContext(ctx, path)
	if err != nil {
		return nil, err
	}

	if err := validateResourceAllowlist(entries); err != nil {
		return nil, err
	}

	return resolver, nil
}
