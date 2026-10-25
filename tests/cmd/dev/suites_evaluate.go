package main

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"strings"

	"github.com/skarm/xmlsec/transform"
)

type suiteEvaluation struct {
	environment  *preparedSuiteEnvironment
	options      suiteOptions
	item         suiteCase
	sequence     transform.Sequence
	result       *transform.Result
	err          error
	secondaryURI string
}

func evaluateSuiteCase(ctx context.Context, options suiteOptions, item suiteCase, environment *preparedSuiteEnvironment) *suiteEvaluation {
	evaluation := &suiteEvaluation{environment: environment, options: options, item: item}
	if options.kind == suiteQT3 {
		evaluation.sequence, evaluation.err = evaluateQT3(ctx, options, item, environment)
	} else {
		evaluation.result, evaluation.err = evaluateXSLTSuite(ctx, options, item, environment)
		if evaluation.result != nil {
			evaluation.sequence = evaluation.result.Primary()
			if environment.output != nil && evaluation.err == nil {
				evaluation.err = evaluation.prepareOutput(ctx)
			}
		}
	}

	return evaluation
}

func (e *suiteEvaluation) prepareOutput(ctx context.Context) error {
	if e.environment.output.attr("serialize") == suiteYes {
		_, err := e.serialized(ctx)
		return err
	}

	if e.environment.output.attr("tree") == suiteYes {
		value, err := e.assertionValue(ctx, `parse-xml-fragment(serialize($result, map{'method':'xml','omit-xml-declaration':true(),'indent':false()}))`, nil)
		if err != nil {
			return err
		}

		e.sequence = value
	}

	return nil
}

func evaluateQT3(ctx context.Context, options suiteOptions, item suiteCase, environment *preparedSuiteEnvironment) (transform.Sequence, error) {
	test := item.node.child("test")
	if test == nil {
		return transform.Sequence{}, suiteHarness("test expression is missing")
	}

	expression := test.Text
	if test.attr(suiteFile) != "" {
		raw, _, err := readSuiteFile(options.directory, item.base, test.attr(suiteFile))
		if err != nil {
			return transform.Sequence{}, suiteHarness("query file: %v", err)
		}

		expression = string(raw)
	}

	version := transform.XPath31
	switch options.version {
	case suiteVersion20:
		version = transform.XPath20
	case suiteVersion30:
		version = transform.XPath30
	}

	query, err := environment.engine.CompileXPath(ctx, expression, transform.XPathOptions{Version: version, Namespaces: environment.namespaces, BaseURI: environment.baseURI, DefaultCollation: environment.collation, DecimalFormats: environment.decimalFormats})
	if err != nil {
		return transform.Sequence{}, err
	}

	environment.executionVersion = options.version

	return query.Evaluate(ctx, environment.document, transform.XPathContext{Variables: environment.variables, ContextItem: environment.contextItem, Context: suiteDynamicContext(environment.currentTime)})
}

func evaluateXSLTSuite(ctx context.Context, options suiteOptions, item suiteCase, environment *preparedSuiteEnvironment) (*transform.Result, error) {
	test := item.node.child("test")
	if test == nil {
		return nil, suiteHarness("test invocation is missing")
	}

	if err := prepareSuiteInvocation(ctx, options, item, test, environment); err != nil {
		return nil, err
	}

	compiled, err := compileSuiteStylesheet(ctx, options, environment)
	if err != nil {
		return nil, err
	}

	environment.executionVersion = fmt.Sprintf("%d.%d", compiled.Version()/10, compiled.Version()%10)

	invocation := transform.XSLTContext{Parameters: environment.variables, Context: suiteDynamicContext(environment.currentTime), BaseOutputURI: environment.baseOutputURI}
	if environment.contextSpecified {
		invocation.ContextItem = &environment.contextItem
	}

	if initial := test.child("initial-template"); initial != nil {
		name := initial.attr("name")
		if name == "" {
			name = "Q{http://www.w3.org/1999/XSL/Transform}initial-template"
		}

		invocation.Template, err = suiteQName(name, suiteScopedNamespaces(environment, initial))
		if err != nil {
			return nil, err
		}

		if err := suiteInitialParameters(ctx, environment, initial, &invocation); err != nil {
			return nil, err
		}
	}

	if initial := test.child("initial-mode"); initial != nil {
		if err := suiteInitialParameters(ctx, environment, initial, &invocation); err != nil {
			return nil, err
		}

		invocation.Mode, err = suiteQName(initial.attr("name"), suiteScopedNamespaces(environment, initial))
		if err != nil {
			return nil, err
		}

		if selectExpression := initial.attr("select"); selectExpression != "" {
			selectionContext := *environment
			selectionContext.document = nil
			selectionContext.contextItem = transform.Value{}
			selectionContext.namespaces = suiteScopedNamespaces(environment, initial)

			selection, err := selectionContext.query(ctx, selectExpression, nil)
			if err != nil {
				return nil, suiteHarness("initial selection: %v", err)
			}

			return compiled.ApplyTemplates(ctx, environment.document, selection, invocation)
		}
	}

	if initial := test.child("initial-function"); initial != nil {
		return suiteFunctionInvocation(ctx, compiled, environment, initial, invocation)
	}

	if environment.document == nil && invocation.Template.Local == "" && test.child("initial-mode") == nil {
		invocation.Template = transform.Name{Space: suiteStylesheetNS, Local: "initial-template"}
	}

	return compiled.Execute(ctx, environment.document, invocation)
}

func suiteFunctionInvocation(ctx context.Context, compiled *transform.Stylesheet, environment *preparedSuiteEnvironment, initial *suiteNode, invocation transform.XSLTContext) (*transform.Result, error) {
	name, err := suiteQName(initial.attr("name"), suiteScopedNamespaces(environment, initial))
	if err != nil {
		return nil, err
	}

	arguments := make([]transform.Sequence, 0, len(initial.Children))
	for _, parameter := range initial.Children {
		if parameter.XMLName.Local != suiteParam {
			return nil, suiteHarness("unknown initial-function argument %q", parameter.XMLName.Local)
		}

		value, err := suiteParameterValue(ctx, environment, parameter)
		if err != nil {
			return nil, err
		}

		arguments = append(arguments, value)
	}

	return compiled.CallFunction(ctx, environment.document, name, arguments, invocation)
}

func suiteInitialParameters(ctx context.Context, environment *preparedSuiteEnvironment, initial *suiteNode, invocation *transform.XSLTContext) error {
	invocation.InitialParameters, invocation.TunnelParameters = make(transform.Bindings), make(transform.Bindings)

	for _, node := range initial.Children {
		if node.XMLName.Local != suiteParam {
			return suiteHarness("unknown initial invocation parameter %q", node.XMLName.Local)
		}

		name, err := suiteQName(node.attr("name"), suiteScopedNamespaces(environment, node))
		if err != nil {
			return err
		}

		value, err := suiteParameterValue(ctx, environment, node)
		if err != nil {
			return err
		}

		if node.attr("tunnel") == suiteYes || node.attr("tunnel") == suiteTrue || node.attr("tunnel") == "1" {
			invocation.TunnelParameters[name] = value
		} else {
			invocation.InitialParameters[name] = value
		}
	}

	return nil
}

func prepareSuiteInvocation(ctx context.Context, options suiteOptions, item suiteCase, test *suiteNode, environment *preparedSuiteEnvironment) error {
	if test.child("stylesheet") != nil || test.child(suitePackageTag) != nil {
		environment.stylesheet = suiteEnvironmentRef{}
	}

	entries := 0

	for _, node := range test.Children {
		switch node.XMLName.Local {
		case suiteParam:
			if err := loadSuiteParameter(ctx, environment, node); err != nil {
				return err
			}
		case "stylesheet", suitePackageTag:
			if err := loadSuiteModule(options.directory, item.base, environment, node); err != nil {
				return err
			}
		case suiteOutput:
			if err := loadSuiteOutput(item.base, environment, node); err != nil {
				return err
			}
		case "initial-template", "initial-mode", "initial-function":
			entries++
		case "posture-and-sweep":
			return suiteHarness("invocation item %q is not implemented", node.XMLName.Local)
		default:
			return suiteHarness("unknown invocation item %q", node.XMLName.Local)
		}
	}

	if entries > 1 {
		return suiteHarness("an invocation cannot select multiple initial entry points")
	}

	return nil
}

func compileSuiteStylesheet(ctx context.Context, options suiteOptions, environment *preparedSuiteEnvironment) (*transform.Stylesheet, error) {
	stylesheet, base := environment.stylesheet.node, environment.stylesheet.base

	if stylesheet == nil || stylesheet.attr(suiteFile) == "" {
		return nil, suiteHarness("a stylesheet file in the test invocation is required by this harness")
	}

	raw, path, err := readSuiteFile(options.directory, base, stylesheet.attr(suiteFile))
	if err != nil {
		return nil, suiteHarness("stylesheet: %v", err)
	}

	if err := checkSuiteStylesheetVersion(options, path); err != nil {
		return nil, err
	}

	baseURI := suiteFileURI(path)
	if stylesheet.attr("uri") != "" {
		baseURI, err = resolveSuiteURI(environment.baseURI, stylesheet.attr("uri"))
		if err != nil {
			return nil, err
		}
	}

	processor := transform.XSLT30
	if options.version == suiteVersion20 {
		processor = transform.XSLT20
	}

	return environment.engine.CompileXSLT(ctx, raw, transform.XSLTOptions{ProcessorVersion: processor, BaseURI: baseURI, StaticParameters: environment.staticParameters})
}

func checkSuiteStylesheetVersion(options suiteOptions, path string) error {
	if options.version != suiteVersion20 {
		return nil
	}

	node, _, err := readSuiteNode(options.directory, filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return suiteHarness("stylesheet declaration: %v", err)
	}

	version := node.attr(suiteVersion)
	if node.XMLName.Space != suiteStylesheetNS {
		version = ""

		for _, attribute := range node.Attributes {
			if attribute.Name.Space == suiteStylesheetNS && attribute.Name.Local == suiteVersion {
				version = attribute.Value
			}
		}
	}

	if strings.HasPrefix(version, "3") {
		return suiteHarness("forcing XSLT 2.0 forwards-compatible processing of a 3.0 declaration is not implemented by the harness")
	}

	return nil
}

func (e *suiteEvaluation) serialized(ctx context.Context) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}

	if e.result != nil {
		if e.secondaryURI != "" {
			var output strings.Builder

			_, err := e.result.WriteSecondary(ctx, e.secondaryURI, &output)

			return []byte(output.String()), err
		}

		output, err := e.result.Serialize(ctx)
		if err != nil {
			return nil, err
		}

		return output.Primary, nil
	}

	result, err := e.environment.query(ctx, `serialize($result, map{'method':'xml', 'omit-xml-declaration':true(), 'indent':false()})`, transform.Bindings{{Local: suiteResultVariable}: e.sequence})
	if err != nil {
		return nil, err
	}

	text, err := result.Text()

	return []byte(text), err
}

func (e *suiteEvaluation) assertionValue(ctx context.Context, expression string, extra transform.Bindings) (transform.Sequence, error) {
	bindings := transform.Bindings{{Local: suiteResultVariable}: e.sequence}
	if variable := e.environment.output.attr("result-var"); variable != "" {
		bindings[transform.Name{Local: variable}] = e.sequence
	}

	maps.Copy(bindings, extra)

	assertionContext := *e.environment
	assertionContext.document = nil

	assertionContext.contextItem = transform.Value{}
	if e.sequence.Len() == 1 {
		assertionContext.contextItem, _ = e.sequence.At(0)
	}

	result, err := assertionContext.query(ctx, expression, bindings)
	if err != nil {
		return transform.Sequence{}, suiteHarness("assertion evaluation: %v", err)
	}

	return result, nil
}

func (e *suiteEvaluation) assertionTrue(ctx context.Context, expression string, extra transform.Bindings) error {
	result, err := e.assertionValue(ctx, expression, extra)
	if err != nil {
		return err
	}

	value, err := result.Single()
	if err != nil {
		return suiteHarness("assertion did not return one item: %v", err)
	}

	matched, err := value.Boolean()
	if err != nil {
		return suiteHarness("assertion did not return a boolean: %v", err)
	}

	if !matched {
		return fmt.Errorf("%s assertion was false", e.item.node.attr("name"))
	}

	return nil
}
