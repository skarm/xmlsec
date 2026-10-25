package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/packageversion"
	"github.com/skarm/xmlsec/transform"
)

func suiteApplicability(options suiteOptions, item suiteCase) (string, string) {
	var (
		dependencies []*suiteNode
		unresolved   []string
	)

	for _, node := range []*suiteNode{item.setNode, item.node} {
		dependencies = append(dependencies, node.children("dependency")...)
		if group := node.child("dependencies"); group != nil {
			dependencies = append(dependencies, group.Children...)
		}
	}

	for _, dependency := range dependencies {
		kind := dependency.attr("type")
		if kind == "" {
			kind = dependency.XMLName.Local
		}

		value := dependency.attr("value")

		matched, known := suiteDependency(options, kind, value)
		if !known {
			unresolved = append(unresolved, fmt.Sprintf("%s=%q", kind, value))
			continue
		}

		if dependency.attr("satisfied") == "false" || dependency.attr("satisfied") == "0" {
			matched = !matched
		}

		if !matched {
			return suiteNotApplicable, fmt.Sprintf("catalog dependency %s=%q (satisfied=%s) does not match the selected language/optional-feature profile", kind, value, dependency.attr("satisfied"))
		}
	}

	if len(unresolved) != 0 {
		return suiteFailed, "unresolved dependencies: " + strings.Join(unresolved, ", ") + "; unknown conditions are not silently skipped"
	}

	return "", ""
}

func suiteDependency(options suiteOptions, kind, value string) (bool, bool) {
	switch kind {
	case "spec":
		return suiteLanguageMatches(options, value), true
	case "feature":
		return suiteFeature(options, value)
	case "xml-version":
		return value == "1.0" || strings.Contains(value, "1.0:5+"), true
	case "xsd-version":
		return value == "1.0", true
	case "unicode-version":
		version, err := strconv.ParseFloat(value, 64)
		return err == nil && version <= 17, err == nil
	case "default-language", "default_language_for_numbering":
		return value == "en", true
	case suiteLanguage, "languages_for_numbering":
		return value == "en", true
	case "unicode-normalization-form":
		return slices.Contains([]string{"NFC", "NFD", "NFKC", "NFKD"}, value), true
	case "additional_normalization_form":
		return strings.HasPrefix(value, "support "), true
	case "default_output_encoding":
		return value == "UTF-8", true
	case "on-multiple-match":
		return value == "recover", true
	case "maximum_number_of_decimal_digits":
		_, err := strconv.Atoi(value)
		return err == nil, err == nil
	default:
		return false, false
	}
}

func suiteLanguageMatches(options suiteOptions, required string) bool {
	prefix := "XP"
	if options.kind == suiteXSLT {
		prefix = "XSLT"
	}

	current, _ := strconv.Atoi(strings.ReplaceAll(options.version, ".", ""))

	for choice := range strings.FieldsSeq(required) {
		if !strings.HasPrefix(choice, prefix) {
			continue
		}

		minimum, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(choice, prefix), "+"))
		if err == nil && (current == minimum || strings.HasSuffix(choice, "+") && current >= minimum) {
			return true
		}
	}

	return false
}

func suiteFeature(options suiteOptions, name string) (bool, bool) {
	switch name {
	case "schemaImport", "schemaValidation", "typedData", "schema_aware", "schema-location-hint", "staticTyping", "moduleImport", "fn-load-xquery-module", "xquery_invocation", "streaming", "streaming-fallback", "infoset-dtd", "dtd", "XML_1.1", "XSD_1.1", "remote_http", "directory-as-collection-uri", "xsl-stylesheet-processing-instruction":
		return false, true
	case "higherOrderFunctions", "higher_order_functions":
		return options.version != suiteVersion20, true
	case "serialization", "namespace-axis", "namespace_axis", "arbitraryPrecisionDecimal", "backwards_compatibility", "built_in_derived_types", "disabling_output_escaping", "dynamic_evaluation", "collection-stability", "non_empty_sequence_collection", "non_unicode_codepoint_collation", "fn-transform-XSLT", "fn-transform-XSLT30", "HTML4", "HTML5":
		return true, true
	case "XPath_3.1":
		return options.version == suiteVersion30 || options.version == suiteVersion31, true
	default:
		return false, false
	}
}

type preparedSuiteEnvironment struct {
	engine             *transform.Engine
	document           *transform.Document
	namespaces         map[string]string
	variables          transform.Bindings
	baseURI, collation string
	contextItem        transform.Value
	contextSpecified   bool
	staticParameters   transform.Bindings
	stylesheet         suiteEnvironmentRef
	decimalFormats     map[transform.Name]map[string]string
	resources          *suiteResourceResolver
	output             *suiteNode
	baseOutputURI      string
	executionVersion   string
	currentTime        time.Time
}

type suitePackage struct {
	name, version, uri string
}

type suiteResourceResolver struct {
	root           string
	resources      map[string]string
	collections    map[string]transform.Sequence
	uriCollections map[string][]string
	packages       []suitePackage
	fileLimit      int
	mediaTypes     map[string]string
}

type suiteMediaReader struct {
	io.ReadCloser
	mediaType string
}

func (r *suiteMediaReader) MediaType() string { return r.mediaType }

func (r *suiteResourceResolver) ResolvePackage(ctx context.Context, name, constraint string) (transform.PackageResource, error) {
	var selected *suitePackage

	for i := range r.packages {
		candidate := &r.packages[i]

		version := packageversion.Parse(candidate.version)
		if candidate.name == name && packageversion.ParseConstraint(constraint).Matches(version) && (selected == nil || version.Compare(packageversion.Parse(selected.version)) > 0) {
			selected = candidate
		}
	}

	if selected == nil {
		return transform.PackageResource{}, fmt.Errorf("suite package %q matching %q is not declared", name, constraint)
	}

	reader, err := r.Resolve(ctx, selected.uri)

	return transform.PackageResource{Reader: reader, BaseURI: selected.uri}, err
}

func (r *suiteResourceResolver) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	path := r.resources[uri]
	if path == "" {
		u, err := url.Parse(uri)
		if err != nil || u.Scheme != suiteFile || u.Host != "" {
			return nil, fmt.Errorf("suite resolver has no explicit mapping for %q", uri)
		}

		path = filepath.FromSlash(u.Path)
	}

	relative, err := filepath.Rel(r.root, path)
	if err != nil {
		return nil, err
	}

	maximum := r.fileLimit
	if maximum == 0 {
		maximum = suiteMaxFileBytes
	}

	raw, _, err := readSuiteFileLimit(r.root, r.root, relative, maximum)
	if err != nil {
		return nil, err
	}

	return &suiteMediaReader{ReadCloser: io.NopCloser(strings.NewReader(string(raw))), mediaType: r.mediaTypes[uri]}, nil
}

func (r *suiteResourceResolver) ResolveCollection(ctx context.Context, uri string) (transform.Sequence, error) {
	if err := ctx.Err(); err != nil {
		return transform.Sequence{}, err
	}

	collection, ok := r.collections[uri]
	if !ok {
		return transform.Sequence{}, fmt.Errorf("suite collection not declared: %q", uri)
	}

	return collection, nil
}

func (r *suiteResourceResolver) ResolveURICollection(ctx context.Context, uri string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	values, ok := r.uriCollections[uri]
	if !ok {
		return nil, fmt.Errorf("suite URI collection not declared: %q", uri)
	}

	return slices.Clone(values), nil
}

func prepareSuiteEnvironment(ctx context.Context, options suiteOptions, item suiteCase) (*preparedSuiteEnvironment, error) {
	resources := &suiteResourceResolver{root: options.directory, resources: make(map[string]string), collections: make(map[string]transform.Sequence), uriCollections: make(map[string][]string)}
	if options.limitsProfile == suiteLanguage {
		resources.fileLimit = suiteLimits(options).MaxInputBytes
	}

	engine, err := transform.NewEngine(transform.Config{Limits: suiteLimits(options), AllowSingleByteEncodings: true, Resolver: resources, CollectionResolver: resources, PackageResolver: resources})
	if err != nil {
		return nil, err
	}

	environment := &preparedSuiteEnvironment{currentTime: options.currentTime, engine: engine, namespaces: make(map[string]string), variables: make(transform.Bindings), staticParameters: make(transform.Bindings), baseURI: suiteFileURI(item.base) + "/", resources: resources, baseOutputURI: "file:///xmlsec-suite-output/"}
	suiteNamespaceDeclarations(item.setNode, environment.namespaces)
	suiteNamespaceDeclarations(item.node, environment.namespaces)

	selected := item.node.child("environment")
	if selected == nil {
		return environment, nil
	}

	ref, err := resolveSuiteEnvironment(item, suiteEnvironmentRef{node: selected, base: item.base}, make(map[*suiteNode]bool))
	if err != nil {
		return nil, err
	}

	// Static context does not depend on the order of metadata declarations.
	suiteNamespaceDeclarations(ref.node, environment.namespaces)

	for _, child := range ref.node.children(suiteNamespace) {
		if err := applySuiteEnvironment(ctx, options.directory, ref.base, resources, environment, child); err != nil {
			return nil, err
		}
	}

	for _, child := range ref.node.Children {
		if isSuiteStaticMetadata(child) && child.XMLName.Local != suiteNamespace {
			if err := applySuiteEnvironment(ctx, options.directory, ref.base, resources, environment, child); err != nil {
				return nil, err
			}
		}
	}

	for _, child := range ref.node.Children {
		if isSuiteStaticMetadata(child) {
			continue
		}

		if err := applySuiteEnvironment(ctx, options.directory, ref.base, resources, environment, child); err != nil {
			return nil, err
		}
	}

	return environment, nil
}

func resolveSuiteEnvironment(item suiteCase, ref suiteEnvironmentRef, seen map[*suiteNode]bool) (suiteEnvironmentRef, error) {
	if seen[ref.node] || len(seen) >= 64 {
		return suiteEnvironmentRef{}, suiteHarness("environment reference cycle or depth limit")
	}

	seen[ref.node] = true

	if name := ref.node.attr("ref"); name != "" {
		parent, ok := item.environments[name]
		if !ok {
			return suiteEnvironmentRef{}, suiteHarness("unknown environment %q", name)
		}

		// The catalog selects the referenced environment. Inline children of
		// the reference do not extend it; see the W3C runner's c:get-environment.
		return resolveSuiteEnvironment(item, parent, seen)
	}

	return ref, nil
}

func isSuiteStaticMetadata(node *suiteNode) bool {
	return node.XMLName.Local == suiteNamespace || node.XMLName.Local == "static-base-uri" || node.XMLName.Local == "collation" || node.XMLName.Local == "decimal-format"
}

func applySuiteEnvironment(ctx context.Context, root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) error {
	switch node.XMLName.Local {
	case suiteNamespace:
		environment.namespaces[node.attr("prefix")] = node.attr("uri")
	case "static-base-uri":
		environment.baseURI = node.attr("uri")
		if environment.baseURI == "#UNDEFINED" {
			environment.baseURI = ""
		}
	case "collation":
		if node.attr("default") == suiteTrue || node.attr("default") == "1" {
			environment.collation = node.attr("uri")
		}
	case "decimal-format":
		return loadSuiteDecimalFormat(environment, node)
	case "source":
		return loadSuiteSource(ctx, root, base, resources, environment, node)
	case "resource":
		return loadSuiteResource(root, base, resources, environment, node)
	case "collection":
		return loadSuiteCollection(ctx, root, base, resources, environment, node)
	case "stylesheet", suitePackageTag:
		return loadSuiteModule(root, base, environment, node)
	case suiteOutput:
		return loadSuiteOutput(base, environment, node)
	case suiteParam:
		return loadSuiteParameter(ctx, environment, node)
	case "context-item":
		environment.contextSpecified = true

		expression := node.attr("select")
		if expression == "" {
			expression = "()"
		}

		value, err := environment.query(ctx, expression, nil)
		if err != nil {
			return suiteHarness("context item: %v", err)
		}

		if value.Len() == 0 {
			environment.contextItem = transform.Value{}
			return nil
		}

		environment.contextItem, err = value.Single()

		return err
	case "schema":
		return suiteHarness("schema-bearing environment is not implemented by the Basic-profile harness")
	case "description", "created", "modified":
	default:
		return suiteHarness("environment item %q is not implemented", node.XMLName.Local)
	}

	return nil
}

func loadSuiteModule(root, base string, environment *preparedSuiteEnvironment, node *suiteNode) error {
	if role := node.attr("role"); role != "" && role != "principal" && role != suiteSecondary {
		return suiteHarness("unknown module role %q", role)
	}

	if node.attr("role") != suiteSecondary {
		if environment.stylesheet.node != nil {
			return suiteHarness("multiple principal modules in an environment or invocation")
		}

		environment.stylesheet = suiteEnvironmentRef{node: node, base: base}
	}

	uri, err := registerSuiteResource(root, base, environment.resources, environment.baseURI, node)
	if err != nil || node.XMLName.Local != suitePackageTag || node.attr("role") != suiteSecondary {
		return err
	}

	declaration, _, err := readSuiteNode(root, base, node.attr(suiteFile))
	if err != nil {
		return suiteHarness("package metadata: %v", err)
	}

	name, version := node.attr("name"), node.attr("package-version")
	if name == "" {
		name = declaration.attr("name")
	}

	if version == "" {
		version = declaration.attr("package-version")
	}

	if version == "" {
		version = "1"
	}

	environment.resources.packages = append(environment.resources.packages, suitePackage{name: name, version: version, uri: uri})

	return nil
}

func loadSuiteOutput(base string, environment *preparedSuiteEnvironment, node *suiteNode) error {
	for _, attribute := range node.Attributes {
		if attribute.Name.Space == "" && !slices.Contains([]string{suiteFile, "serialize", "tree", "well-formed", "result-var"}, attribute.Name.Local) {
			return suiteHarness("unknown output property %q", attribute.Name.Local)
		}
	}

	for _, property := range []string{"serialize", "tree", "well-formed"} {
		if value := node.attr(property); value != "" && value != suiteYes && value != "no" {
			return suiteHarness("invalid output %s=%q", property, value)
		}
	}

	if file := node.attr(suiteFile); file != "" {
		if file == "#absent" {
			environment.baseOutputURI = ""
		} else {
			uri, err := resolveSuiteURI(suiteFileURI(base)+"/", file)
			if err != nil {
				return err
			}

			environment.baseOutputURI = uri
		}
	}

	environment.output = node

	return nil
}

func loadSuiteDecimalFormat(environment *preparedSuiteEnvironment, node *suiteNode) error {
	namespaces := maps.Clone(environment.namespaces)
	suiteNamespaceDeclarations(node, namespaces)

	name, err := suiteQName(node.attr("name"), namespaces)
	if err != nil {
		return err
	}

	if environment.decimalFormats == nil {
		environment.decimalFormats = make(map[transform.Name]map[string]string)
	}

	properties := environment.decimalFormats[name]
	if properties == nil {
		properties = make(map[string]string)
		environment.decimalFormats[name] = properties
	}

	for _, attribute := range node.Attributes {
		if attribute.Name.Space != "" || attribute.Name.Local == "name" {
			continue
		}

		if previous, exists := properties[attribute.Name.Local]; exists && previous != attribute.Value {
			return suiteHarness("conflicting decimal-format property %q", attribute.Name.Local)
		}

		properties[attribute.Name.Local] = attribute.Value
	}

	return nil
}

func loadSuiteParameter(ctx context.Context, environment *preparedSuiteEnvironment, node *suiteNode) error {
	name, err := suiteQName(node.attr("name"), suiteScopedNamespaces(environment, node))
	if err != nil {
		return err
	}

	value, err := suiteParameterValue(ctx, environment, node)
	if err != nil {
		return err
	}

	if static := node.attr("static"); static == suiteTrue || static == "1" || static == suiteYes {
		environment.staticParameters[name] = value
	} else {
		environment.variables[name] = value
	}

	return nil
}

func suiteParameterValue(ctx context.Context, environment *preparedSuiteEnvironment, node *suiteNode) (transform.Sequence, error) {
	scoped := *environment
	scoped.namespaces = suiteScopedNamespaces(environment, node)

	expression := node.attr("select")

	var bindings transform.Bindings

	if source := node.attr("source"); source != "" {
		if expression != "" {
			return transform.Sequence{}, suiteHarness("parameter specifies both select and source")
		}

		expression = "doc($parameterSource)"
		bindings = transform.Bindings{{Local: "parameterSource"}: transform.Values(transform.String(source))}
	}

	if expression == "" || len(node.Children) != 0 {
		return transform.Sequence{}, suiteHarness("parameter requires a select expression or source URI and no child content")
	}

	value, err := scoped.query(ctx, expression, bindings)
	if err != nil {
		return transform.Sequence{}, suiteHarness("parameter %s: %v", node.attr("name"), err)
	}

	return value, nil
}

func loadSuiteSource(ctx context.Context, root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) error {
	doc, err := readSuiteSource(ctx, root, base, resources, environment, node)
	if err != nil {
		return err
	}

	role := node.attr("role")
	if role == "." {
		environment.document = doc
	} else if after, ok := strings.CutPrefix(role, "$"); ok {
		name, err := suiteQName(after, environment.namespaces)
		if err != nil {
			return err
		}

		environment.variables[name] = transform.Values(doc.Root())
	}

	return nil
}

func readSuiteSource(ctx context.Context, root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) (*transform.Document, error) {
	if validation := node.attr("validation"); validation != "" && validation != "skip" {
		return nil, suiteHarness("source validation=%q requires unimplemented harness schema processing", validation)
	}

	var doc *transform.Document

	if name := node.attr(suiteFile); name != "" {
		uri, err := registerSuiteResource(root, base, resources, environment.baseURI, node)
		if err != nil {
			return nil, err
		}

		result, err := environment.query(ctx, "doc($sourceURI)", transform.Bindings{{Local: "sourceURI"}: transform.Values(transform.String(uri))})
		if err != nil {
			return nil, suiteHarness("load source: %v", err)
		}

		value, err := result.Single()
		if err != nil {
			return nil, err
		}

		native, ok := value.Node()
		if !ok {
			return nil, suiteHarness("source is not a document node")
		}

		doc = native.Document()
	} else if content := node.child("content"); content != nil {
		var err error

		doc, err = environment.engine.Parse(ctx, []byte(content.Text))
		if err != nil {
			return nil, suiteHarness("inline source: %v", err)
		}
	} else {
		return nil, suiteHarness("source requires file or textual content")
	}

	return doc, nil
}

func registerSuiteResource(root, base string, resources *suiteResourceResolver, staticBase string, node *suiteNode) (string, error) {
	path, err := localPath(root, base, filepath.FromSlash(node.attr(suiteFile)))
	if err != nil {
		return "", err
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	if !info.Mode().IsRegular() {
		return "", suiteHarness("a resource must be a regular file")
	}

	uri := node.attr("uri")
	if uri == "" {
		uri = suiteFileURI(path)
	}

	resolved, err := resolveSuiteURI(staticBase, uri)
	if err != nil {
		return "", err
	}

	if previous, exists := resources.resources[resolved]; exists && previous != path {
		return "", suiteHarness("conflicting resource URI %q", resolved)
	}

	resources.resources[resolved] = path

	return resolved, nil
}

func resolveSuiteURI(base, uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	if !parsed.IsAbs() {
		baseURI, err := url.Parse(base)
		if err != nil || !baseURI.IsAbs() {
			return "", suiteHarness("relative resource URI requires an absolute static base URI")
		}

		parsed = baseURI.ResolveReference(parsed)
	}

	return parsed.String(), nil
}

func loadSuiteResource(root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) error {
	uri, err := registerSuiteResource(root, base, resources, environment.baseURI, node)
	if err != nil {
		return err
	}

	contentType := node.attr("media-type")
	if encoding := node.attr("encoding"); encoding != "" {
		if contentType == "" {
			contentType = "text/plain"
		}

		mediaType, parameters, err := mime.ParseMediaType(contentType)
		if err != nil {
			return suiteHarness("resource media type: %v", err)
		}

		parameters["charset"] = encoding
		contentType = mime.FormatMediaType(mediaType, parameters)
	}

	if resources.mediaTypes == nil {
		resources.mediaTypes = make(map[string]string)
	}

	if previous, exists := resources.mediaTypes[uri]; exists && previous != contentType {
		return suiteHarness("conflicting resource media type for %q", uri)
	}

	resources.mediaTypes[uri] = contentType

	return nil
}

func loadSuiteCollection(ctx context.Context, root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) error {
	uri := node.attr("uri")
	if uri != "" {
		resolved, err := resolveSuiteURI(environment.baseURI, uri)
		if err != nil {
			return err
		}

		uri = resolved
	}

	var (
		items []transform.Value
		uris  []string
	)

	for _, child := range node.Children {
		switch child.XMLName.Local {
		case "source":
			doc, err := readSuiteSource(ctx, root, base, resources, environment, child)
			if err != nil {
				return err
			}

			items = append(items, doc.Root())

			if child.attr(suiteFile) != "" {
				memberURI, err := registerSuiteResource(root, base, resources, environment.baseURI, child)
				if err != nil {
					return err
				}

				uris = append(uris, memberURI)
			}
		case "query":
			values, err := environment.query(ctx, child.Text, nil)
			if err != nil {
				return suiteHarness("collection query: %v", err)
			}

			for index := range values.Len() {
				value, _ := values.At(index)
				items = append(items, value)
			}
		default:
			return suiteHarness("collection item %q is not implemented", child.XMLName.Local)
		}
	}

	resources.collections[uri] = transform.Values(items...)
	resources.uriCollections[uri] = uris

	return nil
}

func suiteFileURI(path string) string {
	return (&url.URL{Scheme: suiteFile, Path: filepath.ToSlash(path)}).String()
}

func suiteNamespaceDeclarations(node *suiteNode, namespaces map[string]string) {
	if node == nil {
		return
	}

	maps.Copy(namespaces, node.namespaces)

	for _, attribute := range node.Attributes {
		if attribute.Name.Space == "xmlns" {
			namespaces[attribute.Name.Local] = attribute.Value
		}
	}
}

func suiteQName(lexical string, namespaces map[string]string) (transform.Name, error) {
	if strings.HasPrefix(lexical, "Q{") {
		space, local, ok := strings.Cut(lexical[2:], "}")
		if !ok || local == "" {
			return transform.Name{}, suiteHarness("invalid EQName %q", lexical)
		}

		return transform.Name{Space: space, Local: local}, nil
	}

	prefix, local, prefixed := strings.Cut(lexical, ":")
	if !prefixed {
		return transform.Name{Local: lexical}, nil
	}

	space, ok := namespaces[prefix]
	if !ok {
		return transform.Name{}, suiteHarness("unbound catalog QName %q", lexical)
	}

	return transform.Name{Space: space, Local: local}, nil
}

func (e *preparedSuiteEnvironment) query(ctx context.Context, expression string, extra transform.Bindings) (transform.Sequence, error) {
	bindings := make(transform.Bindings, len(e.variables)+len(extra))
	maps.Copy(bindings, e.variables)

	maps.Copy(bindings, extra)

	query, err := e.engine.CompileXPath(ctx, expression, transform.XPathOptions{Version: transform.XPath31, Namespaces: e.namespaces, BaseURI: e.baseURI, DefaultCollation: e.collation, DecimalFormats: e.decimalFormats})
	if err != nil {
		return transform.Sequence{}, err
	}

	return query.Evaluate(ctx, e.document, transform.XPathContext{Variables: bindings, ContextItem: e.contextItem, Context: suiteDynamicContext(e.currentTime)})
}

func suiteDynamicContext(currentTime time.Time) transform.DynamicContext {
	if currentTime.IsZero() {
		currentTime, _ = time.Parse(time.RFC3339Nano, suiteDefaultCurrentTime)
	}

	return transform.DynamicContext{CurrentTime: currentTime, ImplicitTimezone: time.UTC, DefaultLanguage: "en"}
}
