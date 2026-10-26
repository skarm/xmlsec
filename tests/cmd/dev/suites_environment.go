package main

import (
	"bytes"
	"context"
	"encoding/xml"
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
	"unicode"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/packageversion"
	"github.com/skarm/xmlsec/transform"
)

func suiteApplicability(options suiteOptions, item suiteCase) (string, string) {
	var (
		dependencies          []*suiteNode
		unresolved            []string
		compatibilityDeclared bool
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
		if kind == "feature" && value == "xpath-1.0-compatibility" {
			compatibilityDeclared = true
		}

		matched, known := suiteDependency(options, kind, value)
		if known && matched && kind == "combinations_for_numbering" && dependency.attr("range") != "" {
			actual, supported := suiteNumberingRange(value)
			matched = supported && strings.Join(strings.Fields(dependency.attr("range")), " ") == actual
		}

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

	// QT3 guide/running.html requires the default compatibility property to be
	// false unless the test explicitly requests XPath 1.0 compatibility. A
	// compatibility-only run must not reinterpret ordinary modern expressions.
	if options.kind == suiteQT3 && options.xpath10Compatibility && !compatibilityDeclared {
		return suiteNotApplicable, "QT3 tests without an xpath-1.0-compatibility dependency require the default false compatibility property (guide/running.html)"
	}

	if status, reason := suiteEnvironmentApplicability(item); status != "" {
		return status, reason
	}

	if len(unresolved) != 0 {
		return suiteFailed, "unresolved dependencies: " + strings.Join(unresolved, ", ") + "; unknown conditions are not silently skipped"
	}

	return "", ""
}

// These catalog source properties require optional preprocessing, independently
// of explicit dependency elements. The pinned catalog schema requires XInclude
// expansion when requested and excludes processors that do not support it.
func suiteEnvironmentApplicability(item suiteCase) (string, string) {
	if item.node == nil {
		return "", ""
	}

	selected := item.node.child("environment")
	if selected == nil {
		return "", ""
	}

	ref, err := resolveSuiteEnvironment(item, suiteEnvironmentRef{node: selected, base: item.base}, make(map[*suiteNode]struct{}))
	if err != nil {
		return "", ""
	} // Preparation retains its existing harness error.

	// QT3's schema element explicitly implies a schema-awareness dependency
	// (catalog-schema.xsd, schema documentation). Do not erase the requested
	// annotations to run those cases as untyped Basic input. XSLT's catalog has
	// a different declaration contract, so unused XSLT schemas stay applicable.
	for _, schema := range ref.node.children("schema") {
		if schema.XMLName.Space == "http://www.w3.org/2010/09/qt-fots-catalog" && !suiteBuiltinJSONSchema(schema) {
			return suiteNotApplicable, "QT3 catalog schema declaration implies schema-awareness, which is outside the selected Basic profile (catalog-schema.xsd: schema)"
		}
	}

	sources := ref.node.children("source")
	for _, collection := range ref.node.children("collection") {
		sources = append(sources, collection.children("source")...)
	}

	for _, source := range sources {
		if status, reason := suiteSourceRequirements(source); status != "" {
			return status, reason
		}
	}

	return "", ""
}

func suiteSourceRequirements(source *suiteNode) (string, string) {
	for _, name := range []string{"xinclude", "streaming", "defines-stylesheet"} {
		value := strings.Trim(source.attr(name), " \t\r\n")
		if value == "" || value == "false" || value == "0" {
			continue
		}

		if value != "true" && value != "1" {
			return suiteFailed, fmt.Sprintf("invalid source %s=%q", name, value)
		}

		if name == "xinclude" || source.attr("role") == "." {
			return suiteNotApplicable, fmt.Sprintf("source %s=%q requires optional preprocessing outside the selected language profile", name, value)
		}
	}

	if value := strings.Trim(source.attr("xml-version"), " \t\r\n"); value != "" {
		version := suiteSourceXMLVersion(value)
		if version == "" {
			return suiteFailed, fmt.Sprintf("invalid source xml-version=%q", value)
		}

		if version == "1.1" {
			return suiteNotApplicable, "source xml-version requires the optional XML 1.1 input profile"
		}
	}

	return "", ""
}

// The catalog uses an xs:decimal enumeration. Compare its exact value without
// rounding unsupported versions to 1.0 or 1.1 through a float conversion.
func suiteSourceXMLVersion(value string) string {
	value = strings.TrimPrefix(value, "+")

	whole, fraction, _ := strings.Cut(value, ".")
	if strings.IndexFunc(whole+fraction, func(r rune) bool { return r < '0' || r > '9' }) >= 0 || strings.TrimLeft(whole, "0") != "1" {
		return ""
	}

	switch strings.TrimRight(fraction, "0") {
	case "":
		return "1.0"
	case "1":
		return "1.1"
	default:
		return ""
	}
}

func suiteDependency(options suiteOptions, kind, value string) (bool, bool) {
	switch kind {
	case "spec":
		return suiteLanguageMatches(options, value), true
	case "feature":
		return suiteFeature(options, value)
	case "xml-version":
		return value == suiteVersion10 || strings.Contains(value, "1.0:5+"), true
	case "xsd-version":
		return value == suiteXSDVersionName(options), true
	case "unicode-version":
		// Catalog dependencies name an edition, not a minimum. Category counts
		// and case mappings can change between Unicode releases.
		return value == strings.TrimSuffix(unicode.Version, ".0"), true
	case "default-language", "default_language_for_numbering":
		return value == "en", true
	case suiteLanguage, "languages_for_numbering":
		return value == "en", true
	case "unicode-normalization-form":
		return slices.Contains([]string{"NFC", "NFD", "NFKC", "NFKD", "FULLY-NORMALIZED"}, value), true
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
		return suiteImplementationDependency(options, kind, value)
	}
}

func suiteImplementationDependency(options suiteOptions, kind, value string) (bool, bool) {
	switch kind {
	case "limits":
		return value == "year_lt_0", value == "year_lt_0"
	case "year_component_values":
		switch value {
		case "support negative year", "support year above 9999":
			return true, true
		case "support year zero":
			return suiteXSDVersion(options) == transform.XMLSchema11, true
		}
	case "calendar", "supported_calendars_in_date_formatting_functions":
		return value == "AD" || value == "ISO", true
	case "default_calendar_in_date_formatting_functions":
		return value == "AD", true
	case "package_version_resolution":
		return value == "highest_version" || value == "unspecified", true
	case "enable_assertions":
		return options.xsltAssertions, true
	case "detect_accumulator_cycles", "recognize_id_as_uri_fragment":
		return true, true
	case "ignore_doc_failure":
		return false, true
	case "unparsed_text_encoding":
		return strings.EqualFold(value, "UTF-8"), true
	case "default_html_version":
		return value == "5", true
	case "available_documents":
		// The runner has no implicit remote documents. Declared environment
		// resources are installed separately and never enable network fallback.
		return false, true
	case "extension-function":
		if value == "Q{http://relaxng.org/ns/structure/1.0}schema-report#1" {
			return false, true
		}
	case "format-integer-sequence":
		switch value {
		case "١", "①", "⑴", "⒈", "Α", "α", "一":
			return true, true
		case "ﯴ":
			return false, true
		}
	case "combinations_for_numbering":
		return suiteNumberingCombination(value)
	}

	return false, false
}

func suiteNumberingCombination(value string) (bool, bool) {
	switch value {
	case "CIRCLED DIGIT ONE", "PARENTHESIZED DIGIT ONE", "DIGIT ONE FULL STOP",
		"DOUBLE CIRCLED DIGIT ONE", "DINGBAT NEGATIVE CIRCLED DIGIT ONE",
		"DINGBAT CIRCLED SANS-SERIF DIGIT ONE", "DINGBAT NEGATIVE CIRCLED SANS-SERIF DIGIT ONE",
		"PARENTHESIZED IDEOGRAPH ONE", "CIRCLED IDEOGRAPH ONE", "AEGEAN NUMBER ONE",
		"COPTIC EPACT DIGIT ONE", "RUMI DIGIT ONE", "BRAHMI NUMBER ONE", "SINHALA ARCHAIC DIGIT ONE",
		"COUNTING ROD UNIT DIGIT ONE", "MENDE KIKAKUI DIGIT ONE", "DIGIT ONE COMMA",
		"GREEK SMALL LETTER ALPHA (ALPHABETIC)":
		return true, true
	case "GREEK SMALL LETTER ALPHA (TRADITIONAL)":
		return false, true
	default:
		return false, false
	}
}

// The catalog's range describes the processor's exact range, including tests
// whose expected decimal fallback depends on exceeding that range.
func suiteNumberingRange(value string) (string, bool) {
	switch value {
	case "CIRCLED DIGIT ONE":
		return "0 to 50", true
	case "PARENTHESIZED DIGIT ONE":
		return "1 to 20", true
	case "DIGIT ONE FULL STOP", "DINGBAT NEGATIVE CIRCLED DIGIT ONE":
		return "0 to 20", true
	case "DOUBLE CIRCLED DIGIT ONE", "PARENTHESIZED IDEOGRAPH ONE", "CIRCLED IDEOGRAPH ONE",
		"AEGEAN NUMBER ONE", "COPTIC EPACT DIGIT ONE", "RUMI DIGIT ONE", "BRAHMI NUMBER ONE", "SINHALA ARCHAIC DIGIT ONE":
		return "1 to 10", true
	case "DINGBAT CIRCLED SANS-SERIF DIGIT ONE", "DINGBAT NEGATIVE CIRCLED SANS-SERIF DIGIT ONE":
		return "0 to 10", true
	case "COUNTING ROD UNIT DIGIT ONE", "MENDE KIKAKUI DIGIT ONE":
		return "1 to 9", true
	case "DIGIT ONE COMMA":
		return "0 to 9", true
	default:
		return "", false
	}
}

func suiteXSDVersionName(options suiteOptions) string {
	if options.xsdVersion == suiteVersion11 {
		return suiteVersion11
	}

	return suiteVersion10
}

func suiteXSDVersion(options suiteOptions) transform.XMLSchemaVersion {
	if suiteXSDVersionName(options) == suiteVersion11 {
		return transform.XMLSchema11
	}

	return transform.XMLSchema10
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
	case "schemaImport", "schemaValidation", "typedData", "schema_aware", "schema-location-hint", "staticTyping", "moduleImport", "fn-load-xquery-module", "xquery_invocation", "streaming", "streaming-fallback", "XML_1.1", "remote_http", "directory-as-collection-uri", "xsl-stylesheet-processing-instruction":
		return false, true
	case "xpath-1.0-compatibility":
		return options.xpath10Compatibility, true
	case "simple-uca-fallback", "advanced-uca-fallback", "olson-timezone":
		return true, true
	case "XSD_1.1":
		return suiteXSDVersion(options) == transform.XMLSchema11, true
	case "higherOrderFunctions", "higher_order_functions":
		return options.version != suiteVersion20, true
	case "infoset-dtd", "dtd", "serialization", "namespace-axis", "namespace_axis", "arbitraryPrecisionDecimal", "backwards_compatibility", "built_in_derived_types", "disabling_output_escaping", "dynamic_evaluation", "collection-stability", "non_empty_sequence_collection", "non_unicode_codepoint_collation", "fn-transform-XSLT", "fn-transform-XSLT30", "HTML4", "HTML5":
		return true, true
	case "XPath_3.1":
		return options.version == suiteVersion30 || options.version == suiteVersion31, true
	default:
		return false, false
	}
}

type preparedSuiteEnvironment struct {
	engine           *transform.Engine
	document         *transform.Document
	namespaces       map[string]string
	variables        transform.Bindings
	baseURI          string
	collation        string
	contextItem      transform.Value
	contextSpecified bool
	staticParameters transform.Bindings
	stylesheet       suiteEnvironmentRef
	decimalFormats   map[transform.Name]map[string]string
	resources        *suiteResourceResolver
	documents        map[string]*transform.Document
	output           *suiteNode
	baseOutputURI    string
	executionVersion string
	currentTime      time.Time
}

type suitePackage struct {
	name    string
	version string
	uri     string
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

type suiteResourceResolver struct {
	root           string
	resources      map[string]string
	unavailable    map[string]string // declared remote files; never fetched by this offline runner
	collections    map[string]transform.Sequence
	uriCollections map[string][]string
	packages       []suitePackage
	fileLimit      int
	mediaTypes     map[string]string
}

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

	if remote, declared := r.unavailable[uri]; declared {
		return nil, fmt.Errorf("declared resource %q is unavailable in the offline suite profile", remote)
	}

	path := r.resources[uri]
	if path == "" && filepath.IsAbs(uri) {
		path = uri
	}

	if path == "" {
		u, err := url.Parse(uri)
		if err != nil || u.Host != "" || u.Scheme != suiteFile {
			return nil, fmt.Errorf("suite resolver has no explicit mapping for %q", uri)
		}

		path = suiteFileURIPath(u.Path)
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

	return &suiteMediaReader{ReadCloser: io.NopCloser(bytes.NewReader(raw)), mediaType: r.mediaTypes[uri]}, nil
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

type suiteMediaReader struct {
	io.ReadCloser
	mediaType string
}

func (r *suiteMediaReader) MediaType() string { return r.mediaType }

func prepareSuiteEnvironment(ctx context.Context, options suiteOptions, item suiteCase) (*preparedSuiteEnvironment, error) {
	return prepareSuiteEnvironmentWithLimits(ctx, options, item, suiteLimits(options))
}

// prepareSuiteEnvironmentWithLimits keeps fixture construction and all resource
// policies identical when reproducing a case with explicit finite host budgets.
func prepareSuiteEnvironmentWithLimits(ctx context.Context, options suiteOptions, item suiteCase, limits transform.Limits) (*preparedSuiteEnvironment, error) {
	resources := &suiteResourceResolver{root: options.directory, resources: make(map[string]string), collections: make(map[string]transform.Sequence), uriCollections: make(map[string][]string)}
	if options.limitsProfile == suiteLanguage {
		resources.fileLimit = limits.MaxInputBytes
	}

	engine, err := transform.NewEngine(transform.Config{Limits: limits, XMLSchemaVersion: suiteXSDVersion(options), EnableXSLTAssertions: options.xsltAssertions, AllowSingleByteEncodings: true, Resolver: resources, CollectionResolver: resources, PackageResolver: resources})
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

	ref, err := resolveSuiteEnvironment(item, suiteEnvironmentRef{node: selected, base: item.base}, make(map[*suiteNode]struct{}))
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

func resolveSuiteEnvironment(item suiteCase, ref suiteEnvironmentRef, seen map[*suiteNode]struct{}) (suiteEnvironmentRef, error) {
	if _, exists := seen[ref.node]; exists || len(seen) >= 64 {
		return suiteEnvironmentRef{}, suiteHarness("environment reference cycle or depth limit")
	}

	seen[ref.node] = struct{}{}

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
	case suiteResourceTag:
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
			return suiteHarness("context item: %w", err)
		}

		if value.Len() == 0 {
			environment.contextItem = transform.Value{}
			return nil
		}

		environment.contextItem, err = value.Single()

		return err
	case "schema":
		return loadSuiteSchema(root, base, resources, environment, node)
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

	resourceNode := node
	if node.XMLName.Local == suitePackageTag && node.attr("role") == suiteSecondary {
		// A package URI identifies a package, not a single source file. Distinct
		// versions have distinct retrieval/base URIs even when their name agrees.
		resourceNode = suiteRetrievalResource(node)
	}

	uri, err := registerSuiteResource(root, base, environment.resources, environment.baseURI, resourceNode)
	if err != nil || node.XMLName.Local != suitePackageTag || node.attr("role") != suiteSecondary {
		return err
	}

	declaration, _, err := readSuiteReferencedNode(root, base, node)
	if err != nil {
		return suiteHarness("package metadata: %w", err)
	}

	name, version := suitePackageIdentity(node, declaration)
	environment.resources.packages = append(environment.resources.packages, suitePackage{name: name, version: version, uri: uri})

	return nil
}

func suitePackageIdentity(catalog, declaration *suiteNode) (string, string) {
	name, version := catalog.attr("name"), catalog.attr("package-version")
	if name == "" {
		name = catalog.attr("uri")
	}

	if declaration.XMLName == (xml.Name{Space: lexicon.NamespaceXSLT, Local: suitePackageTag}) {
		// The publisher runner registers sourceLocation, so the package's own
		// declaration supplies its identity. Catalog metadata does not rewrite it.
		// For computed shadow attributes, explicit catalog values remain discovery
		// hints; the compiler alone evaluates and validates the effective identity.
		shadowName, shadowVersion := false, false
		for _, attribute := range declaration.Attributes {
			shadowName = shadowName || attribute.Name == (xml.Name{Local: "_name"})
			shadowVersion = shadowVersion || attribute.Name == (xml.Name{Local: "_package-version"})
		}

		if !shadowName && declaration.attr("name") != "" {
			name = declaration.attr("name")
		}

		if !shadowVersion {
			version = declaration.attr("package-version")
		}
	}

	if version == "" {
		version = "1"
	}

	return name, version
}

// A package name or schema target namespace identifies its content, not the
// retrieval URI of one particular file. Preserve the distinct local resources.
func suiteRetrievalResource(node *suiteNode) *suiteNode {
	copyNode := *node
	copyNode.Attributes = slices.DeleteFunc(slices.Clone(node.Attributes), func(a xml.Attr) bool { return a.Name.Space == "" && a.Name.Local == "uri" })

	return &copyNode
}

func loadSuiteSchema(root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) error {
	if node.XMLName.Space != suiteXSLTNamespace {
		// QT3 imports the built-in functions namespace without a schema file
		// for untyped json-to-xml. This supplies no schema validation;
		// validate=true still reaches the evaluator's FOJS0004.
		if suiteBuiltinJSONSchema(node) {
			return nil
		}

		return suiteHarness("schema-bearing environment is not implemented by the Basic-profile harness")
	}

	switch node.attr("role") {
	case "", "stylesheet-import", "source-reference", suiteSecondary:
	default:
		return suiteHarness("unknown schema role %q", node.attr("role"))
	}
	// Declaring an available schema does not require validation. A Basic
	// compiler must still diagnose import-schema/type requests itself. Source
	// validation remains explicit and is rejected by readSuiteSource.
	_, err := registerSuiteResource(root, base, resources, environment.baseURI, suiteRetrievalResource(node))

	return err
}

func suiteBuiltinJSONSchema(node *suiteNode) bool {
	return node.XMLName.Space == "http://www.w3.org/2010/09/qt-fots-catalog" && node.attr("role") == "import" && node.attr("uri") == lexicon.NamespaceFn && node.attr(suiteFile) == ""
}

func loadSuiteOutput(base string, environment *preparedSuiteEnvironment, node *suiteNode) error {
	file, fileSpecified := "", false

	for _, attribute := range node.Attributes {
		if attribute.Name.Space == "" && !slices.Contains([]string{suiteFile, "serialize", "tree", "well-formed", "result-var"}, attribute.Name.Local) {
			return suiteHarness("unknown output property %q", attribute.Name.Local)
		}

		if attribute.Name.Space == "" && attribute.Name.Local == suiteFile {
			file, fileSpecified = attribute.Value, true
		}
	}

	for _, property := range []string{"serialize", "tree", "well-formed"} {
		if value := node.attr(property); value != "" && value != suiteYes && value != "no" {
			return suiteHarness("invalid output %s=%q", property, value)
		}
	}

	if fileSpecified {
		if file == "#absent" {
			environment.baseOutputURI = ""
		} else {
			location := node.baseURI
			if location == "" {
				location = suiteFileURI(base) + "/"
			}

			uri, err := resolveSuiteURI(location, file)
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
		return transform.Sequence{}, suiteHarness("parameter %s: %w", node.attr("name"), err)
	}

	return value, nil
}

func loadSuiteSource(ctx context.Context, root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) error {
	if status, reason := suiteSourceRequirements(node); status != "" {
		return suiteHarness("%s", reason)
	}
	// Sources without a role only declare retrievable resources. Defer their
	// XML parse to doc()/document(), where the test can assert loading errors.
	if node.attr("role") == "" && node.attr(suiteFile) != "" && node.attr("validation") == "" {
		_, err := registerSuiteResource(root, base, resources, environment.baseURI, node)
		return err
	}

	if node.attr(suiteFile) == "" && node.child("content") == nil && node.attr("select") != "" {
		return loadSuiteSelectedSource(ctx, environment, node)
	}

	doc, uri, err := readSuiteSource(ctx, root, base, resources, environment, node)
	if err != nil {
		return err
	}

	value, fragment, err := suiteSourceValue(ctx, environment, doc, uri, node)
	if err != nil {
		return err
	}

	role := node.attr("role")
	if role == "." {
		environment.document = doc
		if fragment {
			environment.contextItem, environment.contextSpecified = value, true
		}

		if expression := node.attr("select"); expression != "" {
			scoped := *environment

			scoped.contextItem = transform.Value{}
			if fragment {
				scoped.contextItem = value
			}

			scoped.namespaces = suiteScopedNamespaces(environment, node)

			selected, err := scoped.query(ctx, expression, nil)
			if err != nil {
				return suiteHarness("source selection: %w", err)
			}

			environment.contextItem, err = selected.Single()
			if err != nil {
				return suiteHarness("source selection must be a singleton: %w", err)
			}

			environment.contextSpecified = true
		}
	} else if after, ok := strings.CutPrefix(role, "$"); ok {
		name, err := suiteQName(after, suiteScopedNamespaces(environment, node))
		if err != nil {
			return err
		}

		environment.variables[name] = transform.Values(value)
	}

	return nil
}

// loadSuiteSelectedSource evaluates a source constructor once, without an
// implicit context document. Its selected node retains its owning document.
func loadSuiteSelectedSource(ctx context.Context, environment *preparedSuiteEnvironment, node *suiteNode) error {
	if node.attr("role") != "." {
		return suiteHarness("a select-only source requires role=\".\"")
	}

	if validation := node.attr("validation"); validation != "" && validation != "skip" {
		return suiteHarness("source validation=%q requires unimplemented harness schema processing", validation)
	}

	scoped := *environment
	scoped.document = nil
	scoped.contextItem = transform.Value{}
	scoped.namespaces = suiteScopedNamespaces(environment, node)

	selected, err := scoped.query(ctx, node.attr("select"), nil)
	if err != nil {
		return suiteHarness("source selection: %w", err)
	}

	value, err := selected.Single()
	if err != nil {
		return suiteHarness("source selection must be a singleton: %w", err)
	}

	environment.document = nil
	if selectedNode, ok := value.Node(); ok {
		environment.document = selectedNode.Document()
	}

	environment.contextItem, environment.contextSpecified = value, true

	return nil
}

func readSuiteSource(ctx context.Context, root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) (*transform.Document, string, error) {
	if status, reason := suiteSourceRequirements(node); status != "" {
		return nil, "", suiteHarness("%s", reason)
	}

	if validation := node.attr("validation"); validation != "" && validation != "skip" {
		return nil, "", suiteHarness("source validation=%q requires unimplemented harness schema processing", validation)
	}

	var (
		doc       *transform.Document
		sourceURI string
	)

	if name := node.attr(suiteFile); name != "" {
		uri, err := registerSuiteResource(root, base, resources, environment.baseURI, node)
		if err != nil {
			return nil, "", err
		}

		sourceURI = uri

		uri, _, err = suiteRetrievalURI(uri)
		if err != nil {
			return nil, "", err
		}

		if cached := environment.documents[uri]; cached != nil {
			return cached, sourceURI, nil
		}

		result, err := environment.query(ctx, "doc($sourceURI)", transform.Bindings{{Local: "sourceURI"}: transform.Values(transform.String(uri))})
		if err != nil {
			return nil, "", suiteHarness("load source: %w", err)
		}

		doc, err = suiteParsedDocument(result)
		if err != nil {
			return nil, "", err
		}

		if environment.documents == nil {
			environment.documents = make(map[string]*transform.Document)
		}

		environment.documents[uri] = doc
	} else if content := node.child("content"); content != nil {
		// The publisher's c:parse-xml uses the content element's own base,
		// independently of the transformation's static base URI.
		scoped := *environment
		scoped.baseURI = content.baseURI

		result, err := scoped.query(ctx, "parse-xml($inlineSource)", transform.Bindings{{Local: "inlineSource"}: transform.Values(transform.String(content.Text))})
		if err != nil {
			return nil, "", suiteHarness("inline source: %w", err)
		}

		doc, err = suiteParsedDocument(result)
		if err != nil {
			return nil, "", err
		}
	} else {
		return nil, "", suiteHarness("source requires file or textual content")
	}

	return doc, sourceURI, nil
}

func suiteParsedDocument(result transform.Sequence) (*transform.Document, error) {
	value, err := result.Single()
	if err != nil {
		return nil, suiteHarness("source must be a singleton document: %w", err)
	}

	native, ok := value.Node()
	if !ok {
		return nil, suiteHarness("source is not a document node")
	}

	return native.Document(), nil
}

func suiteSourceValue(ctx context.Context, environment *preparedSuiteEnvironment, doc *transform.Document, uri string, node *suiteNode) (transform.Value, bool, error) {
	_, fragment, err := suiteRetrievalURI(uri)
	if err != nil {
		return transform.Value{}, false, err
	}

	file, err := url.Parse(node.attr(suiteFile))
	if err != nil {
		return transform.Value{}, false, err
	}

	if fragment != "" && file.Fragment != "" && fragment != file.Fragment {
		return transform.Value{}, true, suiteHarness("conflicting source fragments %q and %q", fragment, file.Fragment)
	}

	if fragment == "" {
		fragment = file.Fragment
	}

	if fragment == "" {
		return doc.Root(), false, nil
	}
	// Catalog source fragments use shorthand XML IDs. More general XPointer
	// schemes are not silently replaced by the containing document.
	selected, err := environment.query(ctx, "if (string(Q{http://www.w3.org/2001/XMLSchema}NCName($fragment)) eq $fragment) then id($fragment, $document) else ()", transform.Bindings{{Local: "fragment"}: transform.Values(transform.String(fragment)), {Local: "document"}: transform.Values(doc.Root())})
	if err != nil {
		return transform.Value{}, true, suiteHarness("source fragment %q: %w", fragment, err)
	}

	value, err := selected.Single()
	if err != nil {
		return transform.Value{}, true, suiteHarness("source fragment %q must identify one element: %w", fragment, err)
	}

	return value, true, nil
}

func registerSuiteResource(root, base string, resources *suiteResourceResolver, staticBase string, node *suiteNode) (string, error) {
	file, err := url.Parse(node.attr(suiteFile))
	if err == nil && node.XMLName.Local == suiteResourceTag && (file.Scheme == "http" || file.Scheme == "https") && file.Host != "" && file.User == nil && file.Fragment == "" {
		return registerSuiteRemoteResource(resources, staticBase, node, file.String())
	}

	if err != nil || file.IsAbs() || file.Host != "" || file.User != nil || file.RawQuery != "" || file.ForceQuery {
		return "", suiteHarness("invalid local resource reference %q", node.attr(suiteFile))
	}

	path, err := suiteLocalReferencePath(root, base, node, file)
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
		if file.Fragment != "" {
			uri += "#" + file.EscapedFragment()
		}
	}

	resolved, err := resolveSuiteURI(staticBase, uri)
	if err != nil {
		return "", err
	}

	retrieval, _, err := suiteRetrievalURI(resolved)
	if err != nil {
		return "", err
	}

	if previous, exists := resources.resources[retrieval]; exists && previous != path {
		return "", suiteHarness("conflicting resource URI %q", resolved)
	}

	if _, exists := resources.unavailable[retrieval]; exists {
		return "", suiteHarness("conflicting resource URI %q", resolved)
	}

	resources.resources[retrieval] = path

	return resolved, nil
}

// The catalog may declare shared remote resources that a test never reads.
// Record their unavailability lazily; declarations do not authorize network I/O.
func registerSuiteRemoteResource(resources *suiteResourceResolver, staticBase string, node *suiteNode, file string) (string, error) {
	uri := node.attr("uri")
	if uri == "" {
		uri = file
	}

	resolved, err := resolveSuiteURI(staticBase, uri)
	if err != nil {
		return "", err
	}

	retrieval, _, err := suiteRetrievalURI(resolved)
	if err != nil {
		return "", err
	}

	if _, exists := resources.resources[retrieval]; exists {
		return "", suiteHarness("conflicting resource URI %q", resolved)
	}

	if previous, exists := resources.unavailable[retrieval]; exists && previous != file {
		return "", suiteHarness("conflicting resource URI %q", resolved)
	}

	if resources.unavailable == nil {
		resources.unavailable = make(map[string]string)
	}

	resources.unavailable[retrieval] = file

	return resolved, nil
}

func suiteRetrievalURI(uri string) (string, string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", "", err
	}

	fragment := parsed.Fragment
	parsed.Fragment, parsed.RawFragment = "", ""

	return parsed.String(), fragment, nil
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
	_, err := registerSuiteTextResource(root, base, resources, environment, node)
	return err
}

func registerSuiteTextResource(root, base string, resources *suiteResourceResolver, environment *preparedSuiteEnvironment, node *suiteNode) (string, error) {
	uri, err := registerSuiteResource(root, base, resources, environment.baseURI, node)
	if err != nil {
		return "", err
	}

	contentType := node.attr("media-type")
	if encoding := node.attr("encoding"); encoding != "" {
		if contentType == "" {
			contentType = "text/plain"
		}

		mediaType, parameters, err := mime.ParseMediaType(contentType)
		if err != nil {
			return "", suiteHarness("resource media type: %w", err)
		}

		parameters["charset"] = encoding
		contentType = mime.FormatMediaType(mediaType, parameters)
	}

	if resources.mediaTypes == nil {
		resources.mediaTypes = make(map[string]string)
	}

	if previous, exists := resources.mediaTypes[uri]; exists && previous != contentType {
		return "", suiteHarness("conflicting resource media type for %q", uri)
	}

	resources.mediaTypes[uri] = contentType

	return uri, nil
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
			doc, memberURI, err := readSuiteSource(ctx, root, base, resources, environment, child)
			if err != nil {
				return err
			}

			value, _, err := suiteSourceValue(ctx, environment, doc, memberURI, child)
			if err != nil {
				return err
			}

			items = append(items, value)
			if memberURI != "" {
				uris = append(uris, memberURI)
			}
		case "query":
			scoped := *environment
			scoped.namespaces = suiteScopedNamespaces(environment, child)

			values, err := scoped.query(ctx, child.Text, nil)
			if err != nil {
				return suiteHarness("collection query: %w", err)
			}

			for index := range values.Len() {
				value, _ := values.At(index)
				items = append(items, value)
			}
		case suiteResourceTag:
			// Catalog resourceType describes a file read as text. Use the same
			// typed reader, decoder and budgets as standalone unparsed-text().
			memberURI, err := registerSuiteTextResource(root, base, resources, environment, child)
			if err != nil {
				return err
			}

			values, err := environment.query(ctx, "unparsed-text($collectionResource)", transform.Bindings{{Local: "collectionResource"}: transform.Values(transform.String(memberURI))})
			if err != nil {
				return suiteHarness("collection resource: %w", err)
			}

			value, err := values.Single()
			if err != nil {
				return suiteHarness("collection text resource must be a singleton: %w", err)
			}

			items = append(items, value)
			uris = append(uris, memberURI)
		default:
			return suiteHarness("collection item %q is not implemented", child.XMLName.Local)
		}
	}

	resources.collections[uri] = transform.Values(items...)
	resources.uriCollections[uri] = uris

	return nil
}

func suiteFileURI(path string) string {
	path = filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return (&url.URL{Scheme: suiteFile, Path: path}).String()
}

// Local Windows drive paths use a leading slash in a file URI, but not on disk.
func suiteFileURIPath(path string) string {
	if filepath.Separator == '\\' && len(path) >= 4 && path[0] == '/' && path[2] == ':' && path[3] == '/' {
		path = path[1:]
	}

	return filepath.FromSlash(path)
}

func suiteNamespaceDeclarations(node *suiteNode, namespaces map[string]string) {
	if node == nil {
		return
	}

	maps.Copy(namespaces, node.namespaces)

	for _, attribute := range node.Attributes {
		if attribute.Name.Space == lexicon.PrefixXMLNS {
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

func suiteDynamicContext(currentTime time.Time) transform.DynamicContext {
	if currentTime.IsZero() {
		currentTime, _ = time.Parse(time.RFC3339Nano, suiteDefaultCurrentTime)
	}

	return transform.DynamicContext{CurrentTime: currentTime, ImplicitTimezone: time.UTC, DefaultLanguage: "en"}
}
