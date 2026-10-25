// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	uripath "github.com/skarm/xmlsec/transform/internal/xdm/uri"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// XSLT/XPath function names referenced from multiple sites. Kept as constants
// alongside xsltFunctionArities (the single source of truth for arities) so the
// repeated literals stay consistent across the package.
const (
	fnNameFormatNumber       = "format-number"
	fnNameCurrent            = "current"
	fnNameDocument           = "document"
	fnNameElementAvailable   = "element-available"
	fnNameFunctionAvailable  = "function-available"
	fnNameTypeAvailable      = "type-available"
	fnNameCurrentGroup       = "current-group"
	fnNameCurrentGroupingKey = "current-grouping-key"
	fnNameCopyOf             = "copy-of"
	fnNameTransform          = "transform"
	fnNameCurrentOutputURI   = "current-output-uri"
)

// xsltFunctions returns the XSLT-specific functions that need to be
// registered with the XPath evaluator by local name (no namespace prefix).
// The map is cached on ec after the first call.
func (ec *execContext) xsltFunctions() map[string]xpath.Function {
	if ec.cachedFns != nil && ec.cachedFnsPackage == ec.effectiveStylesheet() {
		return ec.cachedFns
	}

	ec.cachedFnsPackage = ec.effectiveStylesheet()

	ec.cachedFns = map[string]xpath.Function{
		fnNameCurrent:              &xsltFunc{min: 0, max: 0, fn: ec.fnCurrent, noDynRef: true, dynRefError: errCodeXTDE1360},
		fnNameDocument:             &xsltFunc{min: 1, max: 2, fn: ec.fnDocument},
		nameKey2:                   &keyFunction{ec: ec, scope: ec.effectiveStylesheet()},
		nameGenerateId:             xpath.HostBuiltin(ec.stylesheet.xpathVersion(), nameGenerateId),
		funcSystemProperty:         newIntrospectionFunc(funcSystemProperty, ec.fnSystemProperty),
		nameUnparsedEntityUri:      &xsltFunc{min: 1, max: 2, fn: ec.fnUnparsedEntityURI},
		nameUnparsedEntityPublicId: &xsltFunc{min: 1, max: 2, fn: ec.fnUnparsedEntityPublicID},
		fnNameElementAvailable:     newIntrospectionFunc(fnNameElementAvailable, ec.fnElementAvailable),
		fnNameFunctionAvailable:    newIntrospectionFunc(fnNameFunctionAvailable, ec.fnFunctionAvailable),
		fnNameTypeAvailable:        newIntrospectionFunc(fnNameTypeAvailable, fnTypeAvailable),
		fnNameCurrentGroup:         &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentGroup, noDynRef: true, dynRefError: errCodeXTDE1061},
		fnNameCurrentGroupingKey:   &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentGroupingKey, noDynRef: true, dynRefError: errCodeXTDE1071},
		nameAccumulatorBefore: &xsltFunc{min: 1, max: 1, fn: func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
			return ec.accumulatorLookup(ctx, args, nameAccumulatorBefore, func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error) {
				return ec.accumulatorBeforeByNode, ec.accumulatorBeforeErrorByNode
			})
		}},
		nameAccumulatorAfter: &xsltFunc{min: 1, max: 1, fn: func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
			return ec.accumulatorLookup(ctx, args, nameAccumulatorAfter, func() (map[xdm.Node]map[string]xdm.Sequence, map[xdm.Node]map[string]error) {
				return ec.accumulatorAfterByNode, ec.accumulatorAfterErrorByNode
			})
		}},
		fnNameCopyOf:                  &xsltFunc{min: 0, max: 1, fn: ec.fnCopyOf},
		funcSnapshot:                  &xsltFunc{min: 0, max: 1, fn: ec.fnSnapshot},
		nameRegexGroup:                &xsltFunc{min: 1, max: 1, fn: ec.fnRegexGroup},
		fnNameTransform:               &xsltFunc{min: 1, max: 1, fn: ec.fnTransform},
		funcAvailableSystemProperties: &xsltFunc{min: 0, max: 0, fn: fnAvailableSystemProperties},
		nameStreamAvailable:           &xsltFunc{min: 1, max: 1, fn: ec.fnStreamAvailable},
		fnNameCurrentOutputURI:        &xsltFunc{min: 0, max: 0, fn: ec.fnCurrentOutputURI},
	}
	if ec.stylesheet.processorLanguage() <= 20 {
		for _, name := range []string{fnNameFormatNumber, "format-date", "format-dateTime", "format-time"} {
			ec.cachedFns[name] = newLegacyFormatFunction(ec.stylesheet.xpathVersion(), name)
		}
	}

	if ec.stylesheet.processorLanguage() == 10 {
		for name, fn := range ec.cachedFns {
			if _, ok := lookupxslt10Functions(name); ok {
				ec.cachedFns[name] = function10{name, fn}
			} else {
				delete(ec.cachedFns, name)
			}
		}
	}

	if ec.stylesheet.processorLanguage() == 20 {
		for name := range ec.cachedFns {
			if xslt30Function(name) {
				delete(ec.cachedFns, name)
			}
		}
	}

	for name, function := range ec.cachedFns {
		if host, ok := function.(*xsltFunc); ok {
			ec.prepareHostFunction(name, host)
		}
	}

	return ec.cachedFns
}

func (ec *execContext) prepareHostFunction(name string, function *xsltFunc) {
	function.name = name
	if ec.stylesheet.processorLanguage() < 30 && (name == nameUnparsedEntityUri || name == nameUnparsedEntityPublicId) {
		function.max = 1
	}

	if function.signature == nil {
		function.signature = xpath.HostBuiltin(ec.stylesheet.xpathVersion(), name)
	}
}

// Preserve the XSLT 2.0 error vocabulary while reusing F&O conversion and
// formatting. A 3.0 processor uses the F&O codes even for a 2.0 declaration.
type legacyFormatFunction struct {
	xpath.TypedFunctionByArity
	name string
}

func newLegacyFormatFunction(version int, name string) xpath.Function {
	return &legacyFormatFunction{TypedFunctionByArity: xpath.HostBuiltin(version, name), name: name}
}

func (f *legacyFormatFunction) AcceptsArity(arity int) bool {
	return xpath.BuiltinFunctionAcceptsArity(xpath.NSFn, f.name, arity)
}

func (f *legacyFormatFunction) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if f.name == fnNameFormatNumber && len(args) == 3 {
		name, err := xpath.XPath10String(args[2])
		if err != nil {
			return nil, err
		}

		if !xmlchar.IsValidQName(name) {
			return nil, dynamicError("XTDE1280", "invalid decimal format QName %q", name)
		}
	}

	value, err := f.TypedFunctionByArity.Call(ctx, args)
	if failure := preserveControlFailure(ctx, err); failure != nil {
		return nil, failure
	}

	if detail, ok := errors.AsType[*xdm.Error](err); ok && detail.CodeQName().URI == lexicon.NamespaceErr {
		code := ""

		switch detail.Code {
		case "FODF1280":
			code = "XTDE1280"
		case "FODF1310":
			code = "XTDE1310"
		case "FOFD1340":
			code = "XTDE1340"
		case "FOFD1350":
			code = "XTDE1350"
		}

		if code != "" {
			return nil, dynamicErrorCause(code, err, "%s: %s", f.name, detail.Message)
		}
	}

	return value, err
}

func xslt30Function(name string) bool {
	switch name {
	case nameAccumulatorBefore, nameAccumulatorAfter, fnNameCopyOf, funcSnapshot,
		fnNameTransform, funcAvailableSystemProperties, nameStreamAvailable,
		fnNameCurrentOutputURI, nameCurrentMergeGroup, nameCurrentMergeKey:
		return true
	default:
		return false
	}
}

// current() returns the current item (node or atomic value being processed).
func (ec *execContext) fnCurrent(_ context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	// For-each over atomic values: return the current atomic item
	if ec.contextItem != nil {
		return xdm.ItemSlice{ec.contextItem}, nil
	}

	if ec.currentNode == nil {
		// XTDE1360: current() called when context item is absent
		return nil, dynamicError(errCodeXTDE1360,
			"current() called when context item is absent")
	}

	return xdm.SingleNode(ec.currentNode), nil
}

// document(uri, base?) loads an external XML document.
// fnDocument resolves string-like references against their argument node or
// captured static base (XSLT 2.0 section 16.1; XSLT 3.0 section 20.1).
// Fragments select nodes only after the absolute document URI is loaded.
func (ec *execContext) fnDocument(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if xdm.SequenceLen(args[0]) == 0 {
		return nil, nil
	}

	var nodes []xdm.Node

	for item := range xdm.SequenceItems(args[0]) {
		selected, err := ec.documentItemNodes(ctx, item, args)
		if err != nil {
			return nil, err
		}

		if len(selected) > xpath.NodeLimit(ctx, xdm.DefaultMaxNodeSetLength)-len(nodes) {
			return nil, xpath.ErrNodeSetLimit
		}

		nodes = append(nodes, selected...)
	}

	// Different fragments may select different nodes in the same document.
	// Deduplicate the selected nodes, then return them in document order.
	if ec.docOrderCache == nil {
		ec.docOrderCache = xpath.NewDocOrderCache()
	}

	nodes, err := xdm.DeduplicateNodes(nodes, ec.docOrderCache, xpath.NodeLimit(ctx, xdm.DefaultMaxNodeSetLength))
	if err != nil {
		return nil, err
	}

	result := make(xdm.ItemSlice, len(nodes))
	for i, node := range nodes {
		result[i] = xdm.NodeItem{Node: node}
	}

	return result, nil
}

func (ec *execContext) documentItemNodes(ctx context.Context, item xdm.Item, args []xdm.Sequence) ([]xdm.Node, error) {
	var nodes []xdm.Node

	switch item.(type) {
	case xdm.AtomicValue, xdm.NodeItem:
	default:
		return nil, dynamicError(errCodeXPTY0004, "document() requires string-like values or nodes")
	}

	atoms, err := xpath.FnAtomize(ctx, xdm.ItemSlice{item})
	if err != nil {
		return nil, err
	}

	for _, atom := range atoms {
		if !isStringLikeType(atom.TypeName) {
			return nil, dynamicError(errCodeXPTY0004, "document() requires string-like URI values")
		}

		atom, err = xpath.CastAtomic(atom, xdm.TypeAnyURI)
		if err != nil {
			return nil, err
		}

		uri, err := xpath.AtomicToString(atom)
		if err != nil {
			return nil, err
		}

		resolved, err := ec.documentItemURI(ctx, uri, item, args)
		if err != nil {
			return nil, err
		}

		doc, err := ec.loadDocument(ctx, resolved, "")
		if err != nil {
			return nil, err
		}

		var node xdm.Node = doc

		if _, fragment, found := strings.Cut(resolved, "#"); found && fragment != "" {
			fragment, err = url.PathUnescape(fragment)
			if err != nil {
				return nil, dynamicErrorCause(errCodeXTDE1160, err, "invalid document URI fragment")
			}

			node = findElementByID(doc, fragment)
			if xdm.IsNilNode(node) {
				continue
			}
		}

		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		if len(nodes) >= xpath.NodeLimit(ctx, xdm.DefaultMaxNodeSetLength) {
			return nil, xpath.ErrNodeSetLimit
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// documentItemURI resolves only relative references against the selected node
// or expression base. Absolute URIs do not require a base node to have a URI.
func (ec *execContext) documentItemURI(ctx context.Context, uri string, item xdm.Item, args []xdm.Sequence) (string, error) {
	if uripath.URIScheme(uri) != "" {
		return xpath.ResolveURIReference(uri, "")
	}

	base := ec.effectiveStaticBaseURI()
	if captured, present := xpath.ContextBaseURI(ctx); present {
		base = captured
	}

	if len(args) >= 2 {
		if node, ok := args[1].Get(0).(xdm.NodeItem); ok {
			base = xpath.NodeBaseURI(node.Node)
		}
	} else if node, ok := item.(xdm.NodeItem); ok {
		base = xpath.NodeBaseURI(node.Node)
	} else if uri == "" && base == "" {
		// Preserve the public API's anonymous stylesheet self-document extension.
		return "", nil
	}

	if base == "" {
		return "", dynamicError(errCodeXTDE1162, "document() relative reference has no base URI")
	}

	if uripath.URIScheme(base) == "" {
		// Compiler.BaseURI also accepts application-owned local file paths.
		if uri == "" {
			return base, nil
		}

		return resolveModuleURI(uri, base)
	}

	return xpath.ResolveURIReference(uri, base)
}

// fnDoc is an XSLT-aware wrapper around fn:doc() that applies
// xsl:strip-space rules to loaded documents.
func (ec *execContext) fnDoc(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	if len(args) == 0 || (args[0] == nil || xdm.SequenceLen(args[0]) == 0) {
		return xdm.EmptySequence(), nil
	}

	av, err := xpath.AtomizeItem(args[0].Get(0))
	if err != nil {
		return nil, err
	}

	uri, err := xpath.AtomicToString(av)
	if err != nil {
		return nil, err
	}

	uri, err = xpath.ResolveDocumentURI(ctx, uri)
	if err != nil {
		return nil, err
	}

	baseDir := ec.baseDir()

	doc, err := ec.loadDocument(ctx, uri, baseDir)
	if err != nil {
		return nil, err
	}

	return xdm.SingleNode(doc), nil
}

// loadDocument loads a single XML document by URI, using baseDir for
// resolving relative paths.
func (ec *execContext) loadDocument(ctx context.Context, uri string, baseDir string) (*xdm.Document, error) {
	// Empty string means the stylesheet module itself (XSLT spec 14.1).
	// When called from an included/imported module, return that module's
	// document, not the top-level stylesheet.
	// However, if xml:base changes the effective base URI, resolve against
	// that URI instead (the base URI may point to a different file).
	if uri == "" {
		sheet := ec.effectiveStylesheet()

		effectiveBase := ec.effectiveStaticBaseURI()
		if ec.currentTemplate != nil && ec.currentTemplate.BaseURI != "" {
			if modDoc, ok := sheet.moduleDocs[ec.currentTemplate.BaseURI]; ok {
				// Only return the module doc if the effective base URI
				// matches the template's module. If xml:base overrides,
				// fall through to load the overridden URI.
				if effectiveBase == ec.currentTemplate.BaseURI || effectiveBase == "" {
					return ec.existingDocumentRead(ctx, modDoc)
				}
			} else if effectiveBase == ec.currentTemplate.BaseURI || effectiveBase == "" {
				return ec.existingDocumentRead(ctx, sheet.sourceDoc)
			}
		} else if effectiveBase == "" || effectiveBase == sheet.baseURI {
			return ec.existingDocumentRead(ctx, sheet.sourceDoc)
		}
		// xml:base overrides the base URI — resolve the empty string
		// against the effective base URI to load the target document.
		uri = effectiveBase
		baseDir = documentBaseDir(effectiveBase)
	}

	// Strip fragment identifier before loading.
	cleanURI := uri
	if idx := strings.IndexByte(cleanURI, '#'); idx >= 0 {
		cleanURI = cleanURI[:idx]
	}

	resolvedURI := ec.resolveDocumentURI(cleanURI, baseDir)
	if err := ec.CheckRead(ctx, resolvedURI); err != nil {
		return nil, err
	}

	// If the resolved URI matches the source document, return it directly
	// to preserve node identity (spec: doc(document-uri(X)) is X).
	if ec.sourceDoc != nil && !ec.sourceDoc.HasProperty(xdm.DocInternal) && ec.resolveDocumentURI(ec.sourceDoc.URL(), "") == resolvedURI {
		return ec.cachedDocumentRead(ctx, resolvedURI, ec.sourceDoc)
	}

	cacheKey := ec.docCacheKey(resolvedURI)
	if doc, ok := ec.docCache[cacheKey]; ok {
		return ec.cachedDocumentRead(ctx, resolvedURI, doc)
	}

	module, err := ec.stylesheetDocument(ctx, cleanURI, resolvedURI)
	if err != nil {
		return nil, err
	}

	if module != nil {
		if ec.docCache == nil {
			ec.docCache = make(map[string]*xdm.Document)
		}

		ec.docCache[cacheKey] = module

		return ec.cachedDocumentRead(ctx, resolvedURI, module)
	}

	reader, err := ec.retrieveDocumentReader(ctx, resolvedURI)
	if err != nil {
		return nil, documentRetrievalError(uri, err)
	}

	doc, err := parseXMLResource(ctx, ec.inputParseOptions(), reader, resolvedURI, ec.resourceLimit())
	if err != nil {
		return nil, documentParsingError(uri, err)
	}

	doc.SetURL(resolvedURI)

	// Retain the original tree for packages with different preprocessing rules.
	doc, err = ec.existingDocumentRead(ctx, doc)
	if err != nil {
		return nil, err
	}

	if ec.docCache == nil {
		ec.docCache = make(map[string]*xdm.Document)
	}

	ec.docCache[cacheKey] = doc

	// Pre-compute accumulator states for documents loaded via doc()/document()
	// so that accumulator-before()/accumulator-after() work when processing
	// these documents (XSLT 3.0 §14.1: accumulators are always applicable).
	if err := loadDocumentEffectiveAccumulators(ctx, ec, doc); err != nil {
		return nil, err
	}

	return doc, nil
}

// Stylesheet modules are already available XML resources in their declaring
// package. Cache a normalized alias after the first lookup; graph traversal is
// charged to the same operation budget as document retrieval.
func (ec *execContext) stylesheetDocument(ctx context.Context, uri, resolved string) (*xdm.Document, error) {
	sheet := ec.effectiveStylesheet()
	if doc := sheet.moduleDocs[uri]; doc != nil {
		return doc, nil
	}

	if doc := sheet.moduleDocs[resolved]; doc != nil {
		return doc, nil
	}

	for key, doc := range sheet.moduleDocs {
		if err := xpath.Charge(ctx, 1); err != nil {
			return nil, err
		}

		if ec.resolveDocumentURI(key, "") == resolved {
			return doc, nil
		}
	}

	return nil, nil
}

func loadDocumentEffectiveAccumulators(ctx context.Context, ec *execContext, doc *xdm.Document) error {
	if len(ec.effectiveAccumulators()) > 0 {
		names := append([]string(nil), ec.effectiveStylesheet().accumulatorOrder...)
		if err := ec.computeAccumulatorStates(ctx, doc, names); err != nil {
			return err
		}

		if ec.accumulatorComputedDocs == nil {
			ec.accumulatorComputedDocs = make(map[xdm.Node]struct{})
		}

		ec.accumulatorComputedDocs[documentRoot(doc)] = struct{}{}
	}

	return nil
}

func documentParsingError(uri string, err error) error {
	if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
		return err
	}

	return dynamicErrorCause(errCodeFODC0002, err, "cannot parse document %q: %v", uri, err)
}

func documentRetrievalError(uri string, err error) error {
	if _, hostFailure := errors.AsType[*xdm.ResourceAccessError](err); hostFailure {
		return err
	}

	if strings.ContainsRune(uri, '#') {
		return dynamicErrorCause(errCodeXTDE1160, err, "cannot load document %q with fragment identifier: %v", uri, err)
	}

	return dynamicErrorCause(errCodeFODC0002, err, "cannot load document %q: %v", uri, err)
}

func (ec *execContext) existingDocumentRead(ctx context.Context, doc *xdm.Document) (*xdm.Document, error) {
	if doc != nil {
		prepared, err := ec.prepareInputNode(ctx, doc)
		if err != nil {
			return nil, err
		}

		doc = prepared.(*xdm.Document) //nolint:forcetypeassert // preprocessing retains node kinds
	}

	if doc != nil && !doc.HasProperty(xdm.DocInternal) {
		if err := ec.RecordRead(ctx, doc.URL()); err != nil {
			return nil, err
		}
	}

	return doc, nil
}

func (ec *execContext) cachedDocumentRead(ctx context.Context, uri string, doc *xdm.Document) (*xdm.Document, error) {
	if err := ec.RecordRead(ctx, uri); err != nil {
		return nil, err
	}

	return ec.existingDocumentRead(ctx, doc)
}

func (ec *execContext) retrieveDocumentReader(ctx context.Context, uri string) (io.ReadCloser, error) {
	if err := ec.CheckRead(ctx, uri); err != nil {
		return nil, &xdm.ResourceAccessError{Cause: err}
	}

	if ec.transformConfig == nil {
		return nil, fmt.Errorf("no URIResolver configured for %q", uri)
	}

	reader, err := openDocumentVia(ctx, uri, ec.transformConfig.uriResolver, ec.transformConfig.httpClient)
	if err != nil {
		if !nilcheck.IsNil(reader) {
			err = errors.Join(err, reader.Close())
		}

		return nil, err
	}

	if nilcheck.IsNil(reader) {
		return nil, fmt.Errorf("resource %q returned a nil reader", uri)
	}

	if err := ec.RecordRead(ctx, uri); err != nil {
		return nil, errors.Join(&xdm.ResourceAccessError{Cause: err}, reader.Close())
	}

	return reader, nil
}

func openDocumentVia(ctx context.Context, uri string, resolver xpath.URIResolver, client *http.Client) (io.ReadCloser, error) {
	if !isHTTPURI(uri) || client == nil {
		if resolver == nil {
			return nil, fmt.Errorf("no URIResolver configured for %q", uri)
		}

		return resolver.Resolve(ctx, uri)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.Join(fmt.Errorf("HTTP %d for %q", response.StatusCode, uri), response.Body.Close())
	}

	return response.Body, nil
}

// resourceLimit returns the per-resource read cap for runtime resolver/HTTP
// reads, taken from the transformConfig (0 = MaxResourceBytes default).
func (ec *execContext) resourceLimit() int64 {
	if ec != nil && ec.transformConfig != nil {
		return ec.transformConfig.maxResourceBytes
	}

	return 0
}

// inputParseOptions returns the caller-injected base parseOptions governing parse policy
// for runtime XML parses (nil = hardened default).
func (ec *execContext) inputParseOptions() *xdm.ParseOptions {
	if ec != nil && ec.transformConfig != nil {
		if configured := ec.transformConfig.parseOptions; configured != nil {
			options := *configured
			if options.AllowDTD {
				options.DTDOpen = ec.retrieveDocumentReader
			}

			return &options
		}
	}

	return nil
}

// resolveDocumentURI resolves a URI against a base directory.
func (ec *execContext) resolveDocumentURI(uri string, baseDir string) string {
	if uri == "" {
		return ""
	}
	// Strip fragment identifier.
	cleanURI := uri
	if idx := strings.IndexByte(cleanURI, '#'); idx >= 0 {
		cleanURI = cleanURI[:idx]
	}
	// Convert file:// URIs to local paths. Use uripath.FileURIToPath so a Windows
	// drive-letter URI ("file:///D:/a/b") yields a drive path ("D:\\a\\b" on
	// Windows), and no spurious leading-slash path ("/D:/a/b"). The result
	// is then normalized with uripath.ToSlash so a non-drive POSIX-shaped URI
	// ("file:///abs/x.xml") resolves to a forward-slash path ("/abs/x.xml") on
	// EVERY OS — FileURIToPath would otherwise emit "\\abs\\x.xml" on Windows.
	// The forward-slash form is what every other helium resolver consumes (Win32
	// accepts '/'); POSIX behavior is unchanged. On parse failure, fall back to
	// the original strip.
	if strings.HasPrefix(cleanURI, "file:///") {
		if p, err := uripath.FileURIToPath(cleanURI); err == nil {
			return uripath.ToSlash(p)
		}
		// On conversion failure (e.g. a "file:////server/share" UNC URI that
		// FileURIToPath rejects) do NOT strip the "file://" prefix: that would
		// yield "//server/share/..." which becomes a UNC path on Windows,
		// bypassing the local-only policy. Return the original file: URI so a
		// downstream local-path loader rejects it.
		return cleanURI
	}
	// Decide absoluteness with uripath.URIScheme (RFC 3986), not a "://" substring
	// check or filepath.IsAbs: an absolute-URI ref may carry a scheme with no
	// "//" authority (e.g. document('urn:doc'), doc('file:/x.xml')) and must be
	// returned unchanged, while a relative ref against a URI base must keep the
	// base scheme/authority (resolved per RFC 3986) instead of being joined as a
	// local path. Only when both base and ref are local filesystem paths is
	// filepath.Join used. Resolution of the URI cases is delegated to the shared
	// canonical uripath.ResolveSchemaURI helper.
	if uripath.URIScheme(cleanURI) != "" || (baseDir != "" && uripath.URIScheme(baseDir) != "") {
		resolved, err := uripath.ResolveSchemaURI(cleanURI, baseDir)
		if err != nil {
			return cleanURI
		}

		return resolved
	}
	// Both local: resolve with forward-slash (path) semantics so the result uses
	// '/' on every OS. uripath.IsAbsolutePath recognizes both POSIX- and
	// Windows-absolute refs regardless of GOOS.
	if uripath.IsAbsolutePath(cleanURI) {
		return cleanURI
	}

	if baseDir != "" {
		return uripath.JoinLocalBaseDir(baseDir, cleanURI)
	}

	return cleanURI
}

// isHTTPURI reports whether uri has an http or https scheme. Such a URI is
// fetched through the configured HTTPClient when one is set, and otherwise
// through the URIResolver. URI schemes are case-insensitive per RFC 3986;
// url.Parse lowercases .Scheme, so "HTTP" and "Https" also match.
func isHTTPURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}

	return u.Scheme == lexicon.SchemeHTTP || u.Scheme == lexicon.SchemeHTTPS
}

// documentBaseDir derives the base passed to resolveDocumentURI /
// resolveAgainstBaseURI for a runtime document base such as a stylesheet or
// node base URI.
//
// For a URI base (it has a scheme per [uripath.URIScheme]) the FULL base URI is
// returned unchanged: the URI-aware resolvers delegate to [uripath.ResolveSchemaURI],
// which performs RFC 3986 resolution and replaces the base's last path segment
// itself. Applying filepath.Dir here would instead collapse the "//" authority
// separator (e.g. "mem://pkg/main.xsl" -> "mem:/pkg"), dropping the host so a
// sibling "doc.xml" wrongly resolves to "mem:/pkg/doc.xml" instead of
// "mem://pkg/doc.xml".
//
// For a genuine local filesystem base the containing directory is derived with
// path.Dir over the forward-slash-normalized base ([uripath.ToSlash]) — the
// SAME derivation compile-time module resolution uses for a local baseURI (see
// resolveModuleHref in compile_imports.go), so a relative reference resolves to
// the same directory whether the surrounding expression is compiled statically
// or evaluated dynamically. A Compiler.BaseURI / stylesheet FILE base such as
// "/styles/main" is treated as a file path: its last segment is dropped
// ("/styles"), so doc("data.xml") lands at "/styles/data.xml". A genuine
// directory-form base (a trailing-slash path such as "…/tests/fn/", as an
// xml:base=".." override resolves to) is still handled correctly: path.Dir
// collapses the trailing slash and keeps the directory ("…/tests/fn/" ->
// "…/tests/fn"). Forward-slash semantics keep the result '/'-separated on every
// OS (on Windows filepath.Dir would emit '\' and corrupt the later slash-based
// join).
func documentBaseDir(base string) string {
	if base == "" {
		return ""
	}

	if uripath.URIScheme(base) != "" {
		return base
	}

	return path.Dir(uripath.ToSlash(base))
}

// xsltFunctionArities is the static arity table for XSLT-defined functions that
// live in the fn: namespace. It is the single source of truth consulted by
// compile-time checks (e.g. validatePatternFunctions) that run without an
// execContext. The runtime registries in xsltFunctions / xsltFunctionsNS must
// stay consistent with this table; TestXSLTFunctionAritiesMatchRegistry guards
// against drift.
func lookupxsltFunctionArities(key string) ([2]int, bool) {
	switch key {
	case nameGenerateId, nameCurrentMergeGroup, fnNameCopyOf, funcSnapshot:
		return [2]int{0, 1}, true
	case fnNameCurrent, fnNameCurrentGroup, fnNameCurrentGroupingKey, nameCurrentMergeKey, funcAvailableSystemProperties, fnNameCurrentOutputURI:
		return [2]int{0, 0}, true
	case fnNameDocument, nameUnparsedEntityUri, nameUnparsedEntityPublicId, fnNameFunctionAvailable:
		return [2]int{1, 2}, true
	case nameDoc, funcSystemProperty, fnNameElementAvailable, fnNameTypeAvailable, nameAccumulatorBefore, nameAccumulatorAfter, nameRegexGroup, fnNameTransform, nameStreamAvailable:
		return [2]int{1, 1}, true
	case nameKey2:
		return [2]int{2, 3}, true
	}

	var zero [2]int

	return zero, false
}

func xsltFunctionAcceptsVersionArity(version int, name string, arity int) bool {
	if version < 30 && (name == nameUnparsedEntityUri || name == nameUnparsedEntityPublicId) && arity > 1 {
		return false
	}

	return xsltFunctionAcceptsArity(name, arity)
}

// xsltFunctionAcceptsArity reports whether an XSLT-defined function (fn:
// namespace) with the given local name exists and accepts the given arity.
func xsltFunctionAcceptsArity(name string, arity int) bool {
	bounds, ok := lookupxsltFunctionArities(name)
	if !ok {
		return false
	}

	return arity >= bounds[0] && arity <= bounds[1]
}

type xsltFunc struct {
	name        string
	min         int
	max         int
	fn          func(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error)
	noDynRef    bool   // true if the function must not be called via dynamic function reference
	dynRefError string // error code to raise on dynamic call
	signature   xpath.TypedFunctionByArity
}

func (f *xsltFunc) FuncParamTypesForArity(arity int) []xdm.SequenceType {
	if f.signature != nil {
		return f.signature.FuncParamTypesForArity(arity)
	}

	return xsltFunctionTypes()[functionTypeKey{f.name, arity}].params
}

func (f *xsltFunc) FuncReturnTypeForArity(arity int) *xdm.SequenceType {
	if f.signature != nil {
		return f.signature.FuncReturnTypeForArity(arity)
	}

	return xsltFunctionTypes()[functionTypeKey{f.name, arity}].result
}

type introspectionFunc struct {
	*xsltFunc
	params []xdm.SequenceType
	result xdm.SequenceType
}

func newIntrospectionFunc(name string, call func(context.Context, []xdm.Sequence) (xdm.Sequence, error)) xpath.Function {
	atomic := func(local string) xdm.SequenceType {
		return xdm.SequenceType{ItemTest: xdm.AtomicOrUnionType{Name: "Q{" + lexicon.NamespaceXSD + "}" + local}}
	}

	params := []xdm.SequenceType{atomic("string")}
	if name == fnNameFunctionAvailable {
		params = append(params, atomic("integer"))
	}

	result := atomic("boolean")
	if name == funcSystemProperty {
		result = atomic("string")
	}

	return &introspectionFunc{xsltFunc: &xsltFunc{min: 1, max: len(params), fn: call}, params: params, result: result}
}

func (f *introspectionFunc) FuncParamTypesForArity(arity int) []xdm.SequenceType {
	return f.params[:arity]
}

func (f *introspectionFunc) FuncReturnTypeForArity(_ int) *xdm.SequenceType { return &f.result }

func (f *xsltFunc) MinArity() int { return f.min }

func (f *xsltFunc) MaxArity() int { return f.max }

func (f *xsltFunc) Call(ctx context.Context, args []xdm.Sequence) (xdm.Sequence, error) {
	return f.fn(ctx, args)
}

// NoDynamicRef returns true if this function should not be available
// for named function references (e.g. current-group#0).
func (f *xsltFunc) NoDynamicRef() bool { return f.noDynRef }

// DynRefErrorCode returns the error code to raise when this function
// is called via dynamic reference.
func (f *xsltFunc) DynRefErrorCode() string { return f.dynRefError }

// regexGroupFunc implements xpath.Function and DynamicRefSnapshotProvider
// for regex-group(). Dynamic references clear the captured-substring context.
// resolveAgainstBaseURI resolves a relative URI against an effective base URI.
// The base URI may be a file path (e.g., /a/b/style.xsl) or a directory-like
// path from xml:base processing (e.g., /a/b). For file paths (containing a
// dot-extension in the last segment), the directory part is extracted via
// filepath.Dir. For directory-like paths, the path is used directly.
//
// Absoluteness is decided with [uripath.URIScheme] (RFC 3986), not filepath.IsAbs
// or a "://" substring check: an absolute-URI reference may carry a scheme with
// no "//" authority (e.g. "urn:shared", "file:/docs/d.xml") and must be returned
// unchanged, while a relative reference against a URI base must keep the base
// scheme/authority. Only when both base and ref are local filesystem paths is
// filepath.Join used. Resolution of the URI cases is delegated to the shared
// canonical [uripath.ResolveSchemaURI] helper.
func resolveAgainstBaseURI(uri string, baseURI string) string {
	if uri == "" || baseURI == "" {
		return uri
	}
	// Absolute-URI ref, or any ref against a URI base: defer to the shared
	// canonical resolver (RFC 3986 + OmitHost preservation). On error, fall
	// back to the raw ref, producing no host-dropping filepath join.
	if uripath.URIScheme(uri) != "" || uripath.URIScheme(baseURI) != "" {
		resolved, err := uripath.ResolveSchemaURI(uri, baseURI)
		if err != nil {
			return uri
		}

		return resolved
	}
	// Both base and ref are local filesystem paths. Resolve with forward-slash
	// (path) semantics so the result uses '/' on every OS; uripath.IsAbsolutePath
	// recognizes both POSIX- and Windows-absolute refs regardless of GOOS.
	if uripath.IsAbsolutePath(uri) {
		return uri
	}

	baseDir := baseURIDir(baseURI)

	return uripath.JoinLocalBaseDir(baseDir, uri)
}

func splitURIFragment(uri string) (string, string) {
	base, fragment, found := strings.Cut(uri, "#")
	if !found {
		return uri, ""
	}

	return base, fragment
}

// baseURIDir extracts the directory from a local-filesystem base URI in
// forward-slash form. If the base looks like a file path (last segment contains
// a dot) the last segment is dropped; otherwise the base itself is treated as a
// directory. uripath.LocalBaseDir performs this in slash space on every OS, so
// the result never gains backslashes on Windows.
func baseURIDir(baseURI string) string {
	return uripath.LocalBaseDir(baseURI)
}
