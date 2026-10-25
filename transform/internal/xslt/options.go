// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// URIResolver resolves URIs to readable content. Used for xsl:import
// and xsl:include during compilation.
type URIResolver = xdm.URIResolver

// PackageResolver resolves package name URIs to file paths or readers.
// Used during compilation when xsl:use-package is encountered.
type PackageResolver interface {
	// ResolvePackage opens a package matching its name and version constraint and returns
	// its retrieval base URI. The compiler closes the reader.
	ResolvePackage(context.Context, string, string) (io.ReadCloser, string, error)
}

// MessageHandler handles xsl:message output during transformation.
// A non-nil error aborts the transform immediately.
//
// Handler methods are called from the goroutine executing Do/Serialize/WriteTo.
// If you run transforms concurrently, your implementation must be safe for
// concurrent use.
type MessageHandler interface {
	// HandleMessage receives serialized message content and its terminate flag. An error
	// stops execution.
	HandleMessage(msg string, terminate bool) error
}

// ResultDocumentHandler handles secondary result documents produced
// by xsl:result-document. The outDef contains the effective output
// definition (method, encoding, indent, etc.) for this result document.
// A non-nil error aborts the transform.
//
// Handler methods are called from the goroutine executing Do/Serialize/WriteTo.
// If you run transforms concurrently, your implementation must be safe for
// concurrent use.
type ResultDocumentHandler interface {
	// HandleResultDocument receives a secondary result URI, tree and effective
	// serialization definition. An error stops execution.
	HandleResultDocument(href string, doc *xdm.Document, outDef *OutputDef) error
}

// RawResultHandler receives the raw XDM result sequence from the primary
// output before it is serialized into the result document tree.
// A non-nil error aborts the transform.
//
// Handler methods are called from the goroutine executing Do/Serialize/WriteTo.
// If you run transforms concurrently, your implementation must be safe for
// concurrent use.
type RawResultHandler interface {
	// HandleRawResult receives the principal XDM sequence before tree serialization. An
	// error stops execution.
	HandleRawResult(seq xdm.Sequence) error
}

// PrimaryItemsHandler receives non-node items captured from the primary
// output during transformation (needed for json/adaptive serialization).
// A non-nil error aborts the transform.
//
// Handler methods are called from the goroutine executing Do/Serialize/WriteTo.
// If you run transforms concurrently, your implementation must be safe for
// concurrent use.
type PrimaryItemsHandler interface {
	// HandlePrimaryItems receives captured principal items for JSON or adaptive delivery.
	// An error stops execution.
	HandlePrimaryItems(seq xdm.Sequence) error
}

// AnnotationHandler receives optional internal type metadata supplied by a host. It
// does not enable schema-aware processing in the public transform API. An error aborts
// the transform. Callbacks run on the executing goroutine; handlers shared between
// concurrent invocations must support concurrent calls.
type AnnotationHandler interface {
	// HandleAnnotations receives internal annotation metadata when a schema-aware host
	// supplies it. This callback does not enable schema awareness in the public API.
	HandleAnnotations(annotations map[xdm.Node]string, declarations xpath.SchemaDeclarations) error
}

// --- Compile configuration (internal) ---

type compileConfig struct {
	processorVersion int
	baseURI          string
	resolver         URIResolver
	packageResolver  PackageResolver
	staticParams     map[string]xdm.Sequence // externally supplied static param values

	isSubPackage     bool  // true when compiling a sub-package (via xsl:use-package)
	maxResourceBytes int64 // per-resource read cap; 0 = MaxResourceBytes default, <0 = unbounded

	parseOptions *xdm.ParseOptions
}

// --- Transform configuration (internal) ---

type transformConfig struct {
	msgHandler            MessageHandler
	resultDocHandler      ResultDocumentHandler
	collectionResolver    xpath.CollectionResolver
	uriResolver           xpath.URIResolver // resolver for fn:doc, fn:unparsed-text, fn:json-doc
	rawResultHandler      RawResultHandler
	annotationHandler     AnnotationHandler
	initialMatchSelection xdm.Sequence // initial match selection for apply-templates entry
	rawCapturedItems      xdm.Sequence // items captured during raw-delivery transform (set by executeTransform)
	primaryItems          xdm.Sequence // items captured from primary output for json/adaptive serialization
	primaryItemsHandler   PrimaryItemsHandler
	traceWriter           io.Writer // destination for fn:trace output (nil discards output)
	globalContextItem     xdm.Item  // explicit global context item (fn:transform global-context-item option)
	valueResults          map[string]ValueResult
	sequenceParams        map[string]xdm.Sequence
	initialModeParams     map[string]xdm.Sequence
	initialModeTunnel     map[string]xdm.Sequence
	initialTemplateParams map[string]xdm.Sequence
	initialTemplateTunnel map[string]xdm.Sequence

	resolvedOutputDef     *OutputDef // resolved primary output def (set by executeTransform)
	parseOptions          *xdm.ParseOptions
	initialTemplate       string
	initialMode           string
	initialFunction       string         // QName of initial function
	onMultipleMatch       string         // "use-last" or "fail" — overrides default mode's on-multiple-match
	baseOutputURI         string         // resolved base-output-uri; drives the PRINCIPAL result-map key and current-output-uri() (empty when the option is absent)
	outputBaseURI         string         // base for RESOLVING secondary result-document output URIs: the resolved base-output-uri when present, else the call's effective static base URI (so secondary keys stay absolute even when base-output-uri is omitted)
	globalContextSelect   string         // XPath for global context item (evaluated after strip-space)
	initialFunctionParams []xdm.Sequence // positional params for initial function
	maxResourceBytes      int64          // per-resource read cap; 0 = MaxResourceBytes default, <0 = unbounded
	rawSequence           bool
	rawCapture            bool // enable captureItems on output frame for raw delivery
	globalContextAbsent   bool // fn:transform supplied no source-node and no global-context-item → the global context item is absent
}
