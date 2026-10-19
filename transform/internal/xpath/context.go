// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// QualifiedName identifies a function in a specific namespace.
type QualifiedName struct {
	URI  string
	Name string
}

// URIResolver resolves URIs to readable content for fn:unparsed-text and fn:doc.
// The resolved URI is the absolute URI after base URI resolution.
type URIResolver = xdm.URIResolver

// CollectionResolver resolves fn:collection and fn:uri-collection lookups.
// The empty string identifies the default collection.
type CollectionResolver interface {
	ResolveCollection(context.Context, string) (xdm.Sequence, error)
	ResolveURICollection(context.Context, string) ([]string, error)
}

// VariableResolver provides lazy variable resolution for variables not found
// in the static variable scope. This is used by the XSLT executor to lazily
// evaluate global variables on demand.
type VariableResolver interface {
	ResolveVariable(ctx context.Context, name string) (xdm.Sequence, bool, error)
}

// FunctionResolver provides lazy function resolution for functions not found
// in the static function scope. Unlike fnsNS, functions registered via this
// interface are NOT discoverable via fn:function-lookup — they are only
// resolved for direct function calls. This is used by xslt to resolve
// xsl:original() without exposing it to function-lookup.
type FunctionResolver interface {
	ResolveFunction(ctx context.Context, uri, name string, arity int) (Function, bool, error)
}

// SchemaDeclarations provides schema element/attribute/type lookup for
// schema-element(), schema-attribute() node tests and schema-aware casting.
type SchemaDeclarations interface {
	LookupSchemaElement(local, ns string) (typeName string, ok bool)
	LookupSchemaAttribute(local, ns string) (typeName string, ok bool)
	LookupSchemaType(local, ns string) (baseType string, ok bool)
	// IsSubtypeOf returns true if typeName is the same as or a subtype of baseTypeName.
	// Both names use the annotation format: "xs:localName" for XSD built-ins,
	// "Q{ns}localName" for user-defined types.
	IsSubtypeOf(typeName, baseTypeName string) bool
	// IsSubstitutionGroupMember reports whether the element (memberLocal, memberNS)
	// is substitutable for — i.e. a (transitive) member of the substitution group
	// headed by — the element (headLocal, headNS). It drives the schema-element()
	// kind test, which matches an element whose name is a member of the head's
	// substitution group (not merely a type-derivation of the head's type).
	// Returns false when the schema declares no such head or no such membership,
	// preserving behavior for callers that are not substitution-group aware.
	IsSubstitutionGroupMember(memberLocal, memberNS, headLocal, headNS string) bool
	// ValidateCast checks whether a string value is valid for a user-defined
	// schema type (including facet constraints). Returns nil if valid or the
	// type is not found; returns an error if the value violates facets.
	ValidateCast(ctx context.Context, value, typeName string) error
	// ValidateCastWithNS validates a string value against a schema type that
	// requires namespace context for QName/NOTATION resolution. The nsMap
	// provides prefix-to-URI bindings for resolving prefixes in the value.
	ValidateCastWithNS(ctx context.Context, value, typeName string, nsMap map[string]string) error
	// ListItemType returns the item type name for a list type. If the type
	// is not a list, returns ("", false).
	ListItemType(typeName string) (itemType string, ok bool)
	// UnionMemberTypes returns the member type names for a union type.
	// If the type is not a union, returns nil.
	UnionMemberTypes(typeName string) []string
}

// ContentTypeKind classifies the content type of a schema type, mirroring the
// XSD content-type kinds. It is reported by the optional ContentTypeKindProvider
// so the fn:data / typed-value accessor path can detect element-only content,
// which has no typed value.
type ContentTypeKind int

// ContentTypeKind values.
const (
	ContentTypeEmpty       ContentTypeKind = iota // element has no content
	ContentTypeSimple                             // text-only (simple) content
	ContentTypeElementOnly                        // child elements only, no character data
	ContentTypeMixed                              // elements interleaved with character data
)

// ContentTypeKindProvider is an OPTIONAL companion interface to
// SchemaDeclarations. A SchemaDeclarations implementation MAY also implement it
// to report the content-type kind of a (complex) schema type. The fn:data /
// typed-value accessor path type-asserts the active SchemaDeclarations to this
// interface and, when an element node's type annotation resolves to a complex
// type with element-only content, raises err:FOTY0012 — element-only content
// has no typed value (XDM 3.1 §5.15). Implementations that do not provide this
// interface are unaffected: atomization keeps its non-schema-aware behavior, and
// mixed/simple/empty content still atomizes normally.
type ContentTypeKindProvider interface {
	// SchemaTypeContentKind returns the content-type kind for the schema type
	// named typeName (annotation format: "xs:local" or "Q{ns}local") and whether
	// the type was found.
	SchemaTypeContentKind(typeName string) (kind ContentTypeKind, ok bool)
}

// DocOrderCache is a shared document-order cache that can be passed
// across evaluations to ensure consistent cross-document ordering.
//
// The cache describes the tree as it was when first indexed. Callers MUST call
// Reset after mutating any document the cache describes, or order results may be
// stale.
type DocOrderCache = xdm.DocOrderCache

// NewDocOrderCache creates a new shared document-order cache.
func NewDocOrderCache() *DocOrderCache {
	return &xdm.DocOrderCache{}
}

// InvocationState shares adapter state within the current evaluation only.
// Evaluations run in one goroutine; concurrent evaluations have separate stores.
// Returned function items must not retain the store that produced them.
func InvocationState(ctx context.Context, key any, create func() any) any {
	ec := getFnContext(ctx)
	if ec == nil || ec.invocation == nil {
		return create()
	}

	state := ec.invocation
	if value, ok := state.values[key]; ok {
		return value
	}

	if state.values == nil {
		state.values = make(map[any]any)
	}

	value := create()
	state.values[key] = value

	return value
}

// IsDynamicCall returns true if the current function call was dispatched
// through a dynamic function reference (NamedFunctionRef → FunctionItem).
func IsDynamicCall(ctx context.Context) bool {
	v, _ := ctx.Value(dynamicCallKey{}).(bool)
	return v
}

// FnContextNode returns the current XPath context node from a function call
// context. This is the context.Context passed to Function.Call by the evaluator.
// Returns nil if the context does not carry an evaluation state or the context
// item is not a node.
func FnContextNode(ctx context.Context) xdm.Node {
	ec := getFnContext(ctx)
	if ec == nil {
		return nil
	}

	return ec.node
}

// fnContextKey is used exclusively by the unexported withFnContext/getFnContext
// pair to pass evalContext to built-in function implementations. It is never
// exposed to external callers.
type fnContextKey struct{}

type invocationState struct{ values map[any]any }

// dynamicCallKey marks a function call as originating from a dynamic
// function reference (e.g. $f(args) where $f holds a named function ref).
type dynamicCallKey struct{}

func withDynamicCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, dynamicCallKey{}, true)
}

// withFnContext stores the evalContext in a context.Context so built-in
// functions can access the evaluation state (position, size, context node).
func withFnContext(ctx context.Context, ec *evalContext) context.Context {
	return context.WithValue(ctx, fnContextKey{}, ec)
}

// getFnContext retrieves the evalContext stashed by the evaluator.
// Returns nil if not in an evaluation.
func getFnContext(ctx context.Context) *evalContext {
	ec, _ := ctx.Value(fnContextKey{}).(*evalContext)
	return ec
}
