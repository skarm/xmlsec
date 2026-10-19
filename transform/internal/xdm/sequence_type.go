// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

// NodeTest filters nodes selected by an axis.
type NodeTest interface {
	nodeTest()
}

// NodeKind identifies the built-in node kind test types.
type NodeKind int

const (
	NodeKindNode                  NodeKind = iota // node()
	NodeKindText                                  // text()
	NodeKindComment                               // comment()
	NodeKindProcessingInstruction                 // processing-instruction()
)

// NameTest matches by qualified name. Local=="*" is a wildcard.
type NameTest struct {
	Prefix string
	Local  string
	URI    string // set for URIQualifiedNames (Q{uri}local)
}

func (NameTest) nodeTest() {}

// TypeTest matches by node kind (node(), text(), comment()).
type TypeTest struct {
	Kind NodeKind
}

func (TypeTest) nodeTest() {}

// PITest matches processing-instruction nodes, optionally by target name.
type PITest struct {
	Target    string // empty means match any PI
	HasTarget bool
}

func (PITest) nodeTest() {}

// ElementTest matches element(name?, type?).
type ElementTest struct {
	Name     string
	TypeName string
	Nillable bool
}

func (ElementTest) nodeTest() {}

// AttributeTest matches attribute(name?, type?).
type AttributeTest struct {
	Name     string
	TypeName string
}

func (AttributeTest) nodeTest() {}

// DocumentTest matches document-node(element(...)?)
type DocumentTest struct {
	Inner NodeTest // nil = any document node
}

func (DocumentTest) nodeTest() {}

// SchemaElementTest matches schema-element(name).
type SchemaElementTest struct {
	Name string
}

func (SchemaElementTest) nodeTest() {}

// SchemaAttributeTest matches schema-attribute(name).
type SchemaAttributeTest struct {
	Name string
}

func (SchemaAttributeTest) nodeTest() {}

// NamespaceNodeTest matches namespace-node().
type NamespaceNodeTest struct{}

func (NamespaceNodeTest) nodeTest() {}

// FunctionTest matches function(*) or function(ParamTypes...) as ReturnType.
type FunctionTest struct {
	AnyFunction bool           // true for function(*)
	ParamTypes  []SequenceType // parameter types (empty for function(*))
	ReturnType  SequenceType   // return type (zero value for function(*))
}

func (FunctionTest) nodeTest() {}

// MapTest matches map(*) or map(KeyType, ValueType).
type MapTest struct {
	AnyType bool         // true for map(*)
	KeyType NodeTest     // key type (e.g. AtomicOrUnionType for xs:string)
	ValType SequenceType // value sequence type
}

func (MapTest) nodeTest() {}

// ArrayTest matches array(*) or array(MemberType).
type ArrayTest struct {
	AnyType    bool         // true for array(*)
	MemberType SequenceType // member sequence type
}

func (ArrayTest) nodeTest() {}

// AnyItemTest matches item().
type AnyItemTest struct{}

func (AnyItemTest) nodeTest() {}

// AtomicOrUnionType matches a named atomic/union type (e.g. xs:integer).
type AtomicOrUnionType struct {
	Prefix string
	Name   string
}

func (AtomicOrUnionType) nodeTest() {}

// Occurrence constrains sequence cardinality in SequenceType.
type Occurrence int

const (
	OccurrenceExactlyOne Occurrence = iota // (default)
	OccurrenceZeroOrOne                    // ?
	OccurrenceZeroOrMore                   // *
	OccurrenceOneOrMore                    // +
)

// SequenceType is used in instance-of, cast-as, castable-as, treat-as.
type SequenceType struct {
	ItemTest   NodeTest // reuses NodeTest interface for item type matching
	Occurrence Occurrence
	Void       bool // true for empty-sequence()
}
