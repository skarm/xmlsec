package tree

import (
	"maps"
	"slices"
)

// Notation retains a notation's external identifiers without retrieving it.
type Notation struct {
	// SystemID is the declared system identifier without resource retrieval.
	SystemID string
	// PublicID is the optional normalized public identifier.
	PublicID string
	// BaseURI is the declaration's base URI for interpreting relative identifiers.
	BaseURI string
}

// ProcessingInstruction retains a processing instruction in the DTD, which is
// not a child of the document element or the XPath document node.
type ProcessingInstruction struct {
	// Target is the processing instruction target name.
	Target string
	// Data is the processing instruction content after its target.
	Data string
	// BaseURI is the base URI at the declaration site.
	BaseURI string
}

// DocumentType describes the declarations read by the nonvalidating processor.
// Maps and slices returned by DTD are owned by the caller.
type DocumentType struct {
	// Name is the declared document element's lexical name.
	Name string
	// SystemID is the external subset's system identifier, if declared.
	SystemID string
	// PublicID is the external subset's public identifier, if declared.
	PublicID string
	// Notations indexes declarations by notation name.
	Notations map[string]Notation
	// UnparsedEntities indexes unparsed general entities by name.
	UnparsedEntities map[string]UnparsedEntity
	// ProcessingInstructions retains DTD processing instructions in read order.
	ProcessingInstructions []ProcessingInstruction
}

// DTD reports the document type and declarations read during parsing. It does
// not load resources or assert DTD validity. Expanded tree serialization omits
// the original DTD; the declaration information remains available here.
func (d *Document) DTD() (DocumentType, bool) {
	if d == nil || d.dtdInfo == nil {
		return DocumentType{}, false
	}

	out := *d.dtdInfo
	out.Notations = maps.Clone(out.Notations)
	out.UnparsedEntities = maps.Clone(out.UnparsedEntities)
	out.ProcessingInstructions = slices.Clone(out.ProcessingInstructions)

	return out, true
}
