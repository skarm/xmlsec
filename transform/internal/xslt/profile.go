// Copyright (c) 2026 xmlsec contributors. MIT License.

package xslt

import (
	"errors"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
	"github.com/skarm/xmlsec/transform/internal/xslt/internal/elements"
)

// ErrLanguageUnsupported identifies features outside the modern Basic profile.
var ErrLanguageUnsupported = errors.New("unsupported XSLT language profile")

// CheckLanguage validates version boundaries using the grammar table from
// knroy/go-xml. It supplements helium's existing syntax checks and version
// compatibility behavior. The Basic profile excludes schema awareness and
// streaming; neither is silently approximated by this API.
func CheckLanguage(d *xdm.Document, want int) (int, error) {
	return CheckProcessorLanguage(d, want, 0)
}

// CheckProcessorLanguage keeps the processor selection separate from the
// principal declaration and each element's effective compatibility version.
func CheckProcessorLanguage(d *xdm.Document, want, processor int) (int, error) {
	if d == nil || d.DocumentElement() == nil {
		return 0, ErrLanguageUnsupported
	}

	root := d.DocumentElement()

	number, err := strconv.ParseFloat(languageVersionAttribute(root), 64)
	if err != nil || !(number >= 1 && number < 2) && number != 2 && number != 3 {
		return 0, ErrLanguageUnsupported
	}

	version := int(number * 10)
	if number >= 1 && number < 2 {
		version = 10
	}

	if want != 0 && want != version {
		return 0, ErrLanguageUnsupported
	}

	if processor == 0 {
		processor = version
	}

	if processor != 10 && processor != 20 && processor != 30 || processor < version {
		return 0, ErrLanguageUnsupported
	}

	if processor == 10 {
		return processor, checkLanguage10(root)
	}

	return processor, checkModernLanguage(root, version, processor)
}

func languageVersionAttribute(elem *xdm.Element) string {
	if elem.URI() == lexicon.NamespaceXSLT {
		return getAttr(elem, paramVersion)
	}

	version := ""

	for _, attribute := range elem.Attributes() {
		if attribute.URI() == lexicon.NamespaceXSLT && attribute.LocalName() == paramVersion {
			version = xdm.CharacterData(attribute)
		}
	}

	return version
}

func checkModernLanguage(elem *xdm.Element, effective, selected int) error {
	if own := languageVersionAttribute(elem); own != "" {
		number, err := strconv.ParseFloat(own, 64)
		if err != nil || !(number >= 1 && number < 2) && number != 2 && number != 3 {
			return ErrLanguageUnsupported
		}

		effective = int(number * 10)
		if effective > selected {
			return staticError("XTSE0010", "nested version exceeds the selected language profile")
		}
	}

	if err := checkModernElementLanguage(elem, selected); err != nil {
		return err
	}

	for child := elem.FirstChild(); child != nil; child = child.NextSibling() {
		if element, ok := child.(*xdm.Element); ok {
			if err := checkModernLanguage(element, effective, selected); err != nil {
				return err
			}
		}
	}

	return nil
}

func checkModernElementLanguage(elem *xdm.Element, effective int) error {
	if elem.URI() != lexicon.NamespaceXSLT {
		return checkLiteralElementLanguage(elem, effective)
	}

	name := elem.LocalName()

	def, known := lookupXSLTElement(name)
	if known && (def.since30 || elements.MinVersion(name) == "3.0") && effective < 30 {
		return staticError("XTSE0010", "xsl:%s requires XSLT 3.0", name)
	}

	if name == "import-schema" || name == "stream" {
		return ErrLanguageUnsupported
	}

	for _, attribute := range elem.Attributes() {
		if attribute.URI() != "" {
			continue
		}

		if err := checkModernAttributeLanguage(attribute.LocalName(), xdm.CharacterData(attribute), name, def, effective); err != nil {
			return err
		}
	}

	if effective < 30 {
		for attribute, metadata := range def.attrs {
			if metadata.optional30 && getAttr(elem, attribute) == "" {
				return staticError("XTSE0010", "xsl:%s requires %s in XSLT 2.0", name, attribute)
			}
		}
	}

	return nil
}

func checkLiteralElementLanguage(elem *xdm.Element, effective int) error {
	if effective >= 30 {
		return nil
	}

	for _, attribute := range elem.Attributes() {
		if attribute.URI() == lexicon.NamespaceXSLT && attribute.LocalName() == nameExpandText {
			return staticError("XTSE0090", "expand-text requires XSLT 3.0")
		}
	}

	return nil
}

func checkModernAttributeLanguage(attribute, value, element string, def elementDef, effective int) error {
	if unsupportedBasicAttribute(attribute, value) {
		return ErrLanguageUnsupported
	}

	if effective < 30 && attribute == paramMethod && (value == "json" || value == "adaptive") {
		return staticError("XTSE0020", "serialization method requires XSLT 3.0")
	}

	if strings.HasPrefix(attribute, "_") && effective < 30 {
		return staticError("XTSE0090", "shadow attributes require XSLT 3.0")
	}

	if attribute == "_version" {
		return ErrLanguageUnsupported
	}

	if effective < 30 {
		if metadata, ok := def.attrs[attribute]; ok && (metadata.since30 || metadata.processor30) {
			return staticError("XTSE0090", "%s on xsl:%s requires XSLT 3.0", attribute, element)
		}

		if attribute == nameExpandText || attribute == nameDefaultMode || attribute == nameUseAccumulators {
			return staticError("XTSE0090", "%s requires XSLT 3.0", attribute)
		}
	}

	if attribute == "as" {
		sequenceType, err := xpath.ParseSequenceType(value)
		if err != nil {
			return err
		}

		return xpath.CheckTypeLanguage(sequenceType, map[int]int{20: 20, 30: 31}[effective])
	}

	return nil
}

func unsupportedBasicAttribute(attribute, value string) bool {
	switch attribute {
	case nameValidation, nameDefaultValidation:
		return value == validationStrict || value == validationLax
	case nameType:
		return true
	case nameTyped:
		return value == validationStrict || value == nameYes || value == nameTrue || value == "1"
	case nameStreamable:
		return value == nameYes || value == nameTrue || value == "1"
	default:
		return false
	}
}
