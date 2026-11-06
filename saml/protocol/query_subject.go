package protocol

import (
	"context"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

func validateQueryConfirmation(e document.Element) error {
	if e.Name() != xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmation) || xmlutil.Attrs(e, []string{nameMethod}, nil) != nil || !profile.URI(xmlutil.Attr(e, nameMethod)) {
		return ErrProfile
	}

	cs, err := xmlutil.Children(e)
	if err != nil {
		return err
	}

	if len(cs) > 0 && cs[0].Name() == xmlutil.Name(AssertionNamespace, xmlNameNameID) {
		if _, err := readNameID(cs[0]); err != nil {
			return err
		}

		cs = cs[1:]
	}

	if len(cs) == 0 {
		return nil
	}

	if len(cs) != 1 || cs[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameSubjectConfirmationData) {
		return ErrProfile
	}

	for _, a := range cs[0].Attributes() {
		if a.Name.Space == "" && !slices.Contains([]string{nameNotBefore, nameNotOnOrAfter, nameRecipient, nameInResponseTo, nameAddress}, a.Name.Local) {
			return ErrProfile
		}
	}

	for _, name := range []string{nameNotBefore, nameNotOnOrAfter} {
		if s, ok := cs[0].Attribute(document.Name{Local: name}); ok {
			if _, err := profile.ParseTime(s); err != nil {
				return err
			}
		}
	}

	if s, ok := cs[0].Attribute(document.Name{Local: nameInResponseTo}); ok && !profile.ID(s) {
		return ErrProfile
	}

	if s, ok := cs[0].Attribute(document.Name{Local: nameRecipient}); ok && !uriReference(s) {
		return ErrProfile
	}

	return nil
}

func attributeAttributes(e document.Element) error {
	for _, a := range e.Attributes() {
		if a.Name.Space == "" && !slices.Contains([]string{nameAttributeName, xmlNameNameFormat, xmlNameFriendlyName}, a.Name.Local) {
			return ErrProfile
		}
	}

	if _, ok := e.Attribute(document.Name{Local: nameAttributeName}); !ok {
		return ErrProfile
	}

	return nil
}

func attributeValueType(e document.Element) error {
	const (
		xsiNilAttribute = "nil"
	)

	const xsi = lexicon.NamespaceXSI
	if value, ok := e.Attribute(document.Name{Space: xsi, Local: xsiNilAttribute}); ok {
		nilValue, err := profile.Bool(value)
		if err != nil {
			return err
		}

		if nilValue && (len(e.Children()) != 0 || e.Text() != "") {
			return ErrProfile
		}
	}

	if value, ok := e.Attribute(document.Name{Space: xsi, Local: lexicon.AttrType}); ok {
		value = strings.Trim(value, lexicon.XMLWhitespace)

		prefix, local, qualified := strings.Cut(value, ":")
		if !qualified {
			if !xmlchar.IsValidNCName(prefix) {
				return ErrProfile
			}

			return nil
		}

		if !xmlchar.IsValidNCName(prefix) || !xmlchar.IsValidNCName(local) {
			return ErrProfile
		}

		if uri, ok := e.Namespace(prefix); !ok || uri == "" {
			return ErrProfile
		}
	}

	return nil
}

func encryptSubjectIdentifiers(ctx context.Context, d *document.Document, o *EncryptionOptions) (*document.Document, error) {
	found := false

	for {
		target := authoritySubjectChild(d, xmlNameNameID)
		if !target.Valid() {
			break
		}

		found = true

		var err error

		d, err = encryptSAML(ctx, d, target, xmlNameEncryptedID, o)
		if err != nil {
			return nil, err
		}
	}

	if !found {
		return nil, ErrEncryption
	}

	return d, nil
}
