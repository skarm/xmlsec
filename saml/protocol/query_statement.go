package protocol

import (
	"slices"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

func validateAuthorityStatement(e document.Element) error {
	if e.Name().Space != AssertionNamespace {
		return ErrProfile
	}

	children, err := xmlutil.Children(e)
	if err != nil {
		return err
	}

	switch e.Name().Local {
	case xmlNameAuthnStatement:
		return validateAuthenticationStatement(e, children)
	case xmlNameAttributeStatement:
		return validateAttributeStatement(e, children)
	case xmlNameAuthzDecisionStatement:
		return validateAuthorizationStatement(e, children)
	default:
		return ErrProfile
	}
}

func simpleURI(e document.Element) bool {
	s, err := xmlutil.Simple(e, maximumURITextBytes)
	return err == nil && profile.URI(s)
}

func validateAuthenticationStatement(e document.Element, cs []document.Element) error {
	const (
		xmlNameDNSName         = "DNSName"
		xmlNameSubjectLocality = "SubjectLocality"
	)

	if xmlutil.Attrs(e, []string{xmlNameAuthnInstant}, []string{xmlNameSessionIndex, nameSessionNotOnOrAfter}) != nil {
		return ErrProfile
	}

	instant, err := profile.ParseTime(xmlutil.Attr(e, xmlNameAuthnInstant))
	if err != nil {
		return err
	}

	if s, ok := e.Attribute(document.Name{Local: nameSessionNotOnOrAfter}); ok {
		end, err := profile.ParseTime(s)
		if err != nil || !instant.Before(end) {
			return ErrConditions
		}
	}

	if len(cs) > 0 && cs[0].Name() == xmlutil.Name(AssertionNamespace, xmlNameSubjectLocality) {
		if xmlutil.Attrs(cs[0], nil, []string{nameAddress, xmlNameDNSName}) != nil || !xmlutil.EmptyContent(cs[0]) {
			return ErrProfile
		}

		cs = cs[1:]
	}

	if len(cs) != 1 || cs[0].Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthnContext) || xmlutil.Attrs(cs[0], nil, nil) != nil {
		return ErrProfile
	}

	return validateAuthenticationContext(cs[0])
}

func validateAttributeStatement(e document.Element, cs []document.Element) error {
	const (
		maximumStatementAttributes = 512
	)

	if xmlutil.Attrs(e, nil, nil) != nil || len(cs) == 0 || len(cs) > maximumStatementAttributes {
		return ErrProfile
	}

	for _, a := range cs {
		if _, err := queryAttribute(a); err != nil {
			return err
		}
	}

	return nil
}

func validateAuthorizationStatement(e document.Element, cs []document.Element) error {
	const (
		decisionDeny                          = "Deny"
		decisionIndeterminate                 = "Indeterminate"
		decisionPermit                        = "Permit"
		maximumAuthorizationStatementChildren = 129
		xmlNameDecision                       = "Decision"
	)

	if xmlutil.Attrs(e, []string{xmlNameResource, xmlNameDecision}, nil) != nil || !uriReference(xmlutil.Attr(e, xmlNameResource)) || !slices.Contains([]string{decisionPermit, decisionDeny, decisionIndeterminate}, xmlutil.Attr(e, xmlNameDecision)) {
		return ErrProfile
	}

	if len(cs) == 0 || len(cs) > maximumAuthorizationStatementChildren {
		return ErrProfile
	}

	if cs[len(cs)-1].Name() == xmlutil.Name(AssertionNamespace, xmlNameEvidence) {
		if err := validateEvidence(cs[len(cs)-1]); err != nil {
			return err
		}

		cs = cs[:len(cs)-1]
	}

	if len(cs) == 0 {
		return ErrProfile
	}

	for _, a := range cs {
		if _, err := readAction(a); err != nil {
			return err
		}
	}

	return nil
}

func validateAuthenticationContext(context document.Element) error {
	const (
		maximumAuthenticationContextChildren = 130
		xmlNameAuthnContextDecl              = "AuthnContextDecl"
	)

	refs, err := xmlutil.Children(context)
	if err != nil || len(refs) == 0 || len(refs) > maximumAuthenticationContextChildren {
		return ErrProfile
	}

	i := 0

	if refs[0].Name() == xmlutil.Name(AssertionNamespace, xmlNameAuthnContextClassRef) {
		if !simpleURI(refs[0]) {
			return ErrProfile
		}

		i++
	}

	if i < len(refs) && refs[i].Name() == xmlutil.Name(AssertionNamespace, xmlNameAuthnContextDecl) {
		i++
	} else if i < len(refs) && refs[i].Name() == xmlutil.Name(AssertionNamespace, xmlNameAuthnContextDeclRef) {
		if !simpleURI(refs[i]) {
			return ErrProfile
		}

		i++
	}

	if i == 0 {
		return ErrProfile
	}

	for _, c := range refs[i:] {
		if c.Name() != xmlutil.Name(AssertionNamespace, xmlNameAuthenticatingAuthority) || !simpleURI(c) {
			return ErrProfile
		}
	}

	return nil
}
