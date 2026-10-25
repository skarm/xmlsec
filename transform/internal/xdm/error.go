// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xdm

import (
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
)

// Error is a structured error with an XPath error code.
// Codes are stored without namespace prefix (e.g. "XPTY0004", not "err:XPTY0004").
type Error struct {
	Cause         error  // xmlsec: preserve cancellation, parser and resolver causes.
	Code          string // e.g. "XPTY0004", "FOER0000" (without err: prefix)
	Message       string
	QualifiedCode QNameValue
	Value         Sequence // fn:error's arbitrary error object; node identity is preserved.
}

// Unwrap preserves the original dynamic failure.
func (e *Error) Unwrap() error { return e.Cause }

func (e *Error) Error() string {
	if e == nil {
		return "<nil XPathError>"
	}

	code := e.displayCode()
	if code == "" {
		return e.Message
	}

	return code + ": " + e.Message
}

// Is supports errors.Is matching by code.
func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}

	if t, ok := target.(*Error); ok {
		actual := e.CodeQName()

		want := t.CodeQName()
		if want.Local == "" {
			return false
		}

		if want.URI != "" {
			return actual.URI == want.URI && actual.Local == want.Local
		}

		return actual.Local == want.Local
	}

	return false
}

// CodeQName returns the error code as a QNameValue.
func (e *Error) CodeQName() QNameValue {
	if e == nil {
		return QNameValue{}
	}

	if e.QualifiedCode.Local != "" {
		return e.QualifiedCode
	}

	if e.Code == "" {
		return QNameValue{}
	}

	return QNameValue{Prefix: lexicon.PrefixErr, URI: lexicon.NamespaceErr, Local: e.Code}
}

func (e *Error) displayCode() string {
	qv := e.CodeQName()
	if qv.Local == "" {
		return ""
	}

	if qv.URI == "" || qv.URI == lexicon.NamespaceErr {
		return qv.Local
	}

	if qv.Prefix != "" {
		return qv.Prefix + ":" + qv.Local
	}

	return "Q{" + qv.URI + "}" + qv.Local
}
