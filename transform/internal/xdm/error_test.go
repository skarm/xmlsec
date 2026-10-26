package xdm_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestErrorCodeMatchingAndCause(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("resolver refused")
	e := &xdm.Error{Code: "FOER0000", Message: "message", Cause: sentinel}
	wrapped := fmt.Errorf("outer: %w", e)
	if !errors.Is(wrapped, sentinel) || !errors.Is(wrapped, &xdm.Error{Code: "FOER0000"}) || errors.Is(wrapped, &xdm.Error{Code: "OTHER"}) || errors.Is(wrapped, &xdm.Error{}) {
		t.Fatal("cause/code error matching failed")
	}
	if e.Error() != "FOER0000: message" || e.CodeQName().URI != "http://www.w3.org/2005/xqt-errors" {
		t.Fatalf("builtin error QName: %v", e)
	}
	custom := &xdm.Error{Code: "IGNORED", Message: "custom", QualifiedCode: xdm.QNameValue{Prefix: "p", Local: "failure", URI: "urn:app"}}
	if custom.Error() != "p:failure: custom" || !errors.Is(custom, &xdm.Error{QualifiedCode: xdm.QNameValue{Local: "failure"}}) || !errors.Is(custom, &xdm.Error{QualifiedCode: xdm.QNameValue{Local: "failure", URI: "urn:app"}}) || errors.Is(custom, &xdm.Error{QualifiedCode: xdm.QNameValue{Local: "failure", URI: "urn:other"}}) || errors.Is(custom, &xdm.Error{Code: "IGNORED"}) {
		t.Fatal("qualified error code precedence/matching")
	}
	custom.QualifiedCode.Prefix = ""
	if custom.Error() != "Q{urn:app}failure: custom" {
		t.Fatal("expanded error formatting")
	}
	custom.QualifiedCode.URI = ""
	if custom.Error() != "failure: custom" {
		t.Fatal("unqualified error formatting")
	}
	plain := &xdm.Error{Message: "only message"}
	if plain.Error() != "only message" || plain.CodeQName().Local != "" || plain.Is(sentinel) {
		t.Fatal("message-only error contract")
	}
	var absent *xdm.Error
	if absent.Error() != "<nil XPathError>" || absent.Is(e) || absent.CodeQName() != (xdm.QNameValue{}) {
		t.Fatal("nil structured error methods")
	}
	access := &xdm.ResourceAccessError{Cause: e}
	if access.Error() != e.Error() || !errors.Is(access, sentinel) || !errors.Is(access, &xdm.Error{Code: "FOER0000"}) {
		t.Fatal("resource error did not preserve structured cause")
	}
}
