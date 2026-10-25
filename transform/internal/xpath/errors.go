// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"errors"
	"fmt"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

const (
	errCodeXPST0003 = "XPST0003"
	errCodeXPST0008 = "XPST0008"
	errCodeXPDY0002 = "XPDY0002"
	errCodeXPDY0050 = "XPDY0050"
	errCodeXPST0080 = "XPST0080"
	errCodeXPST0081 = "XPST0081"
	errCodeFOAR0001 = "FOAR0001"
	errCodeFOAR0002 = "FOAR0002"
	errCodeFOAP0001 = "FOAP0001"
	errCodeFOCA0002 = "FOCA0002"
	errCodeFOCH0002 = "FOCH0002"
	errCodeFOCH0003 = "FOCH0003"
	errCodeFODC0001 = "FODC0001"
	errCodeFODC0002 = "FODC0002"
	errCodeFODC0004 = "FODC0004"
	errCodeFODC0005 = "FODC0005"
	errCodeFODC0006 = "FODC0006"
	errCodeFODT0001 = "FODT0001"
	errCodeFODT0002 = "FODT0002"
	errCodeFODF1280 = "FODF1280"
	errCodeFODF1310 = "FODF1310"
	errCodeFOFD1340 = "FOFD1340"
	errCodeFOFD1350 = "FOFD1350"
	errCodeFOAY0001 = "FOAY0001"
	errCodeFOTY0012 = "FOTY0012"
	errCodeFOTY0013 = "FOTY0013"
	errCodeFONS0004 = "FONS0004"
	errCodeFORG0001 = "FORG0001"
	errCodeFORG0006 = "FORG0006"
	errCodeFOER0000 = "FOER0000"
	errCodeFORX0001 = "FORX0001"
	errCodeFORX0002 = "FORX0002"
	errCodeFORX0003 = "FORX0003"
	errCodeFORX0004 = "FORX0004"
	errCodeFOTY0014 = "FOTY0014"
	errCodeFOJS0001 = "FOJS0001"
	errCodeFOJS0003 = "FOJS0003"
	errCodeFOJS0004 = "FOJS0004"
	errCodeFOJS0005 = "FOJS0005"
	errCodeFOJS0006 = "FOJS0006"
	errCodeFOJS0007 = "FOJS0007"
	errCodeFORG0002 = "FORG0002"
	errCodeSENR0001 = "SENR0001"
	errCodeXPTY0018 = "XPTY0018"
	errCodeXPTY0019 = "XPTY0019"
	errCodeXPTY0020 = "XPTY0020"
)

// UndefinedVariableError preserves the lookup category and the language code.
func UndefinedVariableError(name string, version int) error {
	return languageError(fmt.Errorf("%w: $%s", ErrUndefinedVariable, name), errCodeXPST0008, version)
}

func languageError(cause error, code string, version int) error {
	if version == 10 {
		return cause
	}

	return &xdm.Error{Code: code, Message: cause.Error(), Cause: cause}
}

// Error message constants reused across the package.
const (
	errMsgContextItemAbsent = "context item is absent"
	errMsgPathMixedResult   = "path expression result contains a mix of nodes and non-nodes"
)

// Sentinel errors for the xpath package.
var (
	ErrNotNodeSet               = errors.New("xpath: result is not a node-set")
	ErrRecursionLimit           = errors.New("xpath: recursion limit exceeded")
	ErrOpLimit                  = errors.New("xpath: operation limit exceeded")
	ErrUnknownFunction          = errors.New("xpath: unknown function")
	ErrUnknownFunctionNamespace = errors.New("xpath: unknown function namespace prefix")
	ErrUnsupportedExpr          = errors.New("xpath: unsupported expression type")
	ErrUndefinedVariable        = errors.New("xpath: undefined variable")
	ErrTypeMismatch             = errors.New("xpath: type mismatch")
	ErrArityMismatch            = errors.New("xpath: arity mismatch")
	ErrUnexpectedToken          = errors.New("xpath: unexpected token")
	ErrUnexpectedChar           = errors.New("xpath: unexpected character")
	ErrUnterminatedString       = errors.New("xpath: unterminated string")
	ErrUnknownAxis              = errors.New("xpath: unknown axis")
	ErrExpectedToken            = errors.New("xpath: expected token")
	ErrExprTooDeep              = errors.New("xpath: expression nesting too deep")
	ErrUnionNotNodeSet          = errors.New("xpath: union operands must be node-sets")
	// ErrPathNotNodeSet is the XPTY0019 type error raised when a step of a path
	// expression other than the last returns a non-node. It is an [*XPathError],
	// so an XPath try/catch on err:XPTY0019 catches it.
	ErrPathNotNodeSet      error = &xdm.Error{Code: errCodeXPTY0019, Message: "path expression requires node-set"}
	ErrUnsupportedBinaryOp       = errors.New("xpath: unsupported binary operator")
	// ErrNodeSetLimit is returned when a node-set exceeds the maximum length.
	// Aliased from transform/internal/xpath so errors.Is works end-to-end.
	ErrNodeSetLimit = xdm.ErrNodeSetLimit
)

// syntaxError preserves parser sentinels and adds the standard error code for
// XPath 2.0 and later. XPath 1.0 has no standard error-code vocabulary.
func syntaxError(err error, version int) error {
	if version == 10 || err == nil {
		return err
	}

	if detail, ok := errors.AsType[*xdm.Error](err); ok && detail.Code != "" {
		return err
	}

	for _, cause := range []error{ErrUnexpectedToken, ErrUnexpectedChar, ErrUnterminatedString, ErrExpectedToken, ErrUnknownAxis} {
		if errors.Is(err, cause) {
			return &xdm.Error{Code: errCodeXPST0003, Message: err.Error(), Cause: err}
		}
	}

	return err
}
