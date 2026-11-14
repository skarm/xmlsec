package x509cert //nolint:testpackage // Checks the DER representation of the critical default.

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
)

func TestValidateExtensionDefault(t *testing.T) {
	t.Parallel()
	oid := der.OID(asn1.ObjectIdentifier{1, 2, 3, 4})
	value := der.Octets([]byte{5, 0})
	for _, tc := range []struct {
		name    string
		encoded []byte
		wantErr error
	}{
		{"default_is_omitted", der.Seq(oid, value), nil},
		{"explicit_true", der.Seq(oid, []byte{1, 1, 0xff}, value), nil},
		{"explicit_default_false", der.Seq(oid, []byte{1, 1, 0}, value), der.ErrInvalidDER},
		{"critical_field_is_not_boolean", der.Seq(oid, der.Int(1), value), der.ErrInvalidDER},
		{"missing_extension_value", der.Seq(oid), der.ErrInvalidDER},
		{"extra_component", der.Seq(oid, []byte{1, 1, 0xff}, value, der.Int(1)), der.ErrInvalidDER},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			extension, err := der.Read(tc.encoded, len(tc.encoded))
			if err != nil {
				t.Fatalf("read DER fixture: %v", err)
			}
			if err := validateExtensionDefault(extension); !errors.Is(err, tc.wantErr) {
				t.Errorf("validateExtensionDefault returned %v, want %v", err, tc.wantErr)
			}
		})
	}
}
