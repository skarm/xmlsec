package x509crl

import (
	"encoding/asn1"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
)

func TestPKIXTimeFormsAndCenturyBoundary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tag   int
		input string
		year  int
		valid bool
	}{
		{asn1.TagUTCTime, "491231235959Z", 2049, true},
		{asn1.TagUTCTime, "500101000000Z", 1950, true},
		{asn1.TagUTCTime, "680229123456Z", 1968, true},
		{asn1.TagUTCTime, "690101000000Z", 1969, true},
		{asn1.TagUTCTime, "000229000000Z", 2000, true},
		{asn1.TagGeneralizedTime, "00010101000000Z", 1, true},
		{asn1.TagGeneralizedTime, "20500101000000Z", 2050, true},
		{asn1.TagGeneralizedTime, "99991231235959Z", 9999, true},
		{asn1.TagGeneralizedTime, "00000101000000Z", 0, false},
		{asn1.TagGeneralizedTime, "20230229000000Z", 0, false},
		{asn1.TagGeneralizedTime, "20000101000000.1Z", 0, false},
		{asn1.TagUTCTime, "5001010000Z", 0, false},
		{asn1.TagUTCTime, "500101000000+0000", 0, false},
		{asn1.TagUTCTime, "500101000060Z", 0, false},
		{asn1.TagUTF8String, "500101000000Z", 0, false},
	} {
		got, err := parseTime(asn1.RawValue{Tag: tc.tag, Bytes: []byte(tc.input), FullBytes: der.Wrap(0, tc.tag, false, []byte(tc.input))})
		if (err == nil) != tc.valid || tc.valid && (got.Year() != tc.year || got.Location() != time.UTC) {
			t.Fatalf("%d/%s: %v, %v", tc.tag, tc.input, got, err)
		}
	}
}
