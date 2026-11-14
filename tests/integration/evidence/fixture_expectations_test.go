package evidence_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFixtureExpectations(t *testing.T) {
	const at = "2026-01-02T03:04:05+02:00"
	wantTime := time.Date(2026, time.January, 2, 1, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		name, group, nonce string
		wantNonce          []byte
	}{
		{name: "ocsp_nonce_as_bytes", group: "ocsp", nonce: "00a1ff", wantNonce: []byte{0, 0xa1, 0xff}},
		{name: "empty_ocsp_nonce", group: "ocsp"},
		{name: "archive_has_no_ocsp_expectation", group: "archive", nonce: "unused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instant, nonce, err := fixtureExpectations(evidenceFixture{Name: tc.name, Group: tc.group, At: at, Nonce: tc.nonce})
			if err != nil || !instant.Equal(wantTime) || !bytes.Equal(nonce, tc.wantNonce) {
				t.Errorf("fixture expectations = (%v, %x, %v), want (%v, %x, nil)", instant, nonce, err, wantTime, tc.wantNonce)
			}
		})
	}
}

func TestFixtureExpectationsReportsInvalidFields(t *testing.T) {
	t.Run("validation_time", func(t *testing.T) {
		instant, nonce, err := fixtureExpectations(evidenceFixture{Name: "bad-clock", Group: "ocsp", At: "2026-01-02"})
		var parseErr *time.ParseError
		if !instant.IsZero() || nonce != nil || !errors.As(err, &parseErr) || !strings.Contains(err.Error(), "bad-clock") {
			t.Errorf("invalid validation time returned (%v, %x, %v), want no data and a time parse error naming bad-clock", instant, nonce, err)
		}
	})
	t.Run("ocsp_nonce", func(t *testing.T) {
		instant, nonce, err := fixtureExpectations(evidenceFixture{Name: "bad-nonce", Group: "ocsp", At: "2026-01-02T03:04:05Z", Nonce: "0g"})
		if !instant.IsZero() || nonce != nil || !errors.Is(err, hex.InvalidByteError('g')) || !strings.Contains(err.Error(), "bad-nonce") {
			t.Errorf("invalid OCSP nonce returned (%v, %x, %v), want no data and a hex error naming bad-nonce", instant, nonce, err)
		}
	})
}
