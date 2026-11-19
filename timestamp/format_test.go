package timestamp //nolint:testpackage // Covers RFC 3161 wire encoding before issuance applies certificate validity.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/skarm/xmlsec/internal/der"
)

func TestCreateRequestReaderOwnsRequestFields(t *testing.T) {
	t.Parallel()

	const message = "timestamped message"
	wantDigest := sha512.Sum384([]byte(message))
	wantNonce := new(big.Int).SetBytes(bytes.Repeat([]byte{0x91}, 16))
	wantPolicy := asn1.ObjectIdentifier{1, 2, 3, 4}
	nonce := wantNonce.Bytes()
	policy := append(asn1.ObjectIdentifier(nil), wantPolicy...)
	request, err := CreateRequestReader(t.Context(), iotest.OneByteReader(strings.NewReader(message)), RequestOptions{
		Hash: crypto.SHA384, Nonce: nonce, Policy: policy, OmitCertificates: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	originalDER := request.DER()
	raw := request.DER()
	reparsed, err := ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	clear(nonce)
	clear(policy)
	clear(raw)
	for _, r := range []*Request{request, reparsed} {
		imprint := r.Imprint()
		if imprint.Hash != crypto.SHA384 || !bytes.Equal(imprint.Digest, wantDigest[:]) ||
			!r.Policy().Equal(wantPolicy) || r.Nonce().Cmp(wantNonce) != 0 ||
			r.CertificatesRequested() || !bytes.Equal(r.DER(), originalDER) {
			t.Fatal("request lost imprint, nonce, policy, certificate preference or encoding")
		}
		clear(imprint.Digest)
		clear(r.Policy())
		r.Nonce().SetInt64(0)
		clear(r.DER())
		if !bytes.Equal(r.Imprint().Digest, wantDigest[:]) || !r.Policy().Equal(wantPolicy) ||
			r.Nonce().Cmp(wantNonce) != 0 || !bytes.Equal(r.DER(), originalDER) {
			t.Error("mutating accessor results changed the request")
		}
	}
}

func TestCreateRequestReaderPreservesInputFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("message read failed")
	var nilReader *bytes.Reader
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		reader  io.Reader
		options RequestOptions
		wantErr error
	}{
		{"typed_nil_reader", t.Context(), nilReader, RequestOptions{}, ErrPolicy},
		{"unsupported_digest", t.Context(), iotest.ErrReader(failure), RequestOptions{Hash: crypto.SHA3_256}, ErrPolicy},
		{"disabled_legacy_digest", t.Context(), iotest.ErrReader(failure), RequestOptions{Hash: crypto.SHA1}, ErrPolicy},
		{"invalid_policy", t.Context(), iotest.ErrReader(failure), RequestOptions{Policy: asn1.ObjectIdentifier{3, 0}}, ErrPolicy},
		{"conflicting_nonce", t.Context(), iotest.ErrReader(failure), RequestOptions{Nonce: bytes.Repeat([]byte{1}, 16), OmitNonce: true}, ErrPolicy},
		{"empty_nonce", t.Context(), iotest.ErrReader(failure), RequestOptions{Nonce: []byte{}}, ErrPolicy},
		{"zero_nonce", t.Context(), iotest.ErrReader(failure), RequestOptions{Nonce: make([]byte, 16)}, ErrPolicy},
		{"reader_failure", t.Context(), iotest.ErrReader(failure), RequestOptions{}, failure},
		{"omitted_nonce", t.Context(), iotest.ErrReader(failure), RequestOptions{Nonce: []byte{}, OmitNonce: true}, failure},
		{"canceled", canceled, strings.NewReader("input"), RequestOptions{}, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if request, err := CreateRequestReader(tc.ctx, tc.reader, tc.options); request != nil || !errors.Is(err, tc.wantErr) {
				t.Errorf("CreateRequestReader = (%v, %v), want no request and %v", request, err, tc.wantErr)
			}
		})
	}
}

func TestImprintReaderDoesNotPublishCanceledDigest(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := imprintReaderFunc(func(dst []byte) (int, error) {
		cancel()
		return copy(dst, "message"), io.EOF
	})
	imprint, err := ImprintReader(ctx, source, crypto.SHA256)
	if imprint.Hash != 0 || imprint.Digest != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("ImprintReader = (%+v, %v), want zero imprint and cancellation", imprint, err)
	}
}

type imprintReaderFunc func([]byte) (int, error)

func (f imprintReaderFunc) Read(dst []byte) (int, error) { return f(dst) }

func TestEncodeTimeUsesUTCYearBounds(t *testing.T) {
	t.Parallel()

	west := time.FixedZone("UTC-01:00", -3600)
	east := time.FixedZone("UTC+01:00", 3600)
	for _, tc := range []struct {
		name string
		at   time.Time
		want string
	}{
		{"local_year_10000_utc_year_9999", time.Date(10000, 1, 1, 0, 0, 0, 0, east), "99991231230000Z"},
		{"local_year_9999_utc_year_10000", time.Date(9999, 12, 31, 23, 0, 0, 0, west), ""},
		{"local_year_0_utc_year_1", time.Date(0, 12, 31, 23, 1, 0, 0, west), "00010101000100Z"},
		{"local_year_1_utc_year_0", time.Date(1, 1, 1, 0, 0, 0, 0, east), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := encodeTime(tc.at)
			if tc.want == "" {
				if !errors.Is(err, ErrPolicy) || raw != nil {
					t.Errorf("encodeTime = (%x, %v), want no bytes and %v", raw, err, ErrPolicy)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			value, err := der.Read(raw, len(raw))
			if err != nil || !der.Is(value, asn1.ClassUniversal, asn1.TagGeneralizedTime, false) || string(value.Bytes) != tc.want {
				t.Errorf("GeneralizedTime = (%q, %v), want %q", value.Bytes, err, tc.want)
			}
		})
	}
}
