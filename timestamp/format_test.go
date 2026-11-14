package timestamp_test

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

	"github.com/skarm/xmlsec/timestamp"
)

func TestCreateRequestReaderOwnsRequestFields(t *testing.T) {
	t.Parallel()

	const message = "timestamped message"
	wantDigest := sha512.Sum384([]byte(message))
	wantNonce := new(big.Int).SetBytes(bytes.Repeat([]byte{0x91}, 16))
	wantPolicy := asn1.ObjectIdentifier{1, 2, 3, 4}
	nonce := wantNonce.Bytes()
	policy := append(asn1.ObjectIdentifier(nil), wantPolicy...)
	request, err := timestamp.CreateRequestReader(t.Context(), iotest.OneByteReader(strings.NewReader(message)), timestamp.RequestOptions{
		Hash: crypto.SHA384, Nonce: nonce, Policy: policy, OmitCertificates: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	originalDER := request.DER()
	raw := request.DER()
	reparsed, err := timestamp.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	clear(nonce)
	clear(policy)
	clear(raw)
	for _, r := range []*timestamp.Request{request, reparsed} {
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
		hash    crypto.Hash
		wantErr error
	}{
		{"typed_nil_reader", t.Context(), nilReader, 0, timestamp.ErrPolicy},
		{"unsupported_digest", t.Context(), iotest.ErrReader(failure), crypto.SHA3_256, timestamp.ErrPolicy},
		{"disabled_legacy_digest", t.Context(), iotest.ErrReader(failure), crypto.SHA1, timestamp.ErrPolicy},
		{"reader_failure", t.Context(), iotest.ErrReader(failure), 0, failure},
		{"canceled", canceled, strings.NewReader("input"), 0, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if request, err := timestamp.CreateRequestReader(tc.ctx, tc.reader, timestamp.RequestOptions{Hash: tc.hash}); request != nil || !errors.Is(err, tc.wantErr) {
				t.Errorf("CreateRequestReader = (%v, %v), want no request and %v", request, err, tc.wantErr)
			}
		})
	}
}
