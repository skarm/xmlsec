package pki_test

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
)

func TestOCSPNextUpdateIsExclusive(t *testing.T) {
	c := testcert.New(t)

	q, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := ocspTemplate()

	raw, err := pki.CreateOCSPResponse(t.Context(), q, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, tmpl)
	if err != nil {
		t.Fatal(err)
	}

	for _, skew := range []time.Duration{0, time.Second} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			at := tmpl.NextUpdate.Add(skew + delta)

			result, report, err := pki.VerifyOCSP(t.Context(), raw, c.Leaf.Raw, c.Root.Raw, at, pki.OCSPOptions{ClockSkew: skew})
			if report.Signature != pki.Valid {
				t.Fatal("control must have an authenticated signature", report, err)
			}

			if delta < 0 {
				if err != nil || result == nil {
					t.Fatalf("fresh response rejected: %v", err)
				}
			} else if result != nil || !errors.Is(err, pki.ErrUnavailable) {
				t.Fatalf("expired response accepted at nextUpdate+%v: result=%v, error=%v", skew+delta, result != nil, err)
			}
		}
	}
}

func TestOCSPResponseStatusEnumeration(t *testing.T) {
	c := testcert.New(t)

	for _, status := range []int{-1, 1, 2, 3, 4, 5, 6, 7, 99} {
		encoded, err := asn1.Marshal(asn1.Enumerated(status))
		if err != nil {
			t.Fatal(err)
		}

		want := pki.ErrUnavailable
		if status < 0 || status == 4 || status > 6 {
			want = pki.ErrEvidence
		}

		result, report, err := pki.VerifyOCSP(t.Context(), der.Seq(encoded), c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{})
		// Verification reports retain diagnostics on failure.
		//noinspection GoDfaErrorMayBeNotNil
		if result != nil || !errors.Is(err, want) || report.Signature != pki.NotChecked {
			t.Fatalf("status %d: result=%v, report=%v, error=%v; want %v", status, result != nil, report, err, want)
		}
	}
}

func TestOCSPResponderAcceptsLegacyNonceLengths(t *testing.T) {
	c := testcert.New(t)

	request, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	v, err := der.Read(request, len(request))
	if err != nil {
		t.Fatal(err)
	}

	f, err := der.Sequence(v, 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	tbs, err := der.Sequence(f[0], 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range []int{0, 1, 15, 16, 31, 32, 33, 128, 129} {
		nonce := bytes.Repeat([]byte{42}, n)
		ext := der.Seq(der.Seq(der.OID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}), der.Octets(der.Octets(nonce))))
		raw := der.Seq(der.Seq(tbs[0].FullBytes, der.Ctx(2, ext)))

		parsed, err := pki.ParseOCSPRequest(raw)
		if n == 0 || n > 128 {
			if parsed != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatalf("invalid nonce length %d accepted: %v", n, err)
			}

			continue
		}

		if err != nil || !bytes.Equal(parsed.Nonce(), nonce) {
			t.Fatalf("valid inbound nonce length %d rejected: %v", n, err)
		}

		response, err := pki.CreateOCSPResponse(t.Context(), raw, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, ocspTemplate())
		if err != nil {
			t.Fatal(err)
		}

		if result, _, err := pki.VerifyOCSP(t.Context(), response, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{ExpectedNonce: nonce}); err != nil || result == nil {
			t.Fatalf("legacy nonce length %d failed response binding: %v", n, err)
		}
	}
}

func TestOCSPRequiresPKIXTimeEncoding(t *testing.T) {
	c := testcert.New(t)

	q, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := pki.CreateOCSPResponse(t.Context(), q, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	for field := range 4 {
		if field == 3 {
			raw, err = pki.CreateOCSPResponse(t.Context(), q, c.Leaf.Raw, c.Root.Raw, c.Root.Raw, c.RootKey, pki.OCSPResponseTemplate{Status: pki.OCSPRevoked, ProducedAt: testcert.Now(), ThisUpdate: testcert.Now().Add(-time.Minute), NextUpdate: testcert.Now().Add(time.Hour), RevokedAt: testcert.Now().Add(-2 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}

			// Verification reports retain diagnostics on failure.
			//noinspection GoDfaErrorMayBeNotNil
			if result, report, err := pki.VerifyOCSP(t.Context(), raw, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{}); result != nil || !errors.Is(err, pki.ErrRevoked) || report.Signature != pki.Valid {
				t.Fatal("invalid authenticated revoked control", err)
			}
		}

		for _, text := range []string{"202610081200Z", "20261008120000.1Z", "20261008140000+0200"} {
			modified := replaceOCSPTime(t, raw, c, field, text)

			result, _, err := pki.VerifyOCSP(t.Context(), modified, c.Leaf.Raw, c.Root.Raw, testcert.Now(), pki.OCSPOptions{})
			if result != nil || !errors.Is(err, pki.ErrEvidence) {
				t.Fatalf("field=%d time=%q result=%v error=%v", field, text, result != nil, err)
			}
		}
	}
}

// Rewrite authenticated OCSP data and re-sign it: failure cannot be attributed
// to a broken signature or stale evidence.
func replaceOCSPTime(t *testing.T, raw []byte, c testcert.Chain, field int, text string) []byte {
	t.Helper()

	v, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}

	f, err := der.Sequence(v, 2, 2)
	if err != nil {
		t.Fatal(err)
	}

	x, err := der.Explicit(f[1], 0)
	if err != nil {
		t.Fatal(err)
	}

	r, err := der.Sequence(x, 2, 2)
	if err != nil {
		t.Fatal(err)
	}

	var body []byte
	if err := der.Decode(r[1], &body); err != nil {
		t.Fatal(err)
	}

	v, err = der.Read(body, len(body))
	if err != nil {
		t.Fatal(err)
	}

	basic, err := der.Sequence(v, 3, 4)
	if err != nil {
		t.Fatal(err)
	}

	tbs, err := der.Sequence(basic[0], 3, 4)
	if err != nil {
		t.Fatal(err)
	}

	parts := make([][]byte, len(tbs))
	for i := range tbs {
		parts[i] = tbs[i].FullBytes
	}

	encoded := der.Wrap(0, asn1.TagGeneralizedTime, false, []byte(text))
	if field == 0 {
		parts[1] = encoded
	} else {
		entries, err := der.Sequence(tbs[2], 1, 1)
		if err != nil {
			t.Fatal(err)
		}

		single, err := der.Sequence(entries[0], 3, 5)
		if err != nil {
			t.Fatal(err)
		}

		one := make([][]byte, len(single))
		for i := range single {
			one[i] = single[i].FullBytes
		}

		switch field {
		case 1:
			one[2] = encoded
		case 2:
			one[3] = der.Ctx(0, encoded)
		default:
			revoked, err := der.Children(single[1])
			if err != nil || len(revoked) != 1 {
				t.Fatal("invalid revoked test response", err)
			}

			one[1] = der.Wrap(2, 1, true, encoded)
		}

		parts[2] = der.Seq(der.Seq(one...))
	}

	data := der.Seq(parts...)

	algorithm, err := signature.Algorithm(basic[1])
	if err != nil {
		t.Fatal(err)
	}

	sig, err := signature.Sign(t.Context(), c.RootKey, algorithm, data)
	if err != nil {
		t.Fatal(err)
	}

	bits, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})

	return der.Seq(f[0].FullBytes, der.Ctx(0, der.Seq(r[0].FullBytes, der.Octets(der.Seq(data, basic[1].FullBytes, bits)))))
}

func TestOCSPUnknownNoncriticalRequestExtensions(t *testing.T) {
	c := testcert.New(t)
	request, err := pki.CreateOCSPRequest(c.Leaf.Raw, c.Root.Raw, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, err := der.Read(request, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := der.Sequence(value, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := der.Sequence(outer[0], 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, critical := range []bool{false, true} {
		name := "noncritical"
		if critical {
			name = "critical"
		}
		t.Run(name, func(t *testing.T) {
			items := [][]byte{der.OID(asn1.ObjectIdentifier{1, 2, 3, 4, 5})}
			if critical {
				items = append(items, []byte{1, 1, 255})
			}
			items = append(items, der.Octets([]byte{5, 0}))
			changed := der.Seq(der.Seq(fields[0].FullBytes, der.Ctx(2, der.Seq(der.Seq(items...)))))
			result, err := pki.ParseOCSPRequest(changed)
			if critical {
				if result != nil || !errors.Is(err, pki.ErrUnsupported) {
					t.Fatal(result, err)
				}
			} else if err != nil || result == nil {
				t.Fatal(result, err)
			}
		})
	}
}

func TestOCSPSingleResponseExtensionSchema(t *testing.T) {
	c := makeChain(t)
	at := verificationTime()
	base := p7Response(t, c, pki.OCSPResponseTemplate{Status: pki.OCSPGood, ProducedAt: at, ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour)})
	cutoff := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6}
	for _, tc := range []struct {
		name string
		ext  pkix.Extension
		want error
	}{
		{"unknown noncritical extension", pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: der.Int(1)}, nil},
		{"unknown critical extension", pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: der.Int(1)}, pki.ErrUnsupported},
		{"cutoff invalid DER", pkix.Extension{Id: cutoff, Value: []byte{0x18, 1}}, pki.ErrEvidence},
		{"cutoff wrong time type", pkix.Extension{Id: cutoff, Value: der.Int(1)}, pki.ErrEvidence},
		{"cutoff invalid date", pkix.Extension{Id: cutoff, Value: der.Wrap(0, asn1.TagGeneralizedTime, false, []byte("20260230000000Z"))}, pki.ErrEvidence},
		{"single-response nonce forbidden", pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}, Value: der.Octets([]byte{1})}, pki.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := p7SingleExtension(t, base, c, tc.ext)
			result, report, err := pki.VerifyOCSP(t.Context(), raw, c.leaf.Raw, c.root.Raw, at, pki.OCSPOptions{})
			if tc.want != nil {
				// Verification reports retain diagnostics on failure.
				//noinspection GoDfaErrorMayBeNotNil
				if result != nil || !errors.Is(err, tc.want) || report.Signature != pki.NotChecked {
					t.Fatalf("single-response extension: %v, %+v, %v; want %v", result != nil, report, err, tc.want)
				}
			} else if result == nil || err != nil || report.Signature != pki.Valid || report.Status != pki.OCSPGood {
				t.Fatal("noncritical extension changed valid status", result != nil, report, err)
			}
		})
	}
}

func p7Response(t *testing.T, c chainData, template pki.OCSPResponseTemplate) []byte {
	t.Helper()
	request, err := pki.CreateOCSPRequest(c.leaf.Raw, c.root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pki.CreateOCSPResponse(t.Context(), request, c.leaf.Raw, c.root.Raw, c.root.Raw, c.rootKey, template)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func p7SingleExtension(t *testing.T, raw []byte, c chainData, extension pkix.Extension) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(extension)
	if err != nil {
		t.Fatal(err)
	}
	return rewriteOCSPData(t, raw, c.rootKey, func(fields []asn1.RawValue) [][]byte {
		responses, err := der.Sequence(fields[2], 1, 64)
		if err != nil {
			t.Fatal(err)
		}
		single, err := der.Sequence(responses[0], 3, 5)
		if err != nil {
			t.Fatal(err)
		}
		responses[0].FullBytes = der.Seq(append(ocspFieldBytes(single), der.Ctx(1, der.Seq(encoded)))...)
		fields[2].FullBytes = der.Seq(ocspFieldBytes(responses)...)
		return ocspFieldBytes(fields)
	})
}
