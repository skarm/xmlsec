package xades //nolint:testpackage // Exercises signed-property parsing before the signature profile consumes its results.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestParseBaselineDigestChecksShapeAlgorithmAndLength(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte("signed property"))
	encoded := base64.StdEncoding.EncodeToString(sum[:])
	method := `<ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `"/>`
	value := `<ds:DigestValue>` + encoded + `</ds:DigestValue>`
	for _, tc := range []struct {
		name, attrs, children string
		wantErr               error
	}{
		{"sha256", "", method + value, nil},
		{"xml_whitespace_in_digest", "", method + "<ds:DigestValue>\n" + encoded[:12] + "\t" + encoded[12:] + "</ds:DigestValue>", nil},
		{"unexpected_container_attribute", ` extra="true"`, method + value, ErrProfile},
		{"missing_value", "", method, ErrProfile},
		{"nonempty_method", "", `<ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `">text</ds:DigestMethod>` + value, ErrProfile},
		{"unsupported_algorithm", "", `<ds:DigestMethod Algorithm="urn:unrecognized"/>` + value, ErrProfile},
		{"unexpected_value_attribute", "", method + `<ds:DigestValue extra="true">` + encoded + "</ds:DigestValue>", ErrProfile},
		{"short_digest", "", method + "<ds:DigestValue>AQI=</ds:DigestValue>", ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := `<CertDigest xmlns="` + Namespace + `" xmlns:ds="` + xmldsig.Namespace + `"` + tc.attrs + ">" + tc.children + "</CertDigest>"
			doc, err := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			gotMethod, gotSum, err := parseBaselineDigest(t.Context(), doc.Root(), BaselineVerifyOptions{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("parseBaselineDigest = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				if gotMethod != "" || gotSum != nil {
					t.Errorf("rejected digest leaked method %q or digest %x", gotMethod, gotSum)
				}
			} else if gotMethod != xmldsig.SHA256 || !bytes.Equal(gotSum, sum[:]) {
				t.Errorf("parsed digest = %q %x, want SHA-256 %x", gotMethod, gotSum, sum)
			}
		})
	}
}

func TestCheckBaselineIssuerSerialRequiresDirectoryNameAndPositiveSerial(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	issuer, err := baselineIssuerSerial(chain.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBaselineIssuerSerial(issuer); err != nil {
		t.Fatalf("valid certificate issuer and serial: %v", err)
	}
	var actual struct {
		Names  []asn1.RawValue
		Serial *big.Int
	}
	rest, err := asn1.Unmarshal(issuer, &actual)
	if err != nil || len(rest) != 0 || len(actual.Names) != 1 || actual.Serial == nil {
		t.Fatalf("issuer-serial DER does not hold one GeneralName and serial: %v", err)
	}
	dir := actual.Names[0]
	if dir.Class != asn1.ClassContextSpecific || dir.Tag != 4 || !dir.IsCompound || !bytes.Equal(dir.Bytes, chain.Leaf.RawIssuer) || actual.Serial.Cmp(chain.Leaf.SerialNumber) != 0 {
		t.Errorf("issuer-serial DER did not preserve certificate issuer and serial")
	}

	validNames := der.Seq(dir.FullBytes)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"truncated_der", []byte{0x30, 0x02, 0x30}},
		{"missing_serial", der.Seq(validNames)},
		{"empty_general_names", der.Seq(der.Seq(), der.Int(1))},
		{"dns_name_instead_of_directory", der.Seq(der.Seq(der.Wrap(asn1.ClassContextSpecific, 2, false, []byte("example.test"))), der.Int(1))},
		{"directory_name_holds_non_sequence", der.Seq(der.Seq(der.Ctx(4, der.Int(1))), der.Int(1))},
		{"zero_serial", der.Seq(validNames, der.Int(0))},
		{"negative_serial", der.Seq(validNames, der.Int(-1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := checkBaselineIssuerSerial(tc.raw); !errors.Is(err, ErrProfile) {
				t.Errorf("checkBaselineIssuerSerial = %v, want %v", err, ErrProfile)
			}
		})
	}
}

func TestParseProductionPlaceKeepsFieldOrder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body string
		want       *ProductionPlace
	}{
		{"optional_fields_omitted", "<City>Perm</City><PostalCode>614000</PostalCode><CountryName>RU</CountryName>", &ProductionPlace{City: "Perm", PostalCode: "614000", CountryName: "RU"}},
		{"empty_place", "", nil},
		{"city_after_country", "<CountryName>RU</CountryName><City>Perm</City>", nil},
		{"duplicate_city", "<City>Perm</City><City>Kazan</City>", nil},
		{"unexpected_field", "<Province>Perm</Province>", nil},
		{"nontext_city", "<City><Other>Perm</Other></City>", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := document.Parse(t.Context(), []byte(`<SignatureProductionPlaceV2 xmlns="`+Namespace+`">`+tc.body+"</SignatureProductionPlaceV2>"), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseProductionPlace(doc.Root())
			if tc.want == nil {
				if got != nil || !errors.Is(err, ErrProfile) {
					t.Errorf("parseProductionPlace = (%+v, %v), want no value and %v", got, err, ErrProfile)
				}
				return
			}
			if err != nil || got == nil || *got != *tc.want {
				t.Errorf("parseProductionPlace = (%+v, %v), want %+v", got, err, tc.want)
			}
		})
	}
}

func TestBaselineSigningTimeTextPreservesExplicitPrecision(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, lexical, want string
		time                time.Time
		wantErr             error
	}{
		{"explicit_fraction", "2026-01-02T10:11:12.123456789123Z", "2026-01-02T10:11:12.123456789123Z", time.Time{}, nil},
		{"structured_time_converts_to_utc", "", "2026-01-02T09:11:12.123Z", time.Date(2026, 1, 2, 10, 11, 12, 123_000_000, time.FixedZone("plus-one", 3600)), nil},
		{"ambiguous_inputs", "2026-01-02T10:11:12Z", "", testcert.Now(), ErrProfile},
		{"missing_inputs", "", "", time.Time{}, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := baselineSigningTimeText(BaselineProperties{SigningTimeLexical: tc.lexical, SigningTime: tc.time})
			if got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Errorf("baselineSigningTimeText = (%q, %v), want (%q, %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestBuildBaselineCertificateRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		id   CertificateIdentifier
		want error
	}{
		{"canceled", ctx, CertificateIdentifier{DER: chain.Leaf.Raw}, context.Canceled},
		{"malformed_der", t.Context(), CertificateIdentifier{DER: []byte{0x30, 0x00}}, ErrCertificate},
		{"unsupported_digest_method", t.Context(), CertificateIdentifier{DER: chain.Leaf.Raw, DigestMethod: "urn:unrecognized"}, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := buildBaselineCertificate(tc.ctx, tc.id, BaselineVerifyOptions{})
			if got != nil || !errors.Is(err, tc.want) {
				t.Errorf("buildBaselineCertificate = (%v, %v), want no node and %v", got, err, tc.want)
			}
		})
	}
}
