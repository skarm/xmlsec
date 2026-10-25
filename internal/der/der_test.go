package der_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
)

func TestDERHeaders(t *testing.T) {
	for _, size := range []int{0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 20} {
		payload := make([]byte, size)

		expected, err := asn1.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}

		encoded := append(der.Header(4, size), payload...)
		if !bytes.Equal(encoded, expected) {
			t.Fatal("DER length header", size)
		}
	}
}

func TestStrict(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		ok   bool
	}{{"integer", []byte{2, 1, 1}, true}, {"set", der.Set(der.Int(1), der.Int(2)), true}, {"indefinite", []byte{0x30, 0x80, 0, 0}, false}, {"trailing", []byte{2, 1, 1, 0}, false}, {"nonminimal length", []byte{4, 0x81, 1, 1}, false}, {"nonminimal integer", []byte{2, 2, 0, 1}, false}, {"bool", []byte{1, 1, 1}, false}, {"null", []byte{5, 1, 0}, false}, {"pad bits", []byte{3, 2, 1, 1}, false}, {"unsorted", []byte{0x31, 6, 2, 1, 2, 2, 1, 1}, false}, {"constructed octets", []byte{0x24, 0}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := der.Read(tc.b, 1024)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
		})
	}

	b := der.Int(1)
	for range 35 {
		b = der.Seq(b)
	}

	if _, e := der.Read(b, len(b)); e == nil {
		t.Fatal("depth")
	}
}

func TestReadExplicitBudgets(t *testing.T) {
	raw := der.Seq(der.Int(1), der.Seq(der.Int(2)))
	if _, err := der.ReadLimits(raw, len(raw), 3, 4); err != nil {
		t.Fatal(err)
	}

	for _, budget := range []struct {
		bytes int
		depth int
		nodes int
	}{{len(raw) - 1, 3, 4}, {len(raw), 2, 4}, {len(raw), 3, 3}} {
		if _, err := der.ReadLimits(raw, budget.bytes, budget.depth, budget.nodes); !errors.Is(err, der.ErrLimit) || !errors.Is(err, der.ErrInvalidDER) {
			t.Fatalf("budget %+v: %v", budget, err)
		}
	}

	value, err := der.Read(raw, len(raw))
	if err != nil {
		t.Fatal(err)
	}

	if partial, err := der.ChildrenLimit(value, 1); partial != nil || !errors.Is(err, der.ErrLimit) {
		t.Fatalf("bounded children exposed partial output: %v, %v", partial, err)
	}

	if children, err := der.Sequence(value, 2, 2); err != nil || len(children) != 2 {
		t.Fatalf("exact sequence bound: %v", err)
	}
}

func TestPrimitiveContents(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tag     int
		content string
		valid   bool
	}{
		{"UTF8", asn1.TagUTF8String, "Привет 世界 \U00010000", true},
		{"UTF8 invalid", asn1.TagUTF8String, "\xff", false},
		{"UTF8 overlong", asn1.TagUTF8String, "\xc0\x80", false},
		{"UTF8 surrogate", asn1.TagUTF8String, "\xed\xa0\x80", false},
		{"Printable repertoire", asn1.TagPrintableString, "Az09 '()+,-./:=?", true},
		{"Printable at", asn1.TagPrintableString, "@", false},
		{"Printable legacy star", asn1.TagPrintableString, "*", false},
		{"Printable legacy ampersand", asn1.TagPrintableString, "&", false},
		{"IA5", asn1.TagIA5String, "\x00\x7f", true},
		{"IA5 high bit", asn1.TagIA5String, "\x80", false},
		{"Numeric", asn1.TagNumericString, "0123456789 ", true},
		{"Numeric letter", asn1.TagNumericString, "1a", false},
		{"BMP", asn1.TagBMPString, "\x00A\x4e\x16\x00\x00", true},
		{"BMP odd", asn1.TagBMPString, "\x00", false},
		{"BMP surrogate", asn1.TagBMPString, "\xd8\x00", false},
		{"BMP surrogate pair", asn1.TagBMPString, "\xd8\x00\xdc\x00", false},
		{"BMP FFFE", asn1.TagBMPString, "\xff\xfe", false},
		{"BMP FFFF", asn1.TagBMPString, "\xff\xff", false},
		{"UTC", asn1.TagUTCTime, "261019010203Z", true},
		{"UTC leap day", asn1.TagUTCTime, "000229010203Z", true},
		{"UTC invalid day", asn1.TagUTCTime, "260229010203Z", false},
		{"UTC seconds missing", asn1.TagUTCTime, "2610190102Z", false},
		{"UTC offset", asn1.TagUTCTime, "261019010203+0000", false},
		{"UTC fraction", asn1.TagUTCTime, "261019010203.1Z", false},
		{"Generalized", asn1.TagGeneralizedTime, "20261019010203Z", true},
		{"Generalized fraction", asn1.TagGeneralizedTime, "20261019010203.123456789123Z", true},
		{"Generalized leap second", asn1.TagGeneralizedTime, "20161231235960Z", true},
		{"Generalized bad calendar", asn1.TagGeneralizedTime, "20260229010203Z", false},
		{"Generalized bad digit", asn1.TagGeneralizedTime, "2026101901a203Z", false},
		{"Generalized trailing zero", asn1.TagGeneralizedTime, "20261019010203.10Z", false},
		{"Generalized zero fraction", asn1.TagGeneralizedTime, "20261019010203.0Z", false},
		{"Generalized empty fraction", asn1.TagGeneralizedTime, "20261019010203.Z", false},
		{"Generalized comma", asn1.TagGeneralizedTime, "20261019010203,1Z", false},
		{"Generalized nondecimal fraction", asn1.TagGeneralizedTime, "20261019010203.aZ", false},
		{"Generalized midnight 24", asn1.TagGeneralizedTime, "20261019240000Z", false},
		{"Generalized offset", asn1.TagGeneralizedTime, "20261019010203+0000", false},
		{"Generalized seconds missing", asn1.TagGeneralizedTime, "202610190102Z", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := der.Wrap(0, tc.tag, false, []byte(tc.content))
			for _, input := range [][]byte{raw, der.Seq(raw)} {
				_, err := der.Read(input, len(input))
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%t: %x: %v", tc.valid, input, err)
				}
			}
		})
	}
}

func TestSetAndSetOfOrdering(t *testing.T) {
	// SET { nested SEQUENCE {}, text IA5String } is ordered by tag number,
	// irrespective of the constructed bit. SET OF CHOICE uses full encodings.
	for _, raw := range [][]byte{
		{0x31, 5, 0x30, 0, 0x16, 1, 'a'},
		{0x31, 5, 0x16, 1, 'a', 0x30, 0},
	} {
		value, err := der.Read(raw, len(raw))
		if err != nil {
			t.Fatalf("valid SET/SET OF: %x: %v", raw, err)
		}

		_, err = der.SetFields(value, 0, asn1.TagSet, 2)
		if (err == nil) != (raw[2] == 0x16) {
			t.Fatalf("schema-specific SET OF order: %x: %v", raw, err)
		}
	}

	raw := []byte{0x31, 8, 0x30, 0, 0x16, 1, 'a', 2, 1, 1}
	if _, err := der.Read(raw, len(raw)); !errors.Is(err, der.ErrInvalidDER) {
		t.Fatal("neither SET nor SET OF order accepted", err)
	}
}

func TestSequenceReaderBoundsAndEOF(t *testing.T) {
	raw := der.Seq(der.Int(1))
	first := true
	source := &sequenceReader{read: func(p []byte) (int, error) {
		if first {
			first = false
			return 0, nil
		}

		return 0, io.EOF
	}}

	encoded := io.MultiReader(bytes.NewReader(raw), source)
	if value, err := der.ReadSequence(t.Context(), encoded, len(raw)); err != nil || !bytes.Equal(value.FullBytes, raw) {
		t.Fatal(value, err)
	}

	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), {0x30, 0x80, 0, 0}, {0x30, 0x81, 1, 0}, {0x30, 0x82, 0x10, 0}, {0x30, 0x81, 0x80}} {
		if _, err := der.ReadSequence(t.Context(), bytes.NewReader(bad), 1024); err == nil {
			t.Fatal("invalid framing", bad)
		}
	}
	// A declared length beyond policy is rejected while reading the header.
	if _, err := der.ReadSequence(t.Context(), bytes.NewReader([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}), 1024); !errors.Is(err, der.ErrLimit) {
		t.Fatal(err)
	}
}

func FuzzSequenceReader(f *testing.F) {
	f.Add(der.Seq(der.Int(1)))
	f.Add([]byte{0x30, 0x82, 0x10, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}

		want, wantErr := der.Read(raw, 4096)
		got, err := der.ReadSequence(t.Context(), bytes.NewReader(raw), 4096)

		valid := wantErr == nil && want.Class == 0 && want.Tag == 16 && want.IsCompound
		if valid != (err == nil) || valid && !bytes.Equal(got.FullBytes, want.FullBytes) {
			t.Fatalf("framing mismatch: %x %v / %v", raw, wantErr, err)
		}
	})
}

func BenchmarkRead(b *testing.B) {
	raw := der.Seq(der.Int(1), der.Octets(make([]byte, 4096)))

	b.ReportAllocs()

	for b.Loop() {
		if _, err := der.Read(raw, len(raw)); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}

		_, _ = der.Read(b, 1<<20)
	})
}

func TestCompositionMatchesStandardEncoder(t *testing.T) {
	for _, size := range []int{0, 1, 126, 127, 128, 255, 256, 65535, 65536} {
		payload := bytes.Repeat([]byte{7}, size)

		for _, tag := range []int{4, 30, 31, 128, 16384} {
			for class := range 4 {
				for _, compound := range []bool{false, true} {
					want, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: payload})
					if err != nil {
						t.Fatal(err)
					}

					if got := der.Wrap(class, tag, compound, payload); !bytes.Equal(got, want) {
						t.Fatalf("class=%d tag=%d size=%d", class, tag, size)
					}
				}
			}
		}

		parts := [][]byte{der.Octets(payload), der.Int(1)}

		original := append([][]byte(nil), parts...)
		for _, tc := range []struct {
			class   int
			tag     int
			got     []byte
			content []byte
		}{
			{0, 16, der.Seq(parts...), bytes.Join(parts, nil)},
			{0, 17, der.Set(parts...), append(bytes.Clone(parts[1]), parts[0]...)},
			{2, 4, der.Ctx(4, parts...), bytes.Join(parts, nil)},
			{2, 128, der.Ctx(128, parts...), bytes.Join(parts, nil)},
		} {
			want, err := asn1.Marshal(asn1.RawValue{Class: tc.class, Tag: tc.tag, IsCompound: true, Bytes: tc.content})
			if err != nil || !bytes.Equal(tc.got, want) {
				t.Fatalf("class=%d tag=%d size=%d: %v", tc.class, tc.tag, size, err)
			}
		}

		if !bytes.Equal(parts[0], original[0]) || !bytes.Equal(parts[1], original[1]) {
			t.Fatal("SET sorting changed caller component order")
		}
	}
}

func TestCompositionWorkingStorage(t *testing.T) {
	part := der.Octets(bytes.Repeat([]byte{7}, 1<<20))
	for _, compose := range []func([]byte) []byte{
		func(part []byte) []byte { return der.Seq(der.Int(1), part) },
		func(part []byte) []byte { return der.Set(part, der.Int(1)) },
		func(part []byte) []byte { return der.Ctx(4, der.Int(1), part) },
		der.Octets,
	} {
		allocated := ^uint64(0)

		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			output := compose(part)

			runtime.ReadMemStats(&after)
			allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)

			if len(output) <= len(part) {
				t.Fatal("lost DER framing")
			}

			output[len(output)-1] = 0
			if part[len(part)-1] != 7 {
				t.Fatal("DER output aliases caller bytes")
			}
		}

		t.Logf("%d component bytes: %d allocated", len(part), allocated)

		if allocated > uint64(len(part))+64<<10 {
			t.Fatalf("composition copied complete intermediate content: %d bytes", allocated)
		}
	}
}

func FuzzComposition(f *testing.F) {
	f.Add([]byte{0, 1, 2}, []byte{3}, uint16(4))
	f.Add([]byte("large tag"), []byte{}, uint16(128))
	f.Fuzz(func(t *testing.T, first, second []byte, tag uint16) {
		if len(first)+len(second) > 64<<10 {
			t.Skip()
		}

		content := bytes.Join([][]byte{first, second}, nil)

		want, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: int(tag), IsCompound: true, Bytes: content})
		if err != nil || !bytes.Equal(der.Ctx(int(tag), first, second), want) {
			t.Fatal("DER composition differs from standard encoder", err)
		}
	})
}

type sequenceReader struct{ read func([]byte) (int, error) }

func (r *sequenceReader) Read(p []byte) (int, error) { return r.read(p) }

// The optimized validator retains encoding/asn1's exact existing OID profile,
// including its MaxInt32 subidentifier cap. It does not broaden ASN.1 support.
func TestObjectIdentifierStrictEquivalence(t *testing.T) {
	checkObjectIdentifier(t, nil)
	for first := range 256 {
		checkObjectIdentifier(t, []byte{byte(first)})
		for second := range 256 {
			checkObjectIdentifier(t, []byte{byte(first), byte(second)})
		}
	}
	for _, body := range [][]byte{
		{0x87, 0xff, 0xff, 0xff, 0x7f}, // MaxInt32 as the first subidentifier.
		{0x88, 0x80, 0x80, 0x80, 0x00}, // MaxInt32+1.
		{42, 0x87, 0xff, 0xff, 0xff, 0x7f},
		{42, 0x88, 0x80, 0x80, 0x80, 0x00},
		{42, 0x80, 0x00},
		{42, 0x81},
		{0x81, 0x80},
		{0x81, 0x80, 0x80, 0x80, 0x80, 0x00},
		{42, 0x81, 0x00, 0, 127, 0x81, 0x7f},
	} {
		checkObjectIdentifier(t, body)
	}
}

func FuzzObjectIdentifierStrictEquivalence(f *testing.F) {
	for _, body := range [][]byte{nil, {0}, {42, 0x86, 0x48}, {0x80, 0}, {0x81}, {0x87, 0xff, 0xff, 0xff, 0x7f}, {0x88, 0x80, 0x80, 0x80, 0}} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 4096 {
			t.Skip("bounded independent OID comparison")
		}
		checkObjectIdentifier(t, body)
	})
}

func checkObjectIdentifier(t testing.TB, body []byte) {
	t.Helper()
	raw := der.Wrap(0, asn1.TagOID, false, body)
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(raw, &oid)
	valid := err == nil && len(rest) == 0
	if valid {
		canonical, marshalErr := asn1.Marshal(oid)
		valid = marshalErr == nil && bytes.Equal(raw, canonical)
	}
	for _, input := range [][]byte{raw, der.Seq(raw)} {
		if _, err := der.Read(input, len(input)); (err == nil) != valid {
			t.Fatalf("OID %x: standard profile valid=%t, optimized=%v", body, valid, err)
		}
	}
}
