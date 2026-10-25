package x509name

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
)

func testName(tag int, value string) []byte {
	return der.Seq(der.Set(der.Seq(der.OID(asn1.ObjectIdentifier{2, 5, 4, 3}), der.Wrap(0, tag, false, []byte(value)))))
}

func TestNamePreparationStructureAndFallback(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		equal      bool
	}{
		{"case fold and spaces", " Straße  ＡK ", "strasse ak", true},
		{"Unicode32 normalization correction", "\U0002f868", "\U0002136a", true},
		{"combining space remains significant", "a \u0308 b", "ä b", false},
		{"distinct values", "alice", "bob", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := testName(asn1.TagUTF8String, tc.a), testName(asn1.TagUTF8String, tc.b)
			beforeA, beforeB := bytes.Clone(a), bytes.Clone(b)
			same, err := Equal(t.Context(), a, b)
			if err != nil || same != tc.equal || !bytes.Equal(a, beforeA) || !bytes.Equal(b, beforeB) {
				t.Fatal("matching/ownership", same, err)
			}
		})
	}
	supported := testName(asn1.TagUTF8String, "foo bar  ")
	key, err := Key(t.Context(), supported)
	if err != nil || !strings.HasSuffix(key, " foo  bar ") {
		t.Fatal("RFC4518 stored space preparation", key, err)
	}
	optional := testName(asn1.TagT61String, "Alice")
	if same, err := Equal(t.Context(), optional, optional); same || !errors.Is(err, ErrUnsupported) {
		t.Fatal("optional semantic claim", same, err)
	}
	if same, err := EqualOrExact(t.Context(), optional, optional); !same || err != nil {
		t.Fatal("exact supported fallback", same, err)
	}
	malformed := append(bytes.Clone(optional), 0)
	if same, err := EqualOrExact(t.Context(), malformed, malformed); same || !errors.Is(err, ErrInvalid) {
		t.Fatal("fallback authenticated malformed name", same, err)
	}
	for _, raw := range [][]byte{nil, der.Seq(der.Set()), testName(asn1.TagUTF8String, "\ue000"), testName(asn1.TagUTF8String, "\u0221")} {
		if key, err := Key(t.Context(), raw); key != "" || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid/prohibited value accepted", key, err)
		}
	}
}

func TestNameCacheOwnershipControlErrorsAndBounds(t *testing.T) {
	raw := testName(asn1.TagUTF8String, "owned cache value")
	original := bytes.Clone(raw)
	expected, err := Key(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	clear(raw)
	if cached, hit := nameCacheGet(original); !hit || cached != expected {
		t.Fatal("cache did not retain its owned immutable source", cached, hit)
	}

	if got, err := Key(t.Context(), original); err != nil || got != expected {
		t.Fatal("cache retained a mutable source", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := Key(ctx, original); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("warm cache bypassed cancellation", got, err)
	}
	for i := range 100 {
		if _, err := Key(t.Context(), testName(asn1.TagUTF8String, "entry-count-bound "+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	nameCache.Lock()
	entries := 0
	for _, entry := range nameCache.entries {
		if entry.raw != "" {
			entries++
		}
	}
	nameCache.Unlock()
	if entries != 64 {
		t.Fatal("cache entry count cap changed", entries)
	}
	for i := range 100 {
		if _, err := Key(t.Context(), testName(asn1.TagUTF8String, strings.Repeat("A", 16<<10)+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	nameCache.Lock()
	retained, count, total := nameCache.bytes, 0, 0
	for _, entry := range nameCache.entries {
		if entry.raw != "" {
			count++
			total += len(entry.raw) + len(entry.key)
		}
	}
	nameCache.Unlock()
	if retained != total || retained > 1<<20 || count < 1 || count >= 64 {
		t.Fatal("cache count/byte eviction accounting", retained, total, count)
	}
	if key, err := Key(t.Context(), make([]byte, (64<<10)+1)); key != "" || !errors.Is(err, ErrLimit) {
		t.Fatal("name byte limit", key, err)
	}
}

func BenchmarkNameKey(b *testing.B) {
	for _, size := range []int{16, 4096, 32768} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			names := make([][]byte, 128)
			for i := range names {
				names[i] = testName(asn1.TagUTF8String, strings.Repeat("A", size)+strconv.Itoa(i))
			}
			for _, warm := range []bool{true, false} {
				b.Run(strconv.FormatBool(warm), func(b *testing.B) {
					if _, err := Key(b.Context(), names[0]); err != nil {
						b.Fatal(err)
					}
					index := 0
					b.ReportAllocs()
					for b.Loop() {
						raw := names[0]
						if !warm {
							raw = names[index%len(names)]
							index++
						}
						if _, err := Key(b.Context(), raw); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestPrintableASCIIPreparationMatchesStoredValueRules(t *testing.T) {
	var printable strings.Builder
	for r := ' '; r <= '~'; r++ {
		printable.WriteRune(r)
	}
	input := printable.String()
	expected := " " + strings.ToLower(strings.TrimSpace(input)) + " "
	got, err := prepare(t.Context(), input)
	if err != nil || got != expected {
		t.Fatal("printable ASCII mapping changed", got, expected, err)
	}
	for _, pair := range [][2]string{{"A\tB", " a  b "}, {"A\x00B", " ab "}, {"A\u0308", " ä "}, {"A \u0308 B", " a \u0308  b "}} {
		prepared, err := prepare(t.Context(), pair[0])
		if err != nil || prepared != pair[1] {
			t.Fatal("ASCII/Unicode boundary", pair[0], prepared, err)
		}
	}
	for _, pair := range [][2]string{{"", "  "}, {"   ", "  "}, {" A  B ", " a  b "}, {" \u0308A", "  \u0308a "}, {"A \u0308 ", " a \u0308 "}, {"A\u200bB", " ab "}} {
		prepared, err := prepare(t.Context(), pair[0])
		if err != nil || prepared != pair[1] {
			t.Fatal("stored whitespace/combining preparation", pair[0], prepared, err)
		}
	}
	for _, separator := range []rune{'\t', '\n', '\r', '\u0085', '\u00a0', '\u1680', '\u2009', '\u202f', '\u3000'} {
		prepared, err := prepare(t.Context(), "A"+string(separator)+"B")
		if err != nil || prepared != " a  b " {
			t.Fatal("XML/Unicode whitespace mapping", separator, prepared, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if prepared, err := prepare(ctx, strings.Repeat("ASCII", 1024)); prepared != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("ASCII mapping bypassed cancellation", prepared, err)
	}
	if _, err := prepare(t.Context(), strings.Repeat("A", maxKeyBytes+1)); !errors.Is(err, ErrLimit) {
		t.Fatal("ASCII path bypassed key budget", err)
	}
}

func BenchmarkNameKeyUnicode(b *testing.B) {
	names := make([][]byte, 128)
	for i := range names {
		names[i] = testName(asn1.TagUTF8String, strings.Repeat("Äß\u0301", 512)+strconv.Itoa(i))
	}
	index := 0
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Key(b.Context(), names[index%len(names)]); err != nil {
			b.Fatal(err)
		}
		index++
	}
}
