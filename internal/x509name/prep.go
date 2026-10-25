package x509name

import (
	"context"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/skarm/xmlsec/internal/normalization"
)

func uint32At(s string, i int) uint32 {
	return uint32(s[i])<<24 | uint32(s[i+1])<<16 | uint32(s[i+2])<<8 | uint32(s[i+3])
}

func inRanges(table string, r rune) bool {
	if r < 0 {
		return false
	}

	n := uint32(r) // #nosec G115 -- r is nonnegative and no greater than the Unicode scalar range.

	lo, hi := 0, len(table)/8
	for lo < hi {
		mid := lo + (hi-lo)/2

		start, end := uint32At(table, mid*8), uint32At(table, mid*8+4)
		if n < start {
			hi = mid
		} else if n > end {
			lo = mid + 1
		} else {
			return true
		}
	}

	return false
}

func caseFold32(r rune) string {
	if r < 0 {
		return ""
	}

	n := uint32(r) // #nosec G115 -- decoded UTF-8 rune, checked nonnegative.

	lo, hi := 0, len(foldKeys32)/7
	for lo < hi {
		mid := lo + (hi-lo)/2

		k := uint32At(foldKeys32, mid*7)
		if n < k {
			hi = mid
		} else if n > k {
			lo = mid + 1
		} else {
			at := mid * 7
			offset := int(foldKeys32[at+4])<<8 | int(foldKeys32[at+5])

			return foldValues32[offset : offset+int(foldKeys32[at+6])]
		}
	}

	return ""
}

func mappedNothing(r rune) bool { return inRanges(nothingMapped32, r) }
func mappedSpace(r rune) bool {
	return r >= 9 && r <= 0xd || r == 0x85 || r == 0x20 || r == 0xa0 || r == 0x1680 || r >= 0x2000 && r <= 0x200a || r >= 0x2028 && r <= 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000
}

func prepare(ctx context.Context, input string) (string, error) {
	// Normalization is stable for assigned Unicode3.2 characters except the five
	// Corrigendum4 changes below. Pin the reused table version for future review.
	if norm.Version != "17.0.0" {
		return "", ErrUnsupported
	}

	mapped, err := mapStoredValue(ctx, input)
	if err != nil {
		return "", err
	}

	normal, err := normalize32(ctx, mapped)
	if err != nil {
		return "", err
	}

	if len(normal) > maxKeyBytes {
		return "", ErrLimit
	}

	values := []rune(normal)
	for i, r := range values {
		if i&255 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}

		if inRanges(unassigned32, r) || inRanges(prohibited32, r) {
			return "", ErrInvalid
		}
	}
	// RFC4518 section2.5 deliberately ignores bidi; SASL StringPrep's RandAL
	// rejection would be a different profile. Section2.6.1 governs stored values.
	result := insignificantSpaces(values)
	if len(result) > maxKeyBytes {
		return "", ErrLimit
	}

	return result, ctx.Err()
}

// mapStoredValue applies RFC4518's Unicode3.2 mapping before normalization.
func mapStoredValue(ctx context.Context, input string) (string, error) {
	mapped := make([]byte, 0, len(input))

	steps := 0
	for _, r := range input {
		steps++
		if steps&255 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		// Printable ASCII is assigned in Unicode 3.2 and has no mappings
		// except case folding; space handling is applied to the final string.
		if r >= ' ' && r <= '~' {
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}

			mapped = utf8.AppendRune(mapped, r)
			if len(mapped) > maxKeyBytes {
				return "", ErrLimit
			}

			continue
		}
		// With Unicode3.2 normalization these stay unassigned through all steps.
		// Reject before using a later normalization table that could map them away.
		if inRanges(unassigned32, r) {
			return "", ErrInvalid
		}

		if mappedNothing(r) {
			continue
		}

		if mappedSpace(r) {
			mapped = append(mapped, ' ')
			continue
		}

		if fold := caseFold32(r); fold != "" {
			mapped = append(mapped, fold...)
		} else {
			mapped = utf8.AppendRune(mapped, r)
		}

		if len(mapped) > maxKeyBytes {
			return "", ErrLimit
		}
	}

	return string(mapped), nil
}

func normalize32(ctx context.Context, mapped string) (string, error) {
	corrected := strings.Map(func(r rune) rune {
		switch r {
		case 0x2f868:
			return 0x2136a
		case 0x2f874:
			return 0x5f33
		case 0x2f91f:
			return 0x43ab
		case 0x2f95f:
			return 0x7aae
		case 0x2f9bf:
			return 0x4d57
		}

		return r
	}, mapped)

	return normalization.String(ctx, normalization.NFKC, corrected)
}

func insignificantSpaces(values []rune) string {
	space := func(i int) bool {
		return values[i] == ' ' && (i+1 == len(values) || !inRanges(combining32, values[i+1]))
	}

	start, end := 0, len(values)
	for start < end && space(start) {
		start++
	}

	for end > start && space(end-1) {
		end--
	}

	if start == end {
		return "  "
	}

	var out strings.Builder
	out.Grow((end-start)*2 + 2)
	out.WriteByte(' ')

	for i := start; i < end; {
		if space(i) {
			out.WriteString("  ")

			for i < end && space(i) {
				i++
			}

			continue
		}

		out.WriteRune(values[i])
		i++
	}

	out.WriteByte(' ')

	return out.String()
}
