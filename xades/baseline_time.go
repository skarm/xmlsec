package xades

import (
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
)

// baselineUTC retains decimal precision and unbounded XML Schema 1.0 year
// values, within an explicit 4096-byte lexical resource bound. Years are stored
// in astronomical numbering internally; XML Schema 1.0 has no lexical year zero.
type baselineUTC struct {
	year     big.Int
	month    int
	day      int
	hour     int
	minute   int
	second   int
	fraction string
}

func (value *baselineUTC) monthDays() int {
	switch value.month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		var mod big.Int
		if mod.Mod(&value.year, big.NewInt(400)).Sign() == 0 || mod.Mod(&value.year, big.NewInt(100)).Sign() != 0 && mod.Mod(&value.year, big.NewInt(4)).Sign() == 0 {
			return 29
		}

		return 28
	default:
		return 31
	}
}

func (value *baselineUTC) convenienceTime() time.Time {
	if !value.year.IsInt64() || value.year.Int64() < 1 || value.year.Int64() > 9999 || len(value.fraction) > 9 {
		return time.Time{}
	}

	fraction := value.fraction + strings.Repeat("0", 9-len(value.fraction))
	nanos, _ := strconv.Atoi(fraction)

	return time.Date(int(value.year.Int64()), time.Month(value.month), value.day, value.hour, value.minute, value.second, nanos, time.UTC)
}

func (value *baselineUTC) normalizeMidnight() error {
	if value.hour == 24 {
		if value.minute != 0 || value.second != 0 || value.fraction != "" {
			return ErrProfile
		}

		value.hour = 0

		value.day++
		if value.day > value.monthDays() {
			value.day = 1

			value.month++
			if value.month == 13 {
				value.month = 1
				value.year.Add(&value.year, big.NewInt(1))
			}
		}
	}

	return nil
}

func parseBaselineTime(element document.Element) (string, time.Time, error) {
	value, err := simple(element)
	if err != nil {
		return "", time.Time{}, err
	}

	value = strings.Trim(value, " \t\r\n")

	parsed, err := parseBaselineUTC(value)
	if err != nil {
		return "", time.Time{}, err
	}

	return value, parsed.convenienceTime(), nil
}

func parseBaselineUTC(value string) (baselineUTC, error) {
	var out baselineUTC
	if len(value) > 4096 {
		return out, ErrProfile
	}

	if strings.HasSuffix(value, "+00:00") || strings.HasSuffix(value, "-00:00") {
		value = value[:len(value)-6] + "Z"
	}

	if len(value) < 20 || len(value) > 4096 || !strings.HasSuffix(value, "Z") {
		return out, ErrProfile
	}

	yearEnd, err := baselineTimeYear(value, &out.year)
	if err != nil {
		return out, err
	}

	tail := value[yearEnd:]
	if len(tail) < 16 || tail[0] != '-' || tail[3] != '-' || tail[6] != 'T' || tail[9] != ':' || tail[12] != ':' {
		return out, ErrProfile
	}

	fields := []*int{&out.month, &out.day, &out.hour, &out.minute, &out.second}

	for i, start := range []int{1, 4, 7, 10, 13} {
		part := tail[start : start+2]
		if !baselineDigits(part) {
			return out, ErrProfile
		}

		*fields[i] = int(part[0]-'0')*10 + int(part[1]-'0')
	}

	if len(tail) > 16 {
		if tail[15] != '.' || len(tail) < 18 || !baselineDigits(tail[16:len(tail)-1]) {
			return out, ErrProfile
		}

		out.fraction = strings.TrimRight(tail[16:len(tail)-1], "0")
	}

	if out.month < 1 || out.month > 12 || out.day < 1 || out.day > out.monthDays() || out.hour > 24 || out.minute > 59 || out.second > 59 {
		return out, ErrProfile
	}

	if err := out.normalizeMidnight(); err != nil {
		return out, err
	}

	return out, nil
}

func baselineDigits(value string) bool {
	if value == "" {
		return false
	}

	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

// SigningTimeLexical returns the complete authenticated UTC xs:dateTime claim,
// retaining arbitrary year and fractional-second precision. It is not a PoE.
func (r *BaselineResult) SigningTimeLexical() string {
	if r == nil {
		return ""
	}

	return r.signingTime
}

// CompareSigningTime compares the exact authenticated claim with other in UTC.
// It returns -1, 0 or 1. No floating point or nanosecond truncation is used.
func (r *BaselineResult) CompareSigningTime(other time.Time) (int, error) {
	if r == nil || r.signingTime == "" {
		return 0, ErrProfile
	}

	value, err := parseBaselineUTC(r.signingTime)
	if err != nil {
		return 0, err
	}

	other = other.UTC()

	var year big.Int
	year.SetInt64(int64(other.Year()))

	if cmp := value.year.Cmp(&year); cmp != 0 {
		return cmp, nil
	}

	left := []int{value.month, value.day, value.hour, value.minute, value.second}

	right := []int{int(other.Month()), other.Day(), other.Hour(), other.Minute(), other.Second()}
	for i, v := range left {
		if v < right[i] {
			return -1, nil
		}

		if v > right[i] {
			return 1, nil
		}
	}

	fraction := strconv.Itoa(other.Nanosecond() + 1_000_000_000)[1:]
	for i := range max(len(fraction), len(value.fraction)) {
		a, b := byte('0'), byte('0')
		if i < len(value.fraction) {
			a = value.fraction[i]
		}

		if i < len(fraction) {
			b = fraction[i]
		}

		if a < b {
			return -1, nil
		}

		if a > b {
			return 1, nil
		}
	}

	return 0, nil
}

func baselineTimeYear(value string, yearValue *big.Int) (int, error) {
	yearEnd := strings.IndexByte(value, '-')
	if yearEnd == 0 {
		next := strings.IndexByte(value[1:], '-')
		if next < 0 {
			return 0, ErrProfile
		}

		yearEnd = next + 1
	}

	if yearEnd < 4 {
		return 0, ErrProfile
	}

	year := value[:yearEnd]

	digits := year
	if digits[0] == '-' {
		digits = digits[1:]
	}

	if len(digits) < 4 || len(digits) > 4 && digits[0] == '0' || !baselineDigits(digits) {
		return 0, ErrProfile
	}

	if _, ok := yearValue.SetString(year, 10); !ok || yearValue.Sign() == 0 {
		return 0, ErrProfile
	}

	if yearValue.Sign() < 0 {
		yearValue.Add(yearValue, big.NewInt(1))
	}

	return yearEnd, nil
}
