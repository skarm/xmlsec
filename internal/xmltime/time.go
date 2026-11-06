// Package xmltime parses the bounded XML Schema dateTime profile shared by
// SAML and XAdES. It does not supply a trusted clock.
package xmltime

import (
	"errors"
	"strings"
	"time"
)

const (
	hoursPerDay                  = 24
	maximumDateTimeBytes         = 30
	maximumYear                  = 9999
	minimumDateTimeBytes         = 20
	minimumFractionDateTimeBytes = minimumDateTimeBytes + 2
)

// Positions in the fixed four-digit-year lexical profile, before the final Z.
// A fractional part starts at the byte immediately following the seconds.
const (
	dateTimeLayout      = "2006-01-02T15:04:05"
	clockEndOffset      = len(dateTimeLayout)
	fractionStartOffset = clockEndOffset + 1
)

// ErrFormat reports an invalid or unsupported XML Schema dateTime value.
var ErrFormat = errors.New("invalid or unsupported UTC XML Schema dateTime")

// ParseUTC accepts UTC dateTime values with four-digit positive years and at
// most nine fractional digits. XML Schema permits 24:00:00 for midnight, but
// does not permit the comma or single-digit hour accepted by time.Parse.
func ParseUTC(s string) (time.Time, error) {
	const (
		hourStartOffset   = 11
		hourDigits        = 2
		minuteStartOffset = 14
		midnightHour      = "24"
		zeroHour          = "00"
		zeroClock         = "00:00"
		zeroFractionChars = ".0"
	)

	if !validLexical(s) {
		return time.Time{}, ErrFormat
	}

	nextDay := s[hourStartOffset:hourStartOffset+hourDigits] == midnightHour
	if nextDay {
		if s[minuteStartOffset:clockEndOffset] != zeroClock || strings.Trim(s[clockEndOffset:len(s)-1], zeroFractionChars) != "" {
			return time.Time{}, ErrFormat
		}

		s = s[:hourStartOffset] + zeroHour + s[hourStartOffset+hourDigits:]
	}

	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 1 {
		return time.Time{}, ErrFormat
	}

	if nextDay {
		t = t.Add(hoursPerDay * time.Hour)
		if t.Year() > maximumYear {
			return time.Time{}, ErrFormat
		}
	}

	return t, nil
}

func validLexical(s string) bool {
	if len(s) < minimumDateTimeBytes || len(s) > maximumDateTimeBytes || s[len(s)-1] != 'Z' {
		return false
	}

	for i := range len(dateTimeLayout) {
		c := dateTimeLayout[i]
		if c >= '0' && c <= '9' {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		} else if s[i] != c {
			return false
		}
	}

	if len(s) == minimumDateTimeBytes {
		return true
	}

	if len(s) < minimumFractionDateTimeBytes || s[clockEndOffset] != '.' {
		return false
	}

	for i := fractionStartOffset; i < len(s)-1; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
