// Package xmltime parses the bounded XML Schema dateTime profile shared by
// SAML and XAdES. It does not supply a trusted clock.
package xmltime

import (
	"errors"
	"strings"
	"time"
)

// ErrFormat reports an invalid or unsupported XML Schema dateTime value.
var ErrFormat = errors.New("invalid or unsupported UTC XML Schema dateTime")

// ParseUTC accepts UTC dateTime values with four-digit positive years and at
// most nine fractional digits. XML Schema permits 24:00:00 for midnight, but
// does not permit the comma or single-digit hour accepted by time.Parse.
func ParseUTC(s string) (time.Time, error) {
	if !validLexical(s) {
		return time.Time{}, ErrFormat
	}

	nextDay := s[11:13] == "24"
	if nextDay {
		if s[14:19] != "00:00" || strings.Trim(s[19:len(s)-1], ".0") != "" {
			return time.Time{}, ErrFormat
		}

		s = s[:11] + "00" + s[13:]
	}

	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 1 {
		return time.Time{}, ErrFormat
	}

	if nextDay {
		t = t.Add(24 * time.Hour)
		if t.Year() > 9999 {
			return time.Time{}, ErrFormat
		}
	}

	return t, nil
}

func validLexical(s string) bool {
	if len(s) < 20 || len(s) > 30 || s[len(s)-1] != 'Z' {
		return false
	}

	const layout = "2006-01-02T15:04:05"
	for i := range len(layout) {
		c := layout[i]
		if c >= '0' && c <= '9' {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		} else if s[i] != c {
			return false
		}
	}

	if len(s) == 20 {
		return true
	}

	if len(s) < 22 || s[19] != '.' {
		return false
	}

	for i := 20; i < len(s)-1; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
