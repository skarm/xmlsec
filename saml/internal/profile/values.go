package profile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/internal/xmltime"
)

// ErrSchema reports unsupported or invalid SAML structure or values.
var ErrSchema = errors.New("unsupported or invalid SAML structure")

// NewID generates an unpredictable SAML ID using crypto/rand.
func NewID() (string, error) {
	var b [20]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}

	return "_" + hex.EncodeToString(b[:]), nil
}

// ParseTime parses SAML UTC dateTime values with four-digit positive years and
// at most nine fractional digits. XML Schema permits 24:00:00 for midnight.
func ParseTime(s string) (time.Time, error) {
	t, err := xmltime.ParseUTC(s)
	if err != nil {
		return time.Time{}, ErrSchema
	}

	return t, nil
}

// Time formats a SAML timestamp in UTC.
func Time(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ID reports whether s is an allowed SAML ID.
func ID(s string) bool { return len(s) > 0 && len(s) <= 256 && xmlchar.IsValidNCName(s) }

// URI reports whether s is a bounded absolute URI without XML whitespace.
func URI(s string) bool {
	if len(s) == 0 || len(s) > 2048 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}

	u, e := url.Parse(s)

	return e == nil && u.IsAbs()
}

// Endpoint checks a bounded absolute HTTPS endpoint, permitting HTTP only when requested.
func Endpoint(s string, allowHTTP bool) bool {
	u, e := url.Parse(s)
	return e == nil && len(s) <= 4096 && u.Host != "" && u.User == nil && u.Fragment == "" && u.Opaque == "" && (u.Scheme == "https" || (allowHTTP && u.Scheme == "http"))
}

// Bool parses an XML Schema boolean.
func Bool(s string) (bool, error) {
	switch s {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	}

	return false, ErrSchema
}

// Duration parses positive day/time XML Schema durations up to 365 days, with
// at most nine fractional second digits. Calendar years/months are unsupported.
func Duration(s string) (time.Duration, error) { // day/time subset; calendar years/months fail explicitly.
	if len(s) < 3 || len(s) > 64 || s[0] != 'P' {
		return 0, ErrSchema
	}

	s = s[1:]
	inTime := false
	seen := false
	last := 0

	var total time.Duration

	for s != "" {
		if s[0] == 'T' {
			if inTime {
				return 0, ErrSchema
			}

			inTime = true
			last = 1

			s = s[1:]
			if s == "" {
				return 0, ErrSchema
			}

			continue
		}

		i := durationNumberEnd(s)

		if i == 0 || i == len(s) {
			return 0, ErrSchema
		}

		kind := s[i]

		order, scale, valid := durationUnit(kind, inTime)
		if !valid {
			return 0, ErrSchema
		}

		if order <= last || kind != 'S' && strings.Contains(s[:i], ".") {
			return 0, ErrSchema
		}

		last = order

		amount, err := durationAmount(s[:i], scale)
		if err != nil || amount > 365*24*time.Hour-total {
			return 0, ErrSchema
		}

		total += amount
		seen = true
		s = s[i+1:]
	}

	if !seen || total <= 0 {
		return 0, ErrSchema
	}

	return total, nil
}

func durationAmount(s string, unit time.Duration) (time.Duration, error) {
	whole, fraction, hasFraction := strings.Cut(s, ".")
	if whole == "" || hasFraction && (unit != time.Second || len(fraction) == 0 || len(fraction) > 9) {
		return 0, ErrSchema
	}

	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || n < 0 || n > int64(365*24*time.Hour/unit) {
		return 0, ErrSchema
	}

	amount := time.Duration(n) * unit

	if hasFraction {
		nanos, err := strconv.ParseUint(fraction+strings.Repeat("0", 9-len(fraction)), 10, 32)
		if err != nil {
			return 0, ErrSchema
		}

		amount += time.Duration(nanos)
	}

	return amount, nil
}

func durationUnit(kind byte, inTime bool) (int, time.Duration, bool) {
	order := 0

	var scale time.Duration

	switch kind {
	case 'D':
		if inTime {
			return 0, 0, false
		}

		order = 1
		scale = 24 * time.Hour
	case 'H':
		if !inTime {
			return 0, 0, false
		}

		order = 2
		scale = time.Hour
	case 'M':
		if !inTime {
			return 0, 0, false
		}

		order = 3
		scale = time.Minute
	case 'S':
		if !inTime {
			return 0, 0, false
		}

		order = 4
		scale = time.Second
	default:
		return 0, 0, false
	}

	return order, scale, true
}

func durationNumberEnd(s string) int {
	i := 0
	for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
		i++
	}

	return i
}
