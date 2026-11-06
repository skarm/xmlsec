package profile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/internal/xmlchar"
	"github.com/skarm/xmlsec/internal/xmltime"
)

// Bound the supported positive day/time duration subset to 365 days; calendar years/months are rejected and fractions retain nanosecond precision.
const (
	maximumDuration = 365 * 24 * time.Hour
)

// HTTPRelayStateMaxBytes is the byte ceiling of opaque RelayState in HTTP bindings. ECP SOAP relay text has a separate, larger profile limit.
const (
	HTTPRelayStateMaxBytes = 80
)

// SAML unsigned index and day/time duration components use decimal lexical digits; hexadecimal prefixes and numeric separators are not enabled.
const (
	decimalRadix = 10
)

// ErrSchema reports unsupported or invalid SAML structure or values.
var ErrSchema = errors.New("unsupported or invalid SAML structure")

// NewID generates an unpredictable SAML ID using crypto/rand.
func NewID() (string, error) {
	const (
		identifierPrefix      = "_"
		identifierRandomBytes = 20
	)

	var b [identifierRandomBytes]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}

	return identifierPrefix + hex.EncodeToString(b[:]), nil
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
func ID(s string) bool {
	const (
		maximumIDBytes = 256
	)

	return len(s) > 0 && len(s) <= maximumIDBytes && xmlchar.IsValidNCName(s)
}

// URI reports whether s is a bounded absolute URI without XML whitespace.
func URI(s string) bool {
	const (
		maximumURIBytes = 2048
	)

	if len(s) == 0 || len(s) > maximumURIBytes || strings.ContainsAny(s, lexicon.XMLWhitespace) {
		return false
	}

	u, e := url.Parse(s)

	return e == nil && u.IsAbs()
}

// Endpoint checks a bounded absolute HTTPS endpoint, permitting HTTP only when requested.
func Endpoint(s string, allowHTTP bool) bool {
	const (
		maximumEndpointBytes = 4096
	)

	u, e := url.Parse(s)

	return e == nil && len(s) <= maximumEndpointBytes && u.Host != "" && u.User == nil && u.Fragment == "" && u.Opaque == "" && (u.Scheme == lexicon.SchemeHTTPS || (allowHTTP && u.Scheme == lexicon.SchemeHTTP))
}

// Bool parses an XML Schema boolean.
func Bool(s string) (bool, error) {
	const (
		xmlBooleanFalseDigit = "0"
		xmlBooleanTrueDigit  = "1"
	)

	switch strings.Trim(s, lexicon.XMLWhitespace) {
	case lexicon.ValueFalse, xmlBooleanFalseDigit:
		return false, nil
	case lexicon.ValueTrue, xmlBooleanTrueDigit:
		return true, nil
	}

	return false, ErrSchema
}

// Index parses the XSD 1.0 xs:unsignedShort endpoint index used by SAML.
// Its lexical space contains decimal digits with XML whitespace collapsed.
func Index(s string) (uint16, error) {
	const (
		indexBitSize = 16
	)

	n, err := strconv.ParseUint(strings.Trim(s, lexicon.XMLWhitespace), decimalRadix, indexBitSize)
	if err != nil {
		return 0, ErrSchema
	}

	return uint16(n), nil
}

// Duration parses positive day/time XML Schema durations up to 365 days, with
// at most nine fractional second digits. Calendar years/months are unsupported.
func Duration(s string) (time.Duration, error) {
	const (
		maximumDurationLexicalBytes = 64
		minimumDurationLexicalBytes = 3
	)

	// day/time subset; calendar years/months fail explicitly.
	if len(s) < minimumDurationLexicalBytes || len(s) > maximumDurationLexicalBytes || s[0] != 'P' {
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
		if err != nil || amount > maximumDuration-total {
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
	const (
		durationFractionBitSize = 32
		durationFractionDigits  = 9
		durationWholeBitSize    = 64
	)

	whole, fraction, hasFraction := strings.Cut(s, ".")
	if whole == "" || hasFraction && (unit != time.Second || len(fraction) == 0 || len(fraction) > durationFractionDigits) {
		return 0, ErrSchema
	}

	n, err := strconv.ParseInt(whole, decimalRadix, durationWholeBitSize)
	if err != nil || n < 0 || n > int64(maximumDuration/unit) {
		return 0, ErrSchema
	}

	amount := time.Duration(n) * unit

	if hasFraction {
		nanos, err := strconv.ParseUint(fraction+strings.Repeat("0", durationFractionDigits-len(fraction)), decimalRadix, durationFractionBitSize)
		if err != nil {
			return 0, ErrSchema
		}

		amount += time.Duration(nanos)
	}

	return amount, nil
}

func durationUnit(kind byte, inTime bool) (int, time.Duration, bool) {
	const (
		durationDay         = 24 * time.Hour
		durationDayOrder    = 1
		durationHourOrder   = 2
		durationMinuteOrder = 3
		durationSecondOrder = 4
	)

	order := 0

	var scale time.Duration

	switch kind {
	case 'D':
		if inTime {
			return 0, 0, false
		}

		order = durationDayOrder
		scale = durationDay
	case 'H':
		if !inTime {
			return 0, 0, false
		}

		order = durationHourOrder
		scale = time.Hour
	case 'M':
		if !inTime {
			return 0, 0, false
		}

		order = durationMinuteOrder
		scale = time.Minute
	case 'S':
		if !inTime {
			return 0, 0, false
		}

		order = durationSecondOrder
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
