// Copyright (c) 2026 xmlsec contributors. MIT License.

package value

import (
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
)

// ValidLanguage checks the ASCII subtag grammar of xs:language directly.
func ValidLanguage(s string) bool {
	first := true

	for part := range strings.SplitSeq(s, "-") {
		if len(part) < 1 || len(part) > 8 {
			return false
		}

		for i := range len(part) {
			c := part[i]
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || !first && c >= '0' && c <= '9' {
				continue
			}

			return false
		}

		first = false
	}

	return !first
}

func digits(s string) bool {
	if s == "" {
		return false
	}

	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}

func unsigned(s string) string {
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		return s[1:]
	}

	return s
}

func decimalLexical(s string) bool {
	s = unsigned(s)

	whole, fraction, dot := strings.Cut(s, ".")
	if !dot {
		return digits(whole)
	}

	return (whole == "" || digits(whole)) && (fraction == "" || digits(fraction)) && (whole != "" || fraction != "")
}

func floatLexical(s string, version Version) bool {
	if s == lexicon.FloatNaN || s == lexicon.FloatINF || s == lexicon.FloatNegINF || s == "+INF" && version == Version11 {
		return true
	}

	if at := strings.IndexAny(s, "eE"); at >= 0 {
		return decimalLexical(s[:at]) && digits(unsigned(s[at+1:]))
	}

	return decimalLexical(s)
}

func hexLexical(s string) bool {
	if len(s)%2 != 0 {
		return false
	}

	for i := range len(s) {
		if !isHexDigit(s[i]) {
			return false
		}
	}

	return true
}

func timezoneBody(s string, required bool) (string, bool) {
	if strings.HasSuffix(s, "Z") {
		return s[:len(s)-1], true
	}

	if len(s) >= 6 {
		at := len(s) - 6
		if (s[at] == '+' || s[at] == '-') && s[at+3] == ':' {
			if !digits(s[at+1:at+3]) || !digits(s[at+4:]) {
				return "", false
			}

			return s[:at], true
		}
	}

	return s, !required
}

func yearLexical(s string) bool {
	s = strings.TrimPrefix(s, "-")
	return len(s) >= 4 && digits(s) && (len(s) == 4 || s[0] != '0')
}

func dateBody(s string) bool {
	if len(s) < 10 {
		return false
	}

	at := len(s) - 6

	return s[at] == '-' && s[at+3] == '-' && yearLexical(s[:at]) && digits(s[at+1:at+3]) && digits(s[at+4:])
}

func timeBody(s string) bool {
	if len(s) < 8 || s[2] != ':' || s[5] != ':' || !digits(s[:2]) || !digits(s[3:5]) || !digits(s[6:8]) {
		return false
	}

	return len(s) == 8 || s[8] == '.' && digits(s[9:])
}

func calendarLexical(s, kind string, requiredZone bool) bool {
	body, ok := timezoneBody(s, requiredZone)
	if !ok {
		return false
	}

	switch kind {
	case lexicon.TypeDate:
		return dateBody(body)
	case lexicon.TypeTime:
		return timeBody(body)
	case lexicon.TypeDateTime:
		d, t, found := strings.Cut(body, "T")
		return found && dateBody(d) && timeBody(t)
	case lexicon.TypeGYear:
		return yearLexical(body)
	case lexicon.TypeGYearMonth:
		return len(body) >= 7 && body[len(body)-3] == '-' && yearLexical(body[:len(body)-3]) && digits(body[len(body)-2:])
	case lexicon.TypeGMonth:
		return len(body) == 4 && strings.HasPrefix(body, "--") && digits(body[2:])
	case lexicon.TypeGDay:
		return len(body) == 5 && strings.HasPrefix(body, "---") && digits(body[3:])
	case lexicon.TypeGMonthDay:
		return len(body) == 7 && strings.HasPrefix(body, "--") && body[4] == '-' && digits(body[2:4]) && digits(body[5:])
	}

	return false
}

func durationLexical(s, kind string) bool {
	s = strings.TrimPrefix(s, "-")
	if !strings.HasPrefix(s, "P") {
		return false
	}

	s = s[1:]
	dateOrder, timeOrder, components := 0, 0, 0
	inTime, timeComponent := false, false

	for len(s) > 0 {
		if s[0] == 'T' {
			if inTime || kind == "yearMonthDuration" {
				return false
			}

			inTime = true
			s = s[1:]

			continue
		}

		at, fraction, valid := scanDurationComponent(s)
		if !valid {
			return false
		}

		unit := s[at]
		if inTime {
			order, valid := durationTimeOrder(unit, fraction, timeOrder)
			if !valid {
				return false
			}

			timeOrder = order
			timeComponent = true
		} else {
			order, valid := durationDateOrder(unit, fraction, kind, dateOrder)
			if !valid {
				return false
			}

			dateOrder = order
		}

		components++
		s = s[at+1:]
	}

	return components > 0 && (!inTime || timeComponent)
}

func base64Characters(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("+/= \t\r\n", rune(c)) {
			continue
		}

		return false
	}

	return true
}

func scanDurationComponent(s string) (int, bool, bool) {
	at := 0
	for at < len(s) && s[at] >= '0' && s[at] <= '9' {
		at++
	}

	if at == 0 {
		return 0, false, false
	}

	fraction := false
	if at < len(s) && s[at] == '.' {
		fraction = true
		at++

		start := at
		for at < len(s) && s[at] >= '0' && s[at] <= '9' {
			at++
		}

		if at == start {
			return 0, false, false
		}
	}

	if at == len(s) {
		return 0, false, false
	}

	return at, fraction, true
}

func durationTimeOrder(unit byte, fraction bool, previous int) (int, bool) {
	order := strings.IndexByte("HMS", unit) + 1
	return order, order > previous && (!fraction || unit == 'S')
}

func durationDateOrder(unit byte, fraction bool, kind string, previous int) (int, bool) {
	order := strings.IndexByte("YMD", unit) + 1
	return order, !(order <= previous || fraction || kind == "dayTimeDuration" && unit != 'D' || kind == "yearMonthDuration" && unit == 'D')
}
