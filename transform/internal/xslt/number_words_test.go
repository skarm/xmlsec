package xslt //nolint:testpackage // Exercises language-specific spelling directly.

import (
	"math"
	"testing"
)

func TestNumberToWordsLangCardinal(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		value    int64
		language string
		casing   string
		want     string
	}{
		{"english_fallback", 42, "xx", "lower", "forty two"},
		{"english_title_case", 121, "en", "title", "One Hundred And Twenty One"},
		{"german_zero", 0, "de", "lower", "null"},
		{"german_negative", -2, "de", "lower", "minus zwei"},
		{"german_unit_before_tens", 21, "DE_de", "lower", "einundzwanzig"},
		{"german_uppercase_sharp_s", 30, "de-DE", "upper", "DREISSIG"},
		{"german_exact_hundred", 100, "de", "lower", "einhundert"},
		{"german_hundreds_and_units", 302, "de", "lower", "dreihundertzwei"},
		{"german_exact_thousand", 1000, "de", "lower", "eintausend"},
		{"german_thousands_and_remainder", 2042, "de", "lower", "zweitausendzweiundvierzig"},
		{"german_million_and_units", 1000002, "de", "lower", "eine Million zwei"},
		{"german_millions_and_units", 2000002, "de", "lower", "zwei Millionen zwei"},
		{"german_large_number_fallback", 1000000000, "de", "lower", "1000000000"},
		{"italian_zero", 0, "it", "lower", "zero"},
		{"italian_negative", -2, "it", "lower", "meno due"},
		{"italian_exact_tens", 20, "it", "lower", "venti"},
		{"italian_tens_elide_before_one", 21, "IT-IT", "lower", "ventuno"},
		{"italian_tens_elide_before_eight", 28, "it", "lower", "ventotto"},
		{"italian_tens_keep_vowel_before_two", 22, "it", "lower", "ventidue"},
		{"italian_exact_hundred", 100, "it", "lower", "cento"},
		{"italian_hundreds_and_units", 202, "it", "lower", "duecentodue"},
		{"italian_exact_thousand", 1000, "it", "lower", "mille"},
		{"italian_thousands_and_units", 2002, "it", "lower", "duemiladue"},
		{"italian_large_number_fallback", 1000000, "it", "lower", "1000000"},
		{"french_title_case_accent", 0, "fr", "title", "Zéro"},
		{"french_negative", -2, "fr", "lower", "moins deux"},
		{"french_exact_tens", 60, "fr", "lower", "soixante"},
		{"french_tens_and_one", 61, "fr", "lower", "soixante et un"},
		{"french_seventies", 71, "fr-FR", "lower", "soixante et onze"},
		{"french_exact_eighty", 80, "fr", "lower", "quatre-vingts"},
		{"french_eighty_one_has_no_conjunction", 81, "fr", "lower", "quatre-vingt-un"},
		{"french_nineties", 91, "fr", "lower", "quatre-vingt-onze"},
		{"french_exact_hundred", 100, "fr", "lower", "cent"},
		{"french_exact_hundreds_are_plural", 200, "fr", "lower", "deux cents"},
		{"french_hundreds_with_remainder_are_singular", 202, "fr", "lower", "deux cent deux"},
		{"french_exact_thousand", 1000, "fr", "lower", "mille"},
		{"french_thousands_and_units", 2002, "fr", "lower", "deux mille deux"},
		{"french_large_number_fallback", 1000000, "fr", "lower", "1000000"},
		{"german_minimum_integer", math.MinInt64, "de", "lower", "minus 9223372036854775808"},
		{"italian_minimum_integer", math.MinInt64, "it", "lower", "meno 9223372036854775808"},
		{"french_minimum_integer", math.MinInt64, "fr", "lower", "moins 9223372036854775808"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := numberToWordsLang(tc.value, tc.casing, tc.language, ""); got != tc.want {
				t.Errorf("cardinal %d (%s, %s) = %q, want %q", tc.value, tc.language, tc.casing, got, tc.want)
			}
		})
	}
}

func TestNumberToWordsLangOrdinal(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		value    int64
		language string
		hint     string
		want     string
	}{
		{"english_zero", 0, "en", "yes", "zeroth"},
		{"english_negative", -1, "en", "yes", "minus first"},
		{"english_minimum_integer", math.MinInt64, "en", "yes", "minus 9223372036854775808th"},
		{"english_teens", 12, "en", "yes", "twelfth"},
		{"english_exact_tens", 20, "en", "yes", "twentieth"},
		{"english_tens_and_units", 21, "en", "yes", "twenty-first"},
		{"english_exact_hundred", 100, "en", "yes", "one hundredth"},
		{"english_hundred_and_unit", 103, "en", "yes", "one hundred and third"},
		{"english_exact_thousand", 1000, "en", "yes", "one thousandth"},
		{"english_thousand_and_unit", 1001, "en", "yes", "one thousand first"},
		{"english_exact_million", 1000000, "en", "yes", "one millionth"},
		{"english_million_and_unit", 1000002, "en", "yes", "one million second"},
		{"english_exact_billion", 1000000000, "en", "yes", "one billionth"},
		{"english_billion_and_unit", 1000000003, "en", "yes", "one billion third"},
		{"english_exact_trillion", 1000000000000, "en", "yes", "one trillionth"},
		{"english_trillion_and_unit", 1000000000008, "en", "yes", "one trillion eighth"},
		{"german_first_masculine", 1, "de", "-er", "erster"},
		{"german_third_neuter", 3, "de", "-es", "drittes"},
		{"german_seventh_inflected", 7, "de", "-en", "siebten"},
		{"german_eighth", 8, "de", "yes", "achte"},
		{"german_teen", 11, "de", "yes", "elfte"},
		{"german_twentieth", 20, "de", "yes", "zwanzigste"},
		{"german_exact_hundred", 100, "de", "yes", "einhundertste"},
		{"german_hundred_and_unit", 103, "de", "yes", "einhundertdritte"},
		{"german_exact_thousands", 2000, "de", "yes", "zweitausendste"},
		{"german_thousand_and_unit", 1001, "de", "yes", "eintausenderste"},
		{"german_nonpositive", 0, "de", "yes", "null"},
		{"italian_first_masculine", 1, "it", "yes", "primo"},
		{"italian_first_feminine", 1, "it", "%spellout-ordinal-feminine", "prima"},
		{"italian_tenth_feminine", 10, "it", "%spellout-ordinal-feminine", "decima"},
		{"italian_eleven_masculine", 11, "it", "yes", "undicesimo"},
		{"italian_eleven_feminine", 11, "it", "%spellout-ordinal-feminine", "undicesima"},
		{"italian_nonpositive", 0, "it", "yes", "zero"},
		{"french_first", 1, "fr", "yes", "premier"},
		{"french_second", 2, "fr", "yes", "deuxième"},
		{"french_elides_final_e", 4, "fr", "yes", "quatrième"},
		{"french_nonpositive", 0, "fr", "yes", "zéro"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := numberToWordsLang(tc.value, "lower", tc.language, tc.hint); got != tc.want {
				t.Errorf("ordinal %d (%s, %s) = %q, want %q", tc.value, tc.language, tc.hint, got, tc.want)
			}
		})
	}
}
