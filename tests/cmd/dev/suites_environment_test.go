package main

import "testing"

func TestSuiteDependencyDistinguishesUnsupportedFromUnknown(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, kind, value string
		options           suiteOptions
		supported, known  bool
	}{
		{name: "year_zero_xsd10", kind: "year_component_values", value: "support year zero", known: true},
		{name: "year_zero_xsd11", kind: "year_component_values", value: "support year zero", options: suiteOptions{xsdVersion: "1.1"}, supported: true, known: true},
		{name: "negative_year", kind: "year_component_values", value: "support negative year", supported: true, known: true},
		{name: "unknown_year_dependency", kind: "year_component_values", value: "unspecified"},
		{name: "xslt_assertions_enabled", kind: "enable_assertions", value: "true", options: suiteOptions{xsltAssertions: true}, supported: true, known: true},
		{name: "xslt_assertions_disabled", kind: "enable_assertions", value: "true", known: true},
		{name: "known_unsupported_numbering", kind: "combinations_for_numbering", value: "GREEK SMALL LETTER ALPHA (TRADITIONAL)", known: true},
		{name: "known_supported_numbering", kind: "combinations_for_numbering", value: "GREEK SMALL LETTER ALPHA (ALPHABETIC)", supported: true, known: true},
		{name: "unknown_numbering", kind: "combinations_for_numbering", value: "not a catalog designation"},
		{name: "default_html_version", kind: "default_html_version", value: "5", supported: true, known: true},
		{name: "default_output_encoding", kind: "default_output_encoding", value: "UTF-8", supported: true, known: true},
		{name: "default_calendar", kind: "default_calendar_in_date_formatting_functions", value: "AD", supported: true, known: true},
		{name: "nondefault_calendar", kind: "default_calendar_in_date_formatting_functions", value: "ISO", known: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			supported, known := suiteDependency(tc.options, tc.kind, tc.value)
			if supported != tc.supported || known != tc.known {
				t.Errorf("suiteDependency(%q, %q) = (%t, %t), want (%t, %t)", tc.kind, tc.value, supported, known, tc.supported, tc.known)
			}
		})
	}
}

func TestSuiteLanguageMatchesExactVersionOrMinimum(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, suite, version, required string
		want                           bool
	}{
		{"exact_xpath_version", "qt3", "3.1", "XP31", true},
		{"different_exact_xpath_version", "qt3", "3.1", "XP30", false},
		{"xpath_minimum", "qt3", "3.1", "XP30+", true},
		{"below_xpath_minimum", "qt3", "2.0", "XP30+", false},
		{"xslt_alternative", "xslt30", "3.0", "XP30 XSLT20+", true},
		{"xslt_ignores_xpath_version", "xslt30", "3.0", "XP30 XSLT20", false},
		{"malformed_version", "qt3", "3.1", "XPthree+", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := suiteOptions{kind: tc.suite, version: tc.version}
			if got := suiteLanguageMatches(options, tc.required); got != tc.want {
				t.Errorf("suiteLanguageMatches(%s %s, %q) = %t, want %t", tc.suite, tc.version, tc.required, got, tc.want)
			}
		})
	}
}
