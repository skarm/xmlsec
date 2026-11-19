package main

import (
	"errors"
	"io"
	"path/filepath"
	"regexp/syntax"
	"strings"
	"testing"
	"time"
)

func TestParseSuiteOptionsKeepsExplicitProfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	wantDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	options, err := parseSuiteOptions([]string{
		"-dir", dir, "-suite=qt3", "-version=3.0", "-xsd-version=1.1",
		"-limits=language", "-xpath10-compatibility", "-sets=^functions$", "-match=^round-",
		"-limit=3", "-timeout=2s", "-current-time=2026-01-02T12:00:00.125+02:00",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseSuiteOptions: %v", err)
	}
	if options.directory != wantDir || options.kind != "qt3" || options.version != "3.0" || options.xsdVersion != "1.1" ||
		options.limitsProfile != "language" || !options.xpath10Compatibility || options.limit != 3 || options.timeout != 2*time.Second {
		t.Errorf("explicit suite settings were not retained: %+v", options)
	}
	wantTime := time.Date(2026, 1, 2, 10, 0, 0, 125_000_000, time.UTC)
	if options.currentTime != wantTime {
		t.Errorf("suite current time = %v, want %v in UTC", options.currentTime, wantTime)
	}
	if !options.setMatch.MatchString("functions") || options.setMatch.MatchString("other-functions") ||
		!options.caseMatch.MatchString("round-1") || options.caseMatch.MatchString("not-round-1") {
		t.Errorf("suite filters = (%q, %q), want exact set and case prefix", options.setMatch, options.caseMatch)
	}
}

func TestParseSuiteOptionsRejectsIncompatibleSettings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, tc := range []struct {
		name       string
		args       []string
		diagnostic string
	}{
		{"unknown_limit_profile", []string{"-limits=huge"}, "limits must be"},
		{"unknown_xsd_version", []string{"-xsd-version=1.2"}, "xsd-version must be"},
		{"xpath_compatibility_in_xslt", []string{"-suite=xslt30", "-version=3.0", "-xpath10-compatibility"}, "applies only to QT3"},
		{"xslt_version_31", []string{"-suite=xslt30", "-version=3.1"}, "select XPath"},
		{"negative_case_limit", []string{"-limit=-1"}, "nonnegative limit"},
		{"nonpositive_timeout", []string{"-timeout=0"}, "positive timeout"},
		{"unexpected_operand", []string{"catalog.xml"}, "no positional arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseSuiteOptions(append([]string{"-dir", dir}, tc.args...), io.Discard); err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
				t.Errorf("parseSuiteOptions(%v) error = %v, want diagnostic containing %q", tc.args, err, tc.diagnostic)
			}
		})
	}
}

func TestParseSuiteOptionsPreservesFlagValueErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, flag := range []string{"-sets=[", "-match=["} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()

			_, err := parseSuiteOptions([]string{"-dir", dir, flag}, io.Discard)
			if detail, ok := errors.AsType[*syntax.Error](err); !ok || detail.Code != syntax.ErrMissingBracket {
				t.Errorf("parseSuiteOptions(%q) error = %v, want missing bracket syntax error", flag, err)
			}
		})
	}

	_, err := parseSuiteOptions([]string{"-dir", dir, "-current-time=tomorrow"}, io.Discard)
	if detail, ok := errors.AsType[*time.ParseError](err); !ok || detail.Value != "tomorrow" {
		t.Errorf("parseSuiteOptions with invalid current time = %v, want a parse error for tomorrow", err)
	}
}

func TestDecodeSuiteNodeRespectsCatalogEncoding(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "catalog.xml")
	for _, tc := range []struct {
		name, label, text string
		want, diagnostic  string
	}{
		{"latin1", "iso-8859-1", "caf\xe9", "café", ""},
		{"ascii", "US-ASCII", "catalog", "catalog", ""},
		{"ascii_non_ascii_byte", "ascii", "caf\xe9", "", "non-ASCII byte"},
		{"unsupported_encoding", "other-encoding", "catalog", "", "unsupported suite catalog encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := `<?xml version="1.0" encoding="` + tc.label + `"?><test-set>` + tc.text + `</test-set>`
			node, resolved, err := decodeSuiteNode([]byte(raw), path)
			if tc.diagnostic != "" {
				if node != nil || resolved != "" || err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
					t.Errorf("decodeSuiteNode = (%v, %q, %v), want no catalog and diagnostic %q", node, resolved, err, tc.diagnostic)
				}
				return
			}
			if err != nil || node == nil {
				t.Fatalf("decodeSuiteNode: %v", err)
			}
			if node.XMLName.Local != "test-set" || node.Text != tc.want || resolved != path {
				t.Errorf("decodeSuiteNode = (%s, %q, %q), want (test-set, %q, %q)", node.XMLName.Local, node.Text, resolved, tc.want, path)
			}
		})
	}
}

func TestDecodeSuiteNodeChecksTrailingInput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "catalog.xml")
	for _, tc := range []struct {
		name, tail string
		valid      bool
	}{
		{"empty", "", true},
		{"XML Misc", "\t\n <!-- trailing comment --> <?catalog declared?>\r\n", true},
		{"additional root", "<extra/>", false},
		{"trailing text", "extra", false},
		{"truncated comment", "<!--", false},
		{"second declaration", `<?xml version="1.0"?>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			node, _, err := decodeSuiteNode([]byte("<catalog/>"+tc.tail), path)
			if tc.valid && (err != nil || node == nil) || !tc.valid && (err == nil || node != nil) {
				t.Fatalf("catalog tail %q: node=%v, error=%v; valid=%t", tc.tail, node, err, tc.valid)
			}
		})
	}
}
