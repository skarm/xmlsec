package testcert_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestPublicFixtureSelection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	const manifest = `[{"name":"first","at":"2020-01-01T00:00:00Z","certificate":"wrong.der","nonce":"00"},{"name":"selected","at":"2026-10-25T12:30:00.123Z","certificate":"certificate.der","nonce":"0102ff"}]`
	testutil.WriteFile(t, dir, "manifest.json", []byte(manifest))
	wantDER := []byte{1, 2, 3, 4}
	testutil.WriteFile(t, dir, "certificate.der", wantDER)

	fixture := testcert.LoadFixture(t, dir, "selected")
	wantTime := time.Date(2026, 10, 25, 12, 30, 0, 123000000, time.UTC)
	if fixture.Certificate != "certificate.der" || !fixture.At.Equal(wantTime) || !bytes.Equal(fixture.Nonce, []byte{1, 2, 255}) {
		t.Fatalf("selected fixture metadata = %+v, want certificate.der at %s with nonce 0102ff", fixture, wantTime)
	}
	if got := fixture.Read(t, fixture.Certificate); !bytes.Equal(got, wantDER) {
		t.Errorf("selected fixture bytes = %x, want %x", got, wantDER)
	}
}

func TestLoadFixtureReportsInvalidManifest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, manifest string
		check          func(*testing.T, error)
	}{
		{"invalid_json", `[{"name":]`, func(t *testing.T, err error) {
			if _, ok := errors.AsType[*json.SyntaxError](err); !ok {
				t.Errorf("LoadFixture failed with %v, want a JSON syntax error", err)
			}
		}},
		{"invalid_time", `[{"name":"selected","at":"today"}]`, func(t *testing.T, err error) {
			var parseErr *time.ParseError
			if !errors.As(err, &parseErr) || parseErr.Value != "today" {
				t.Errorf("LoadFixture failed with %v, want a time parse error for today", err)
			}
		}},
		{"invalid_nonce", `[{"name":"selected","at":"2026-10-25T12:30:00Z","nonce":"zz"}]`, func(t *testing.T, err error) {
			var invalid hex.InvalidByteError
			if !errors.As(err, &invalid) || invalid != 'z' {
				t.Errorf("LoadFixture failed with %v, want invalid hex byte z", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			testutil.WriteFile(t, dir, "manifest.json", []byte(tc.manifest))
			err := captureFixtureFatal(t, func(tb testing.TB) { testcert.LoadFixture(tb, dir, "selected") })
			tc.check(t, err)
		})
	}
}

func TestLoadFixtureReportsMissingManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := captureFixtureFatal(t, func(tb testing.TB) { testcert.LoadFixture(tb, dir, "selected") })
	assertMissingFixturePath(t, err, filepath.Join(dir, "manifest.json"))
}

func TestLoadFixtureReportsUnknownName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WriteFile(t, dir, "manifest.json", []byte(`[{"name":"available","at":"2026-10-25T12:30:00Z"}]`))
	err := captureFixtureFatal(t, func(tb testing.TB) { testcert.LoadFixture(tb, dir, "missing") })
	if got := err.Error(); !strings.Contains(got, dir) || !strings.Contains(got, "missing") {
		t.Errorf("LoadFixture failed with %q, want directory %q and requested name missing", got, dir)
	}
}

func TestPublicFixtureReadReportsMissingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WriteFile(t, dir, "manifest.json", []byte(`[{"name":"selected","at":"2026-10-25T12:30:00Z","certificate":"missing.der"}]`))
	fixture := testcert.LoadFixture(t, dir, "selected")
	err := captureFixtureFatal(t, func(tb testing.TB) { fixture.Read(tb, fixture.Certificate) })
	assertMissingFixturePath(t, err, filepath.Join(dir, "missing.der"))
}

func assertMissingFixturePath(t *testing.T, err error, want string) {
	t.Helper()

	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || !errors.Is(err, os.ErrNotExist) || pathErr.Path != want {
		t.Errorf("fixture failed with %v, want missing path %q", err, want)
	}
}
