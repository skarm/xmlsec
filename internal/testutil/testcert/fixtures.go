package testcert

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PublicFixture contains checked-in public evidence, never private keys.
// All fuzz processes use the same certificates and validation time.
type PublicFixture struct {
	base string
	// At is the explicit trusted time used by this operation.
	At          time.Time
	Certificate string
	Nonce       []byte
}

// LoadFixture selects metadata for a checked-in public interoperability fixture.
func LoadFixture(t testing.TB, base, name string) PublicFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(base, "manifest.json")) // #nosec G304 -- Go tests supply the fixture directory.
	if err != nil {
		t.Fatal(err)
	}

	var cases []struct {
		Name        string
		At          string
		Certificate string
		Nonce       string
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}

	for _, c := range cases {
		if c.Name != name {
			continue
		}

		at, err := time.Parse(time.RFC3339Nano, c.At)
		if err != nil {
			t.Fatal(err)
		}

		nonce, err := hex.DecodeString(c.Nonce)
		if err != nil {
			t.Fatal(err)
		}

		return PublicFixture{base: base, At: at, Certificate: c.Certificate, Nonce: nonce}
	}

	t.Fatalf("missing public fixture %s/%s", base, name)

	return PublicFixture{}
}

// Read reads a file from the selected fixture directory without authenticating it.
func (f PublicFixture) Read(t testing.TB, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(f.base, path)) // #nosec G304 -- Paths come from the repository fixture manifest.
	if err != nil {
		t.Fatal(err)
	}

	return data
}
