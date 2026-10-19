package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestFuzzDiscovery(t *testing.T) {
	t.Setenv("GOWORK", "off")

	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.test/fixture\n\ngo 1.27.0\n")
	writeFixture(t, root, "internal_test.go", `package fixture
import tst "testing"
func FuzzOne(f *tst.F) {}
func TestOne(t *tst.T) {}
// func FuzzComment(f *tst.F) {}
type fixture struct{}
func (fixture) FuzzMethod(f *tst.F) {}
`)
	writeFixture(t, root, "external_test.go", `package fixture_test
import "testing"
func FuzzTwo(f *testing.F) {}
`)
	writeFixture(t, root, "excluded_test.go", `//go:build ignore

package fixture
import "testing"
func FuzzExcluded(f *testing.F) {}
`)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	var stderr bytes.Buffer

	want := []fuzzTarget{{Package: "example.test/fixture", Name: "FuzzOne"}, {Package: "example.test/fixture", Name: "FuzzTwo"}}

	targets, err := discoverFuzz(ctx, root, ".*", &stderr)
	if err != nil || !slices.Equal(targets, want) {
		t.Fatal("Go-selected fuzz targets changed", targets, err, stderr.String())
	}

	selected, err := discoverFuzz(ctx, root, "^FuzzTwo$", &stderr)
	if err != nil || !slices.Equal(selected, want[1:]) {
		t.Fatal("fuzz selection changed", selected, err, stderr.String())
	}

	if _, err := discoverFuzz(ctx, root, "^Missing$", &stderr); err == nil {
		t.Fatal("empty fuzz selection succeeded")
	}

	writeFixture(t, root, "broken_test.go", "package fixture\nimport \"testing\"\nfunc FuzzWrongType(f *testing.T) {}\n")

	if _, err := discoverFuzz(ctx, root, ".*", &stderr); err == nil {
		t.Fatal("Go test discovery failure ignored")
	}
}

func TestCanceledFuzzDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var stderr bytes.Buffer
	if _, err := discoverFuzz(ctx, t.TempDir(), ".*", &stderr); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
