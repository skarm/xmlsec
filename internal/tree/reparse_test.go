package tree_test

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestReparseUsesParserStorageWithoutSerializedCopy(t *testing.T) {
	raw := `<r xmlns:p="urn:p"><p:v a="test">` + strings.Repeat("x", 1<<20) + `</p:v></r>`

	source, err := tree.ParseReader(t.Context(), strings.NewReader(raw), tree.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	measure := func(run func() error) uint64 {
		t.Helper()

		best := ^uint64(0)

		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			if err := run(); err != nil {
				t.Fatal(err)
			}

			runtime.ReadMemStats(&after)
			best = min(best, after.TotalAlloc-before.TotalAlloc)
		}

		return best
	}
	baseline := measure(func() error {
		_, err := tree.ParseReader(t.Context(), strings.NewReader(raw), tree.DefaultLimits())
		return err
	})

	allocated := measure(func() error { _, err := tree.Reparse(t.Context(), source, tree.DefaultLimits()); return err })
	if allocated > baseline+128<<10 {
		t.Fatalf("reparse allocated %d bytes against parser baseline %d", allocated, baseline)
	}

	limits := tree.DefaultLimits()

	limits.MaxBytes = 1024
	if result, err := tree.Reparse(t.Context(), source, limits); result != nil || !errors.Is(err, tree.ErrLimit) {
		t.Fatal("output budget", result, err)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	if result, err := tree.Reparse(canceled, source, tree.DefaultLimits()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", result, err)
	}

	after, err := source.XML(t.Context())
	if err != nil || string(after) != raw {
		t.Fatal("reparse changed source", err)
	}
}

func TestParseProducedRejectsProducerErrors(t *testing.T) {
	failure := errors.New("producer failed after complete XML")
	if got, err := tree.ParseProduced(t.Context(), func(dst io.Writer) error {
		if _, err := io.WriteString(dst, "<r/>"); err != nil {
			return err
		}

		return failure
	}, tree.DefaultLimits()); got != nil || !errors.Is(err, failure) {
		t.Fatal("producer error lost", got, err)
	}

	stopped := false
	if got, err := tree.ParseProduced(t.Context(), func(dst io.Writer) error {
		defer func() { stopped = true }()

		for range 10000 {
			if _, err := io.WriteString(dst, "<r>invalid"); err != nil {
				return err
			}
		}

		return nil
	}, tree.DefaultLimits()); got != nil || err == nil || !stopped {
		t.Fatal("producer was not stopped", got, err, stopped)
	}
}
