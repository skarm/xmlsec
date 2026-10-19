package reference

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestTransformReaderPullAndCleanup(t *testing.T) {
	writes, cleaned := 0, false

	r := readTransform(t.Context(), func(w io.Writer) error {
		defer func() { cleaned = true }()

		for range 100 {
			writes++

			if _, err := w.Write([]byte("abcdef")); err != nil {
				return err
			}
		}

		return nil
	})
	if writes != 0 {
		t.Fatal("producer ran before reading")
	}

	var part [3]byte
	if n, err := r.Read(part[:]); n != 3 || err != nil || string(part[:]) != "abc" || writes != 1 {
		t.Fatal(n, err, writes)
	}

	if n, err := r.Read(part[:]); n != 3 || err != nil || string(part[:]) != "def" || writes != 1 {
		t.Fatal(n, err, writes)
	}

	if err := r.Close(); err != nil || !cleaned || writes != 1 {
		t.Fatal("close did not unwind producer", err, cleaned, writes)
	}

	if _, err := r.Read(part[:]); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTransformReaderErrorsAndCancellation(t *testing.T) {
	failure := errors.New("producer failed")
	r := readTransform(t.Context(), func(w io.Writer) error {
		if _, err := w.Write([]byte("ok")); err != nil {
			return err
		}

		return failure
	})

	data, err := io.ReadAll(r)
	if string(data) != "ok" || !errors.Is(err, failure) {
		t.Fatal(string(data), err)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	r = readTransform(ctx, func(w io.Writer) error { _, err := w.Write([]byte("cancel")); return err })

	cancel()

	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
