package timestamp_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
)

func TestFetchRejectsNonProgressingReader(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	q, err := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}

	reads := 0
	exhausted := errors.New("reader exceeded test bound")
	response := &body{Reader: clientReaderFunc(func([]byte) (int, error) {
		reads++
		if reads > 200 {
			return 0, exhausted
		}

		return 0, nil
	})}

	result, err := v.Fetch(t.Context(), transport{b: response}, q, testcert.Now(), pki.Evidence{})
	if result != nil || !errors.Is(err, io.ErrNoProgress) || !response.closed || reads > 100 {
		t.Fatalf("result=%v err=%v closed=%v reads=%d", result, err, response.closed, reads)
	}
}

func TestFetchRejectsInvalidReaderCount(t *testing.T) {
	c := testcert.New(t)
	v := verifier(t, c)

	q, err := timestamp.CreateRequest(t.Context(), nil, timestamp.RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}

	response := &body{Reader: clientReaderFunc(func(p []byte) (int, error) { return len(p) + 1, nil })}

	defer func() {
		if value := recover(); value != nil {
			t.Errorf("reader caused panic: %v", value)
		}
	}()

	result, err := v.Fetch(context.Background(), transport{b: response}, q, testcert.Now(), pki.Evidence{})
	if result != nil || !errors.Is(err, io.ErrShortBuffer) || !response.closed {
		t.Fatalf("result=%v err=%v closed=%v", result, err, response.closed)
	}
}

type clientReaderFunc func([]byte) (int, error)

func (f clientReaderFunc) Read(p []byte) (int, error) { return f(p) }
