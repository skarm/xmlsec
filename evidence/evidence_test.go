package evidence_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/evidence"
)

func TestObservationSnapshotsUntrustedBytesAndMetadata(t *testing.T) {
	raw := []byte("untrusted original bytes")
	expected := bytes.Clone(raw)
	redirects := []string{"https://evidence.test/final"}
	at := time.Unix(1700000000, 0).In(time.FixedZone("offset", 3600))
	item, err := evidence.NewObservation(t.Context(), evidence.CRL, raw, evidence.Provenance{URI: "https://evidence.test/first", Redirects: redirects, RetrievedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	clear(raw)
	redirects[0] = "https://changed.test/"
	output := item.Bytes()
	output[0] ^= 1
	metadata := item.Provenance()
	metadata.Redirects[0] = "https://changed-again.test/"
	if !bytes.Equal(item.Bytes(), expected) || item.DigestSHA256() != sha256.Sum256(expected) || item.Kind() != evidence.CRL || item.Size() != len(expected) {
		t.Fatal("mutable or reencoded observation")
	}
	if got := item.Provenance(); got.Redirects[0] != "https://evidence.test/final" || !got.RetrievedAt.Equal(at) || got.RetrievedAt.Location() != time.UTC {
		t.Fatal("provenance snapshot", got)
	}
	digest := sha256.Sum256(expected)
	if item.FingerprintSHA256() != hex.EncodeToString(digest[:]) || !item.Valid() {
		t.Fatal("missing acquisition identity")
	}
}

func TestObservationReaderTerminalErrors(t *testing.T) {
	failure := errors.New("terminal failure")
	for _, terminal := range []error{failure, errors.Join(io.EOF, failure)} {
		input := terminalReader{data: []byte("complete"), terminal: terminal}
		if item, err := evidence.ReadObservation(t.Context(), evidence.Timestamp, &input, evidence.Provenance{}, 8); item != nil || !errors.Is(err, failure) {
			t.Fatal("published failed acquisition", item, err)
		}
	}
	for _, tc := range []struct {
		input string
		limit int
		want  error
	}{{"", 1, evidence.ErrInput}, {"12345", 4, evidence.ErrLimit}, {"x", 0, evidence.ErrLimit}} {
		if item, err := evidence.ReadObservation(t.Context(), evidence.CRL, strings.NewReader(tc.input), evidence.Provenance{}, tc.limit); item != nil || !errors.Is(err, tc.want) {
			t.Fatal(item, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if item, err := evidence.NewObservation(ctx, evidence.CRL, []byte("x"), evidence.Provenance{}); item != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(item, err)
	}
	if item, err := evidence.NewObservation(t.Context(), "unknown", []byte("x"), evidence.Provenance{}); item != nil || !errors.Is(err, evidence.ErrInput) {
		t.Fatal(item, err)
	}
}

type terminalReader struct {
	data     []byte
	terminal error
}

func (r *terminalReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.terminal
	}
	return n, nil
}

func TestStoreRepeatableReadsAndReclaimedBudget(t *testing.T) {
	store, err := evidence.NewStore(t.TempDir(), 12)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, err := store.PutReader(t.Context(), evidence.OCSP, strings.NewReader("original"), evidence.Provenance{}, 12)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		reader, err := first.Open(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		err = errors.Join(err, reader.Close())
		if err != nil || string(got) != "original" || first.DigestSHA256() != sha256.Sum256(got) {
			t.Fatal("changed replay", string(got), err)
		}
	}
	if item, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("extra"), evidence.Provenance{}, 5); item != nil || !errors.Is(err, evidence.ErrLimit) {
		t.Fatal("aggregate budget bypass", item, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("123456789012"), evidence.Provenance{}, 12)
	if err != nil {
		t.Fatal("record close did not release budget", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Open(t.Context()); err == nil {
		t.Fatal("closed store reopened a record")
	}
}

func BenchmarkObservation(b *testing.B) {
	for _, size := range []int{256, 4096, 1 << 20} {
		raw := bytes.Repeat([]byte("x"), size)
		b.Run(stringSize(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				item, err := evidence.NewObservation(b.Context(), evidence.CRL, raw, evidence.Provenance{})
				if err != nil || item.Size() != size {
					b.Fatal(err)
				}
			}
		})
	}
}

func stringSize(size int) string {
	switch size {
	case 256:
		return "256B"
	case 4096:
		return "4KiB"
	default:
		return "1MiB"
	}
}
