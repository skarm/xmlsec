package evidence_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/evidence"
)

func TestRecordRetainsMetadataAndRejectsNewReadersAfterStoreClose(t *testing.T) {
	t.Parallel()

	store, err := evidence.NewStore(t.TempDir(), 32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	const data = "fixture evidence"
	const next = "https://example.test/next"
	redirects := []string{next}
	at := time.Unix(1700000000, 0)
	record, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(data), evidence.Provenance{Redirects: redirects, RetrievedAt: at}, 32)
	if err != nil {
		t.Fatal(err)
	}
	redirects[0] = "https://example.test/changed"
	provenance := record.Provenance()
	if len(provenance.Redirects) != 1 {
		t.Fatalf("redirects = %v, want one", provenance.Redirects)
	}
	provenance.Redirects[0] = "https://example.test/other"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if reader, err := record.Open(ctx); reader != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("Open with canceled context = (%v, %v), want no reader and cancellation", reader, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := record.Close(); err != nil {
			t.Errorf("record Close after store Close: %v", err)
		}
	}
	if reader, err := record.Open(t.Context()); reader != nil || !errors.Is(err, evidence.ErrResource) || !errors.Is(err, os.ErrClosed) {
		t.Errorf("Open after store Close = (%v, %v), want no reader and closed resource error", reader, err)
	}
	digest := sha256.Sum256([]byte(data))
	if record.Size() != len(data) || record.Kind() != evidence.CRL || record.DigestSHA256() != digest || record.FingerprintSHA256() != hex.EncodeToString(digest[:]) {
		t.Error("record lost byte identity after close")
	}
	got := record.Provenance()
	if len(got.Redirects) != 1 || got.Redirects[0] != next || !got.RetrievedAt.Equal(at) {
		t.Errorf("record provenance after close = %+v, want original redirect and retrieval time", got)
	}
}

func TestStoreRejectsMissingParentAndCanceledAcquisition(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	if store, err := evidence.NewStore(filepath.Join(parent, "missing"), 8); store != nil || !errors.Is(err, evidence.ErrResource) || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("NewStore = (%v, %v), want no store and missing directory error", store, err)
	}
	store, err := evidence.NewStore(parent, 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if record, err := store.PutReader(canceled, evidence.CRL, strings.NewReader("data"), evidence.Provenance{}, 8); record != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("PutReader with canceled context = (%v, %v), want no record and cancellation", record, err)
	}
	record, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("fullsize"), evidence.Provenance{}, 8)
	if err != nil {
		t.Fatalf("canceled write took storage budget: %v", err)
	}
	reader, err := record.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err = errors.Join(err, reader.Close()); err != nil || string(got) != "fullsize" {
		t.Errorf("record bytes = (%q, %v), want fullsize", got, err)
	}
}
