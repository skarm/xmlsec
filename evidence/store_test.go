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

func TestStoreKeepsRelativeParentAcrossWorkingDirectoryChanges(t *testing.T) {
	parent := t.TempDir()
	t.Chdir(parent)
	store, err := evidence.NewStore(".", 16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	const contents = "evidence"
	first, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(contents), evidence.Provenance{}, len(contents))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	reader, err := first.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err := errors.Join(err, reader.Close()); err != nil || string(got) != contents {
		t.Fatalf("record = (%q, %v), want %q", got, err, contents)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(contents), evidence.Provenance{}, len(contents)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Errorf("original parent after Close = (%v, %v), want empty directory", entries, err)
	}
}

func TestRecordOpensThroughOriginalAbsoluteDirectoryPath(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	target := filepath.Join(parent, "target", "child")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Keep the absolute caller path as written so the filesystem resolves the
	// parent of the symlink target.
	alternate := link + string(filepath.Separator) + ".."
	store, err := evidence.NewStore(alternate, 16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	const contents = "sample evidence"
	record, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(contents), evidence.Provenance{}, len(contents))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := record.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err := errors.Join(err, reader.Close(), record.Close()); err != nil || string(got) != contents {
		t.Fatalf("record = (%q, %v), want %q", got, err, contents)
	}
}

func TestRecordCopiesShareClose(t *testing.T) {
	t.Parallel()

	const contents = "evidence"

	store, err := evidence.NewStore(t.TempDir(), int64(len(contents)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	record, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(contents), evidence.Provenance{}, len(contents))
	if err != nil {
		t.Fatal(err)
	}
	copyOfRecord := *record
	closed := make(chan error, 1)
	go func() { closed <- copyOfRecord.Close() }()
	if err := errors.Join(record.Close(), <-closed); err != nil {
		t.Fatalf("closing both handles: %v", err)
	}

	for _, handle := range []*evidence.Record{record, &copyOfRecord} {
		reader, err := handle.Open(t.Context())
		if reader != nil {
			t.Error("closed record opened a reader", reader.Close())
		}
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("Open after Close: %v, want %v", err, os.ErrClosed)
		}
	}

	replacement, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader(contents), evidence.Provenance{}, len(contents))
	if err != nil {
		t.Fatalf("replacement write could not reuse released storage: %v", err)
	}
	if _, err := store.PutReader(t.Context(), evidence.CRL, strings.NewReader("x"), evidence.Provenance{}, 1); !errors.Is(err, evidence.ErrLimit) {
		t.Fatalf("store accepted more than its capacity: %v", err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}
