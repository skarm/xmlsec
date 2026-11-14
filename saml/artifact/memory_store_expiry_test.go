package artifact_test

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/artifact"
	"github.com/skarm/xmlsec/saml/binding"
)

func TestStoreMixedExpiryAndReuse(t *testing.T) {
	at := testcert.Now()
	doc, err := document.Parse(t.Context(), []byte(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{16, 64, 128} {
		store, err := artifact.NewMemoryStore(size)
		if err != nil {
			t.Fatal(err)
		}
		entries := make([]artifact.Entry, size)
		for i := range entries {
			a := binding.Artifact{}
			binary.BigEndian.PutUint64(a.MessageHandle[:8], uint64(i))
			entries[i] = artifact.Entry{Artifact: a, Recipient: "https://sp.test/entity", Message: doc, ExpiresAt: at.Add(time.Duration(1+i%4) * time.Minute)}
			if err := store.Put(t.Context(), entries[i], at); err != nil {
				t.Fatal(err)
			}
		}
		for i, entry := range entries {
			if i%4 >= 2 {
				continue
			}
			if message, err := store.Take(t.Context(), entry.Artifact, entry.Recipient, at); err != nil || message != doc {
				t.Fatal("live message lost", err)
			}
			if err := store.Put(t.Context(), entry, at); err == nil {
				t.Fatal("consumed artifact lost its collision tombstone")
			}
		}
		for i, entry := range entries {
			if i%4 >= 2 {
				continue
			}
			entry.ExpiresAt = at.Add(5 * time.Minute)
			if err := store.Put(t.Context(), entry, at.Add(2*time.Minute)); err != nil {
				t.Fatal("expired tombstone blocked capacity or handle reuse", err)
			}
		}
		for i, entry := range entries {
			message, err := store.Take(t.Context(), entry.Artifact, entry.Recipient, at.Add(2*time.Minute))
			if err != nil || message != doc {
				t.Fatalf("wrong live entry %d: %v", i, err)
			}
		}
		for _, entry := range entries {
			entry.ExpiresAt = at.Add(6 * time.Minute)
			if err := store.Put(t.Context(), entry, at.Add(5*time.Minute)); err != nil {
				t.Fatal("store did not drain all expired entries", err)
			}
		}
	}
}

func TestStoreConcurrentIndexedConsumption(t *testing.T) {
	at := testcert.Now()
	doc, err := document.Parse(t.Context(), []byte(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewMemoryStore(128)
	if err != nil {
		t.Fatal(err)
	}
	var handles [128]binding.Artifact
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := worker; i < len(handles); i += 8 {
				binary.BigEndian.PutUint64(handles[i].MessageHandle[:8], uint64(i))
				if err := store.Put(t.Context(), artifact.Entry{Artifact: handles[i], Recipient: "https://sp.test/entity", Message: doc, ExpiresAt: at.Add(time.Minute)}, at); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	var consumed atomic.Int32
	for range 16 {
		wg.Go(func() {
			for _, a := range handles {
				message, err := store.Take(t.Context(), a, "https://sp.test/entity", at)
				if err != nil {
					t.Error(err)
				}
				if message != nil {
					consumed.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if consumed.Load() != int32(len(handles)) {
		t.Fatal("indexed store lost atomic single-use consumption", consumed.Load())
	}
}

func TestArtifactZeroDeadlinePreservesLiveEntries(t *testing.T) {
	t.Parallel()

	doc, err := document.Parse(t.Context(), []byte(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{16, 64, 65} {
		for _, later := range []bool{false, true} {
			t.Run(fmt.Sprintf("count=%d/later=%t", count, later), func(t *testing.T) {
				t.Parallel()

				// MemoryStore accepts supplied nonzero times around year1. This
				// exercises storage expiry, not a protocol authentication timestamp.
				zero := time.Time{}
				at, checkAt := zero.Add(-4*time.Minute), zero.Add(-3*time.Minute)
				store, err := artifact.NewMemoryStore(count + 2)
				if err != nil {
					t.Fatal(err)
				}
				put := func(id int, expires, now time.Time) {
					t.Helper()

					entry := artifact.Entry{
						Artifact:  binding.Artifact{MessageHandle: [20]byte{byte(id)}},
						Recipient: "urn:recipient", Message: doc, ExpiresAt: expires,
					}
					if err := store.Put(t.Context(), entry, now); err != nil {
						t.Fatal(err)
					}
				}
				for id := 1; id <= count; id++ {
					put(id, zero, at)
				}
				expires := checkAt
				if later {
					expires = zero.Add(time.Minute)
				}
				put(count+1, expires, at)
				put(count+2, zero, checkAt)
				for id := 1; id <= count; id++ {
					got, err := store.Take(t.Context(), binding.Artifact{MessageHandle: [20]byte{byte(id)}}, "urn:recipient", checkAt)
					if err != nil || got != doc {
						t.Fatalf("unexpired artifact %d lost: got %p, want %p, err %v", id, got, doc, err)
					}
				}
			})
		}
	}
}
