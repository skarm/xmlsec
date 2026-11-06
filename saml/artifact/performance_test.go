package artifact_test

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/artifact"
	"github.com/skarm/xmlsec/saml/binding"
)

// Measure a burst filling the bounded store. Handles and the immutable message
// are prepared outside the timer; one operation is a complete population.
func BenchmarkMemoryStoreIssue(b *testing.B) {
	at := testcert.Now()
	doc, err := document.Parse(b.Context(), []byte(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{16, 1024, 8192} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			entries := make([]artifact.Entry, size)
			for i := range entries {
				a := binding.Artifact{}
				binary.BigEndian.PutUint64(a.MessageHandle[:8], uint64(i))
				entries[i] = artifact.Entry{Artifact: a, Recipient: "https://sp.test/entity", Message: doc, ExpiresAt: at.Add(time.Duration(1+i%4) * time.Minute)}
			}
			b.ReportAllocs()
			for b.Loop() {
				store, err := artifact.NewMemoryStore(size)
				if err != nil {
					b.Fatal(err)
				}
				for _, entry := range entries {
					if err := store.Put(b.Context(), entry, at); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// Run with a fixed iteration count: population is deliberately outside the
// timer, and is expensive in implementations that scan on every insertion.
func BenchmarkMemoryStoreExpire(b *testing.B) {
	at := testcert.Now()
	doc, err := document.Parse(b.Context(), []byte(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}
	entries := make([]artifact.Entry, 1024)
	for i := range entries {
		a := binding.Artifact{}
		binary.BigEndian.PutUint64(a.MessageHandle[:8], uint64(i))
		entries[i] = artifact.Entry{Artifact: a, Recipient: "https://sp.test/entity", Message: doc, ExpiresAt: at.Add(time.Minute)}
	}
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		store, err := artifact.NewMemoryStore(len(entries))
		if err != nil {
			b.Fatal(err)
		}
		for _, entry := range entries {
			if err := store.Put(b.Context(), entry, at); err != nil {
				b.Fatal(err)
			}
		}
		entry := entries[0]
		entry.ExpiresAt = at.Add(2 * time.Minute)
		b.StartTimer()
		if err := store.Put(b.Context(), entry, at.Add(time.Minute)); err != nil {
			b.Fatal(err)
		}
	}
}
