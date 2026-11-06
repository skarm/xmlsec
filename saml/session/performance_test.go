package session_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/session"
)

// Each operation registers and signs in size independent users. Input setup is
// excluded; store growth, uniqueness checks and expiry maintenance are included.
func BenchmarkMemoryStorePopulation(b *testing.B) {
	at := testcert.Now()
	for _, size := range []int{16, 1024, 8192} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			relations := make([]session.Relationship, size)
			sessions := make([]session.Session, size)
			for i := range relations {
				id := "user-" + strconv.Itoa(i)
				n := protocol.NameIdentifier{Value: id}
				relations[i] = session.Relationship{Principal: id, Peer: idpID, NameID: n, ExpiresAt: at.Add(time.Hour)}
				sessions[i] = session.Session{ID: id, Principal: id, Peer: idpID, NameID: n, ExpiresAt: at.Add(time.Duration(1+i%4) * time.Minute)}
			}
			b.ReportAllocs()
			for b.Loop() {
				store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: size})
				if err != nil {
					b.Fatal(err)
				}
				for i, r := range relations {
					if err := store.Register(b.Context(), r, at); err != nil {
						b.Fatal(err)
					}
					if err := store.Add(b.Context(), sessions[i], at); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkMemoryStoreExpire(b *testing.B) {
	at := testcert.Now()
	relations := make([]session.Relationship, 1024)
	for i := range relations {
		id := "user-" + strconv.Itoa(i)
		relations[i] = session.Relationship{Principal: id, Peer: idpID, NameID: protocol.NameIdentifier{Value: id}, ExpiresAt: at.Add(time.Minute)}
	}
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		store, err := session.NewMemoryStore(session.Config{EntityID: spID, Role: metadata.ServiceProvider, Capacity: len(relations)})
		if err != nil {
			b.Fatal(err)
		}
		for _, r := range relations {
			if err := store.Register(b.Context(), r, at); err != nil {
				b.Fatal(err)
			}
		}
		r := relations[0]
		r.ExpiresAt = at.Add(2 * time.Minute)
		b.StartTimer()
		if err := store.Register(b.Context(), r, at.Add(time.Minute)); err != nil {
			b.Fatal(err)
		}
	}
}
