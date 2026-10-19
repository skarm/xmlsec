package state_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/saml/state"
)

const uriUrnTest = "urn:test"

const (
	nameRequest       = "_request"
	uriHTTPSSpTestAcs = "https://sp.test/acs"
)

func TestStateAtomicExpiryCopies(t *testing.T) {
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	m, e := state.NewMemoryStore(state.Config{Capacity: 1})
	if e != nil {
		t.Fatal(e)
	}

	p := pending(at)

	var (
		wins atomic.Int32
		wg   sync.WaitGroup
	)
	for range 32 {
		wg.Go(func() {
			e := m.Put(context.Background(), p, at)
			if e == nil {
				wins.Add(1)
			} else if !errors.Is(e, state.ErrExists) {
				t.Errorf("put: %v", e)
			}
		})
	}

	wg.Wait()

	if wins.Load() != 1 {
		t.Fatal("non-atomic insert", wins.Load())
	}

	p.RequestedContexts[0] = "urn:changed"

	got, e := m.Get(context.Background(), p.SP, p.RelayState, at)
	if e != nil || got.RequestedContexts[0] != uriUrnTest {
		t.Fatal("copy", e)
	}

	got.RequestedContexts[0] = "urn:changed2"

	got, e = m.Get(context.Background(), p.SP, p.RelayState, at)
	if e != nil || got.RequestedContexts[0] != uriUrnTest {
		t.Fatal("output copy", e)
	}

	p.RelayState += "other"
	if e = m.Put(context.Background(), p, at); !errors.Is(e, state.ErrCapacity) {
		t.Fatal("live eviction", e)
	}

	if _, e = m.Get(context.Background(), got.SP, got.RelayState, at.Add(time.Minute)); !errors.Is(e, state.ErrMissing) {
		t.Fatal("half-open expiry", e)
	}

	p.IssuedAt = at.Add(time.Minute)

	p.ExpiresAt = at.Add(2 * time.Minute)
	if e = m.Put(context.Background(), p, at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, e = m.Get(ctx, p.SP, p.RelayState, at); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestPendingURIStorageLimits(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, field := range []string{"NameIDFormat", "RequestedContexts"} {
		for _, length := range []int{0, 2048, 2049, 1 << 20} {
			store, err := state.NewMemoryStore(state.Config{})
			if err != nil {
				t.Fatal(err)
			}

			value := ""
			if length != 0 {
				value = "urn:" + strings.Repeat("x", length-4)
			}

			p := pending(at)
			if field == "NameIDFormat" {
				p.NameIDFormat = value
			} else {
				p.RequestedContexts = []string{value}
			}

			err = store.Put(t.Context(), p, at)

			invalid := length > 2048 || length == 0 && field == "RequestedContexts"
			if invalid {
				if !errors.Is(err, state.ErrPolicy) || store.Len() != 0 {
					t.Fatal("oversized or invalid URI stored", field, length, err)
				}

				continue
			}

			if err != nil || store.Len() != 1 {
				t.Fatal("valid URI rejected", field, length, err)
			}
		}
	}
}

func BenchmarkPutAndExpire(b *testing.B) {
	m, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		b.Fatal(err)
	}

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := state.Pending{SP: "urn:sp", IDP: "urn:idp", RequestID: nameRequest, RelayState: "0123456789abcdef", ACS: uriHTTPSSpTestAcs}

	b.ReportAllocs()

	for b.Loop() {
		p.IssuedAt = at

		p.ExpiresAt = at.Add(time.Second)
		if err := m.Put(context.Background(), p, at); err != nil {
			b.Fatal(err)
		}

		at = p.ExpiresAt
	}
}

func BenchmarkGetParallel(b *testing.B) {
	m, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		b.Fatal(err)
	}

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	p := state.Pending{SP: "urn:sp", IDP: "urn:idp", RequestID: nameRequest, RelayState: "0123456789abcdef", ACS: uriHTTPSSpTestAcs, IssuedAt: at, ExpiresAt: at.Add(time.Minute), RequestedContexts: []string{"urn:auth:password"}}
	if err := m.Put(context.Background(), p, at); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := m.Get(context.Background(), p.SP, p.RelayState, at); err != nil {
				b.Error(err)
			}
		}
	})
}

func pending(at time.Time) state.Pending {
	return state.Pending{SP: "https://sp.test", IDP: "https://idp.test", RequestID: nameRequest, RelayState: "abcdefghijklmnop", ACS: uriHTTPSSpTestAcs, IssuedAt: at, ExpiresAt: at.Add(time.Minute), RequestedContexts: []string{uriUrnTest}}
}
