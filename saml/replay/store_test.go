package replay_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/saml/replay"
)

const nameRequest = "request"

const uriUrnSpUrnIdp = "urn:sp:urn:idp"

func TestAtomicConsume(t *testing.T) {
	m, e := replay.NewMemoryStore(replay.Config{})
	if e != nil {
		t.Fatal(e)
	}

	now := time.Now()
	entries := []replay.Entry{{Scope: nameRequest, ID: "r", ExpiresAt: now.Add(time.Minute)}, {Scope: "assertion", ID: "a", ExpiresAt: now.Add(time.Minute)}}

	var (
		success atomic.Int32
		wg      sync.WaitGroup
	)
	for range 64 {
		wg.Go(func() {
			e := m.Consume(t.Context(), entries, now)
			if e == nil {
				success.Add(1)
			} else if !errors.Is(e, replay.ErrReplay) {
				t.Error(e)
			}
		})
	}

	wg.Wait()

	if success.Load() != 1 || m.Len() != 2 {
		t.Fatal("not atomic")
	}
}

func TestCapacityExpiryAndAllOrNothing(t *testing.T) {
	m, _ := replay.NewMemoryStore(replay.Config{Capacity: 2})
	now := time.Now()

	entry := func(id string) replay.Entry { return replay.Entry{Scope: "s", ID: id, ExpiresAt: now.Add(time.Minute)} }
	if e := m.Consume(t.Context(), []replay.Entry{entry("a")}, now); e != nil {
		t.Fatal(e)
	}

	if e := m.Consume(t.Context(), []replay.Entry{entry("b"), entry("c")}, now); !errors.Is(e, replay.ErrCapacity) || m.Len() != 1 {
		t.Fatal("partial capacity commit")
	}

	if e := m.Consume(t.Context(), []replay.Entry{entry("b"), entry("a")}, now); !errors.Is(e, replay.ErrReplay) || m.Len() != 1 {
		t.Fatal("partial replay commit")
	}

	if e := m.Consume(t.Context(), []replay.Entry{entry("b")}, now); e != nil {
		t.Fatal(e)
	}

	later := now.Add(time.Minute)
	a := entry("a")

	a.ExpiresAt = later.Add(time.Minute)
	if e := m.Consume(t.Context(), []replay.Entry{a}, later); e != nil || m.Len() != 1 {
		t.Fatal("expiry")
	}
}

func TestReplayValidation(t *testing.T) {
	m, _ := replay.NewMemoryStore(replay.Config{})

	now := time.Now()
	for _, es := range [][]replay.Entry{nil, {{Scope: "", ID: "a", ExpiresAt: now.Add(time.Second)}}, {{Scope: "s", ID: "a", ExpiresAt: now}}, {{Scope: "s", ID: "a", ExpiresAt: now.Add(2 * time.Hour)}}, {{Scope: "s", ID: "a", ExpiresAt: now.Add(time.Second)}, {Scope: "s", ID: "a", ExpiresAt: now.Add(time.Second)}}} {
		if e := m.Consume(t.Context(), es, now); !errors.Is(e, replay.ErrPolicy) {
			t.Fatal(e)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if e := m.Consume(ctx, []replay.Entry{{Scope: "s", ID: "a", ExpiresAt: now.Add(time.Minute)}}, now); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func BenchmarkConsumeAndExpire(b *testing.B) {
	m, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		b.Fatal(err)
	}

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := []replay.Entry{{Scope: uriUrnSpUrnIdp, ID: nameRequest}, {Scope: uriUrnSpUrnIdp, ID: "assertion"}}

	b.ReportAllocs()

	for b.Loop() {
		expiry := at.Add(time.Second)
		for i := range entries {
			entries[i].ExpiresAt = expiry
		}

		if err := m.Consume(b.Context(), entries, at); err != nil {
			b.Fatal(err)
		}

		at = expiry
	}
}

func BenchmarkReplayParallel(b *testing.B) {
	m, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		b.Fatal(err)
	}

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	entries := []replay.Entry{{Scope: uriUrnSpUrnIdp, ID: nameRequest, ExpiresAt: at.Add(time.Minute)}}
	if err := m.Consume(b.Context(), entries, at); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := m.Consume(b.Context(), entries, at); !errors.Is(err, replay.ErrReplay) {
				b.Errorf("replay result: %v", err)
			}
		}
	})
}
