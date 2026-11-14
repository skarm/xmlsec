package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/saml/replay"
)

func TestExample(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

type consumeFunc func(context.Context, []replay.Entry, time.Time) error

func (consume consumeFunc) Consume(ctx context.Context, entries []replay.Entry, now time.Time) error {
	return consume(ctx, entries, now)
}

func TestDemonstrateReplay(t *testing.T) {
	storeFailure := errors.New("store unavailable")
	for _, tc := range []struct {
		name      string
		responses []error
		wantErr   error
	}{
		{name: "replay_rejected", responses: []error{nil, replay.ErrReplay}},
		{name: "initial_consume_failed", responses: []error{storeFailure}, wantErr: storeFailure},
		{name: "second_consume_failed", responses: []error{nil, storeFailure}, wantErr: storeFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			now := time.Date(2026, time.January, 2, 3, 0, 0, 0, time.UTC)
			want := replay.Entry{Scope: "example-only", ID: "already-validated-id", ExpiresAt: time.Date(2026, time.January, 2, 3, 0, 30, 0, time.UTC)}
			calls := 0
			store := consumeFunc(func(gotCtx context.Context, entries []replay.Entry, at time.Time) error {
				if gotCtx != ctx || !at.Equal(now) || len(entries) != 1 || entries[0] != want {
					t.Errorf("consume %d received entries=%+v at %v, want %+v at %v with test context", calls+1, entries, at, want, now)
				}
				if calls >= len(tc.responses) {
					t.Fatalf("unexpected consume call %d", calls+1)
				}
				err := tc.responses[calls]
				calls++
				return err
			})
			if err := demonstrateReplay(ctx, store, now); !errors.Is(err, tc.wantErr) {
				t.Errorf("demonstrateReplay returned %v, want %v", err, tc.wantErr)
			}
			if calls != len(tc.responses) {
				t.Errorf("consume called %d times, want %d", calls, len(tc.responses))
			}
		})
	}

	t.Run("replay_unexpectedly_accepted", func(t *testing.T) {
		store := consumeFunc(func(context.Context, []replay.Entry, time.Time) error { return nil })
		if err := demonstrateReplay(t.Context(), store, time.Time{}); err == nil {
			t.Error("demonstrateReplay accepted two successful consumes")
		}
	})
}
