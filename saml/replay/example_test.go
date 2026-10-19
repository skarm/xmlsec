package replay_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/saml/replay"
)

func ExampleMemoryStore_Consume() {
	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	store, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		panic(err)
	}
	// After signature, protocol and browser checks, consume all identifiers in
	// one atomic operation. Use shared storage when running multiple instances.
	entries := []replay.Entry{
		{Scope: "https://sp.example.test/request", ID: "_request", ExpiresAt: at.Add(time.Minute)},
		{Scope: "https://idp.example.test/assertion", ID: "_assertion", ExpiresAt: at.Add(time.Minute)},
	}
	if err := store.Consume(ctx, entries, at); err != nil {
		panic(err)
	}

	err = store.Consume(ctx, entries, at)
	fmt.Println(errors.Is(err, replay.ErrReplay))
	fmt.Println(store.Len())
	// Output:
	// true
	// 2
}
