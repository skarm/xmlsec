package state_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/skarm/xmlsec/saml/state"
)

func ExampleMemoryStore_Get() {
	ctx := context.Background()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	defer clear(secret)

	digest, err := state.BrowserDigest(secret)
	if err != nil {
		panic(err)
	}

	store, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		panic(err)
	}

	pending := state.Pending{
		SP: "https://sp.example.test/entity", IDP: "https://idp.example.test/entity",
		RequestID: "_request", RelayState: "opaque-request-handle-1", ACS: "https://sp.example.test/acs",
		IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute), BrowserSHA256: digest,
	}
	if err := store.Put(ctx, pending, at); err != nil {
		panic(err)
	}

	first, err := store.Get(ctx, pending.SP, pending.RelayState, at)
	if err != nil {
		panic(err)
	}

	again, err := store.Get(ctx, pending.SP, pending.RelayState, at)
	if err != nil {
		panic(err)
	}

	// Get does not consume a login attempt. saml/sp performs browser correlation
	// and commits acceptance through the separate atomic replay store.
	fmt.Println(first.RequestID, again.RequestID)
	// Output: _request _request
}
