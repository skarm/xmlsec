// Command redirect demonstrates the corresponding XML security API.
// Signed HTTP-Redirect binding and a SEPARATE atomic replay-store demonstration.
// This does not authenticate a user or implement SAML Web Browser SSO.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	message, err := document.Parse(ctx, []byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request" Version="2.0" IssueInstant="2026-10-08T00:00:00Z" Destination="https://example.invalid/slo"><saml:Issuer>https://issuer.invalid/</saml:Issuer><saml:NameID>example-user</saml:NameID></samlp:LogoutRequest>`), document.DefaultLimits())
	if err != nil {
		return err
	}

	relay := "opaque-session-bound-value"
	options := binding.Options{SignatureMethod: xmldsig.ECDSASHA256}

	rawQuery, err := binding.SignRedirect(ctx, message, binding.Request, &relay, key, options)
	if err != nil {
		return err
	}
	// In an HTTP handler pass req.URL.RawQuery, NOT req.URL.Query().Encode().
	verified, err := binding.VerifyRedirect(ctx, rawQuery, key.Public(), options)
	if err != nil {
		return err
	}

	fmt.Printf("binding-integrity=valid kind=%s protocol-validation=not-performed\n", verified.Kind())
	// Separate storage primitive: a real profile must validate issuer, destination,
	// request/session correlation, subject and time BEFORE consuming these IDs.
	store, err := replay.NewMemoryStore(replay.Config{Capacity: 10, MaxTTL: time.Minute})
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	entries := []replay.Entry{{Scope: "example-only", ID: "already-validated-id", ExpiresAt: now.Add(30 * time.Second)}}
	if err = store.Consume(ctx, entries, now); err != nil {
		return err
	}

	if err = store.Consume(ctx, entries, now); !errors.Is(err, replay.ErrReplay) {
		if err == nil {
			return errors.New("replay unexpectedly accepted")
		}

		return fmt.Errorf("expected replay rejection, got %w", err)
	}

	fmt.Println("replay-store-demo=second-consume-rejected (single-process)")

	return nil
}
