package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/saml/metadata"
)

func TestExample(t *testing.T) {
	if e := run(); e != nil {
		t.Fatal(e)
	}
}

func TestRegistryLookup(t *testing.T) {
	at := time.Date(2026, time.January, 2, 3, 0, 0, 0, time.UTC)
	expires := at.Add(time.Hour)
	const raw = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
		entityID="https://sp.example.test/entity" validUntil="2026-01-02T04:00:00Z">
		<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
			<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
				Location="https://sp.example.test/acs" index="0"/>
		</md:SPSSODescriptor>
	</md:EntityDescriptor>`
	snapshot, err := metadata.ParseTrusted(t.Context(), []byte(raw), at, metadata.Options{})
	if err != nil {
		t.Fatalf("parse registry fixture: %v", err)
	}
	reg := registry{spEntity: snapshot}

	t.Run("active_entity", func(t *testing.T) {
		entity, err := reg.Lookup(t.Context(), spEntity, expires.Add(-time.Second))
		if err != nil || entity == nil || entity.ID() != spEntity {
			t.Fatalf("Lookup returned entity ID=%q, error=%v, want %q and nil", entity.ID(), err, spEntity)
		}
	})

	for _, tc := range []struct {
		name     string
		id       string
		at       time.Time
		canceled bool
		want     error
	}{
		{name: "unknown_entity", id: idpEntity, at: at, want: metadata.ErrMetadata},
		{name: "at_expiry", id: spEntity, at: expires, want: metadata.ErrExpired},
		{name: "canceled_unknown_entity", id: idpEntity, at: at, canceled: true, want: context.Canceled},
		{name: "canceled_lookup", id: spEntity, at: at, canceled: true, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			entity, err := reg.Lookup(ctx, tc.id, tc.at)
			if entity != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Lookup(%q, %v) returned entity ID=%q, error=%v, want nil and %v", tc.id, tc.at, entity.ID(), err, tc.want)
			}
		})
	}
}
