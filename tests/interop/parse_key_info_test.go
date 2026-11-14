//go:build interop

package interop_test

import (
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestKeyInfoFixtures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	base := filepath.Join(fixture.root, "testdata/keyinfo")

	var manifest struct {
		Cases []struct {
			Name      string
			Signature string
			SPKI      string
		}
	}
	decode(t, read(t, filepath.Join(base, "manifest.json")), &manifest)

	if len(manifest.Cases) == 0 {
		t.Fatal("missing KeyInfo corpus")
	}

	for _, tc := range manifest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			d := xmlDoc(t, read(t, filepath.Join(base, tc.Signature)))
			public := write(t, filepath.Join(dir, "public.pem"), pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: read(t, filepath.Join(base, tc.SPKI))}))
			sig := one(t, tree.Root(d), ds, "Signature")
			verifySignatureValue(t, fixture, d, sig, public)

			if !checkReferences(t, fixture, d, sig) {
				t.Fatal("KeyInfo fixture reference differs")
			}
		})
	}
}
