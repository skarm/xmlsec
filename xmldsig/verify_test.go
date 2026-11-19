package xmldsig_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestVerifyUsesConfiguredExpandedRootAndIDNames(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	key := ecKey(t, elliptic.P256())
	source := parse(t, `<p:r xmlns:p="urn:invoice" xmlns:i="urn:identity" i:key="invoice"><p:total>42</p:total></p:r>`)
	root := document.Name{Space: "urn:invoice", Local: "r"}
	id := document.Name{Space: "urn:identity", Local: "key"}
	signed := sign(t, key, source, xmldsig.SignOptions{IDAttribute: id})
	opt := xmldsig.VerifyOptions{ExpectedRoot: root, IDAttribute: id}
	result, err := xmldsig.Verify(ctx, signed, key.Public(), opt)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(spki)
	if result.KeyFingerprintSHA256() != hex.EncodeToString(fingerprint[:]) || result.SignatureMethod() != xmldsig.ECDSASHA256 {
		t.Errorf("verified metadata = (%q, %q), want fingerprint %x and ECDSA-SHA256", result.KeyFingerprintSHA256(), result.SignatureMethod(), fingerprint)
	}
	if refs := result.References(); len(refs) != 1 || refs[0].URI() != "#invoice" || !refs[0].Target().Same(signed.Root()) ||
		refs[0].CanonicalizationMethod() != c14n.Exclusive {
		t.Errorf("verified references = %v, want the original root selected by #invoice with Exclusive C14N", refs)
	}
	if !result.CoversElement(signed.Root().Children()[0]) || result.CoversElement(source.Root().Children()[0]) {
		t.Error("coverage did not distinguish equal content in separate snapshots")
	}

	for _, tc := range []struct {
		name string
		opt  xmldsig.VerifyOptions
		want error
	}{
		{"wrong_root_namespace", xmldsig.VerifyOptions{ExpectedRoot: document.Name{Local: "r"}, IDAttribute: id}, xmldsig.ErrPolicy},
		{"wrong_id_namespace", xmldsig.VerifyOptions{ExpectedRoot: root, IDAttribute: document.Name{Local: "key"}}, xmldsig.ErrReference},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := xmldsig.Verify(t.Context(), signed, key.Public(), tc.opt); got != nil || !errors.Is(err, tc.want) {
				t.Errorf("Verify = (result present: %t, %v), want no result and %v", got != nil, err, tc.want)
			}
		})
	}
}

func TestVerifyEnforcesAggregateCanonicalBudget(t *testing.T) {
	t.Parallel()

	key := ecKey(t, elliptic.P256())
	const source = `<r ID="r"><v ID="v">value</v></r>`
	const child = `<v ID="v">value</v>`
	signed := sign(t, key, parse(t, source), xmldsig.SignOptions{ReferenceIDs: []string{"r", "v"}})
	info := findImportElement(t, signed.Root(), document.Name{Space: xmldsig.Namespace, Local: "SignedInfo"})
	var canonical bytes.Buffer
	if err := c14n.WriteElement(t.Context(), &canonical, info, c14n.Options{Algorithm: c14n.Exclusive}); err != nil {
		t.Fatal(err)
	}
	budget := canonical.Len() + len(source) + len(child)

	result, err := xmldsig.Verify(t.Context(), signed, key.Public(), xmldsig.VerifyOptions{Policy: xmldsig.Policy{MaxCanonicalBytes: budget}})
	if err != nil {
		t.Fatalf("verify at exact aggregate limit %d: %v", budget, err)
	}
	refs := result.References()
	if len(refs) != 2 || refs[0].URI() != "#r" || refs[0].Size() != len(source) || refs[1].URI() != "#v" || refs[1].Size() != len(child) {
		t.Errorf("wrong reference order or byte counts: %v", refs)
	}

	result, err = xmldsig.Verify(t.Context(), signed, key.Public(), xmldsig.VerifyOptions{Policy: xmldsig.Policy{MaxCanonicalBytes: budget - 1}})
	var failure *xmldsig.ReferenceError
	if result != nil || !errors.Is(err, xmldsig.ErrPolicy) || !errors.Is(err, reference.ErrLimit) || !errors.As(err, &failure) ||
		failure.Index != 1 || failure.URI != "#v" || failure.Stage != "transform" {
		t.Errorf("verify one byte below aggregate limit = (%v, %v), want reference 1 (#v) transform limit error and no result", result, err)
	}

	result, err = xmldsig.Verify(t.Context(), signed, key.Public(), xmldsig.VerifyOptions{Policy: xmldsig.Policy{MaxCanonicalBytes: canonical.Len() - 1}})
	if result != nil || !errors.Is(err, xmldsig.ErrPolicy) || !errors.Is(err, reference.ErrLimit) || errors.As(err, &failure) {
		t.Errorf("verify below SignedInfo limit = (%v, %v), want policy limit before reference processing", result, err)
	}
}

func TestVerifiedReferenceReplaysExactOctets(t *testing.T) {
	t.Parallel()

	key := ecKey(t, elliptic.P256())
	original := parse(t, `<r ID="r"><v b="2" a="1"/></r>`)
	signed := sign(t, key, original, xmldsig.SignOptions{})
	verified, err := xmldsig.Verify(t.Context(), signed, key.Public(), xmldsig.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Root().Same(signed.Root()) || verified.Root().Same(original.Root()) {
		t.Fatal("result did not retain the exact verified root")
	}
	refs := verified.References()
	if len(refs) != 1 {
		t.Fatalf("references = %d, want one", len(refs))
	}
	ref := refs[0]
	refs[0] = xmldsig.ReferenceResult{}
	if verified.References()[0].URI() != "#r" || !ref.Target().Same(signed.Root()) {
		t.Fatal("reference result changed after caller updated its slice, or lost target identity")
	}
	const expected = `<r ID="r"><v a="1" b="2"></v></r>`
	digest := sha256.Sum256([]byte(expected))
	if got := ref.Digest(); !bytes.Equal(got, digest[:]) {
		t.Errorf("reference digest = %s, want %x", hex.EncodeToString(got), digest)
	} else {
		clear(got)

		if again := ref.Digest(); !bytes.Equal(again, digest[:]) {
			t.Errorf("reference digest changed after clearing returned bytes: got %x, want %x", again, digest)
		}
	}
	var replay bytes.Buffer
	method := reference.Transform{Algorithm: c14n.Exclusive}
	n, err := ref.WriteCanonicalizedInput(t.Context(), &replay, method)
	if err != nil || n != int64(len(expected)) || replay.String() != expected {
		t.Errorf("replay = (%d, %q, %v), want (%d, %q, nil)", n, replay.String(), err, len(expected), expected)
	}

	sinkError := errors.New("destination failed")
	replay.Reset()
	n, err = ref.WriteCanonicalizedInput(t.Context(), replayErrorWriter{sinkError}, method)
	if n != 0 || !errors.Is(err, sinkError) {
		t.Errorf("replay to failed writer = (%d, %v), want (0, %v)", n, err, sinkError)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	n, err = ref.WriteCanonicalizedInput(ctx, &replay, method)
	if n != 0 || replay.Len() != 0 || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled replay = (%d, %d buffered, %v), want zero bytes and cancellation", n, replay.Len(), err)
	}
	var absent *bytes.Buffer
	if n, err := ref.WriteDigestInput(t.Context(), absent); n != 0 || !errors.Is(err, xmldsig.ErrPolicy) {
		t.Errorf("digest replay to typed nil writer = (%d, %v), want policy error and zero bytes", n, err)
	}
	if n, err := (xmldsig.ReferenceResult{}).WriteCanonicalizedInput(t.Context(), io.Discard, method); n != 0 || !errors.Is(err, xmldsig.ErrPolicy) {
		t.Errorf("zero reference replay = (%d, %v), want policy error and zero bytes", n, err)
	}
}

type replayErrorWriter struct{ err error }

func (w replayErrorWriter) Write([]byte) (int, error) { return 0, w.err }
