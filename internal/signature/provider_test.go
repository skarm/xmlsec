package signature_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

type recordingProvider struct {
	key      crypto.Signer
	ctx      context.Context
	reader   io.Reader
	options  crypto.SignerOpts
	input    []byte
	output   []byte
	err      error
	calls    int
	complete func()
}

func (p *recordingProvider) Public() crypto.PublicKey { return p.key.Public() }
func (p *recordingProvider) Sign(ctx context.Context, reader io.Reader, input []byte, options crypto.SignerOpts) ([]byte, error) {
	p.calls++
	p.ctx, p.reader, p.options = ctx, reader, options
	p.input = input
	if p.err != nil {
		return nil, p.err
	}
	value, err := p.key.Sign(reader, input, options)
	p.output = value
	if p.complete != nil {
		p.complete()
	}
	return value, err
}

func TestSignerAdapterPreservesContextAndOwnedProviderBuffers(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	provider := &recordingProvider{key: key}
	adapter := signature.SignerAdapter{Provider: provider}
	algorithm, err := signature.Select(key.Public(), crypto.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	type contextKey struct{}
	ctx := context.WithValue(t.Context(), contextKey{}, "operation marker")
	message := []byte("exact message")
	value, err := signature.Sign(ctx, adapter, algorithm, message)
	if err != nil || provider.calls != 1 || provider.ctx.Value(contextKey{}) != "operation marker" || provider.options.HashFunc() != crypto.SHA256 {
		t.Fatal("context-aware signing failed", provider.calls, provider.ctx, err)
	}
	wantDigest := sha256.Sum256(message)
	if !bytes.Equal(provider.input, wantDigest[:]) || adapter.Public() != key.Public() {
		t.Fatal("provider received wrong digest or public key")
	}
	clear(provider.output)
	if err := signature.Verify(key.Public(), algorithm, message, value); err != nil {
		t.Fatal("caller signature aliased provider output", err)
	}

	digest := bytes.Clone(wantDigest[:])
	reader := bytes.NewReader([]byte("unused entropy for failing provider"))
	sentinel := errors.New("provider refused")
	provider.err = sentinel
	if result, err := signature.SignDigest(ctx, adapter, reader, digest, crypto.SHA256); result != nil || !errors.Is(err, sentinel) || provider.reader != reader || provider.ctx.Value(contextKey{}) != "operation marker" {
		t.Fatal("SignDigest replaced provider arguments or error", result, err)
	}
	clear(provider.input)
	if !bytes.Equal(digest, wantDigest[:]) {
		t.Fatal("provider received caller-owned digest storage")
	}
	if _, err := adapter.Sign(reader, digest, crypto.SHA256); !errors.Is(err, sentinel) || provider.ctx == nil || provider.ctx.Err() != nil || provider.ctx.Value(contextKey{}) != nil {
		t.Fatal("plain crypto.Signer adapter did not provide independent background context", err)
	}
}

func TestSignRejectsCancellationDuringProviderAndPreservesCause(t *testing.T) {
	t.Parallel()

	key := testcert.Key(t)
	algorithm, err := signature.Select(key.Public(), crypto.SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	provider := &recordingProvider{key: key, complete: cancel}
	if value, err := signature.Sign(ctx, signature.SignerAdapter{Provider: provider}, algorithm, []byte("message")); value != nil || !errors.Is(err, context.Canceled) || provider.calls != 1 || len(provider.output) == 0 {
		t.Fatal("cancellation after successful provider call returned signature", value, err)
	}
	sentinel := errors.New("hardware failed")
	provider.complete, provider.err = nil, sentinel
	if value, err := signature.Sign(t.Context(), signature.SignerAdapter{Provider: provider}, algorithm, []byte("message")); value != nil || !errors.Is(err, sentinel) || provider.calls != 2 {
		t.Fatal("provider failure lost", value, err)
	}
	if value, err := signature.Sign(nil, key, algorithm, nil); value != nil || !errors.Is(err, signature.Err) {
		t.Fatal("nil context accepted", value, err)
	}
	var absent *ecdsa.PrivateKey
	if value, err := signature.Sign(t.Context(), absent, algorithm, nil); value != nil || !errors.Is(err, signature.Err) {
		t.Fatal("nil signer accepted", value, err)
	}
}
