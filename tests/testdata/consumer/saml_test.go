package consumer_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/idp"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/saml/replay"
	"github.com/skarm/xmlsec/saml/sp"
	"github.com/skarm/xmlsec/saml/state"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestSAMLStoresReleaseExpiredCapacity(t *testing.T) {
	const stateStore = "State"

	for _, name := range []string{stateStore, "Replay"} {
		t.Run(name, func(t *testing.T) {
			requests, err := state.NewMemoryStore(state.Config{Capacity: 32768})
			if err != nil {
				t.Fatal(err)
			}

			consumed, err := replay.NewMemoryStore(replay.Config{Capacity: 32768})
			if err != nil {
				t.Fatal(err)
			}

			at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

			for batch := range 2 {
				retained := retainedHeapDuring(t, func() any {
					if name == stateStore {
						return expireRequestCapacity(t, requests, at)
					}

					return expireReplayCapacity(t, consumed, at)
				})
				t.Logf("store %s after expiry batch %d: %d retained bytes", name, batch, retained)

				if retained > 2<<20 {
					t.Fatalf("store retained expired capacity: %d bytes", retained)
				}

				at = at.Add(3 * time.Minute)
			}
		})
	}
}

func fillExpiryStore(t *testing.T, at time.Time, put func(string, time.Time) error) {
	t.Helper()

	for i := range 32768 {
		expires := at.Add(time.Minute)
		if i < 16 {
			expires = at.Add(2 * time.Minute)
		}

		if err := put(fmt.Sprintf("_%016d", i), expires); err != nil {
			t.Fatal(err)
		}
	}
}

func expireRequestCapacity(t *testing.T, store *state.MemoryStore, at time.Time) any {
	t.Helper()

	const spID = "https://sp.test"

	fillExpiryStore(t, at, func(id string, expires time.Time) error {
		pending := state.Pending{SP: spID, IDP: "https://idp.test", RequestID: id, RelayState: id, ACS: "https://sp.test/acs", IssuedAt: at, ExpiresAt: expires}
		return store.Put(t.Context(), pending, at)
	})
	later := at.Add(time.Minute)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := store.Get(ctx, spID, "_0000000000000000", later); !errors.Is(err, context.Canceled) || store.Len() != 32768 {
		t.Fatal("canceled lookup changed the store", err)
	}

	live, err := store.Get(t.Context(), spID, "_0000000000000000", later)
	if err != nil || store.Len() != 16 || live.RequestID != "_0000000000000000" {
		t.Fatal("pruning lost live state", err, store.Len())
	}

	return store
}

func expireReplayCapacity(t *testing.T, store *replay.MemoryStore, at time.Time) any {
	t.Helper()

	fillExpiryStore(t, at, func(id string, expires time.Time) error {
		return store.Consume(t.Context(), []replay.Entry{{Scope: "s", ID: id, ExpiresAt: expires}}, at)
	})
	later := at.Add(time.Minute)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	live := []replay.Entry{{Scope: "s", ID: "_0000000000000000", ExpiresAt: at.Add(2 * time.Minute)}}
	if err := store.Consume(ctx, live, later); !errors.Is(err, context.Canceled) || store.Len() != 32768 {
		t.Fatal("canceled consumption changed the store", err)
	}

	if err := store.Consume(t.Context(), live, later); !errors.Is(err, replay.ErrReplay) || store.Len() != 16 {
		t.Fatal("pruning lost replay protection", err, store.Len())
	}

	return store
}

func TestSAMLStateRejectsOversizedValuesBeforeCopy(t *testing.T) {
	source := "urn:" + strings.Repeat("x", 8<<20)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for _, field := range []string{"NameIDFormat", "RequestedContexts"} {
		store, err := state.NewMemoryStore(state.Config{})
		if err != nil {
			t.Fatal(err)
		}

		pending := state.Pending{SP: "urn:sp", IDP: "urn:idp", RequestID: "_request", RelayState: "0123456789abcdef", ACS: "https://sp.test/return", IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
		if field == "NameIDFormat" {
			pending.NameIDFormat = source
		} else {
			pending.RequestedContexts = []string{source}
		}

		allocated := allocatedDuring(t, func() error {
			if err := store.Put(t.Context(), pending, at); !errors.Is(err, state.ErrPolicy) {
				t.Fatal("oversized state accepted", field, err)
			}

			return nil
		})
		if allocated > 128<<10 || store.Len() != 0 {
			t.Fatal("oversized state copied or persisted", field, allocated)
		}
	}
}

func TestSAMLStoresReleaseCallerBuffers(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, name := range []string{"State", "Replay"} {
		t.Run(name, func(t *testing.T) {
			retained := retainedHeapDuring(t, func() any {
				requests, err := state.NewMemoryStore(state.Config{})
				if err != nil {
					t.Fatal(err)
				}
				consumed, err := replay.NewMemoryStore(replay.Config{})
				if err != nil {
					t.Fatal(err)
				}
				for i := range 8 {
					header := fmt.Sprintf("https://sp.test|https://idp.test|_request%d|%016d|https://sp.test/acs|urn:name|urn:context", i, i)
					source := header + strings.Repeat("x", 1<<20)
					fields := strings.Split(source[:len(header)], "|")
					if name == "State" {
						pending := state.Pending{SP: fields[0], IDP: fields[1], RequestID: fields[2], RelayState: fields[3], ACS: fields[4], NameIDFormat: fields[5], RequestedContexts: fields[6:], IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
						if err := requests.Put(t.Context(), pending, at); err != nil {
							t.Fatal(err)
						}
					} else if err := consumed.Consume(t.Context(), []replay.Entry{{Scope: fields[0], ID: fields[2], ExpiresAt: at.Add(time.Minute)}}, at); err != nil {
						t.Fatal(err)
					}
				}
				if name == "State" {
					pending, err := requests.Get(t.Context(), "https://sp.test", "0000000000000000", at)
					if err != nil || requests.Len() != 8 || pending.RequestID != "_request0" || len(pending.RequestedContexts) != 1 || pending.RequestedContexts[0] != "urn:context" {
						t.Fatal("stored state changed", pending, err)
					}
					return requests
				}
				if consumed.Len() != 8 {
					t.Fatal("replay entries lost")
				}
				if err := consumed.Consume(t.Context(), []replay.Entry{{Scope: "https://sp.test", ID: "_request0", ExpiresAt: at.Add(time.Minute)}}, at); !errors.Is(err, replay.ErrReplay) {
					t.Fatal("replay detection changed", err)
				}
				return consumed
			})
			t.Logf("eight stored requests: %d retained heap bytes", retained)
			if retained > 2<<20 {
				t.Fatalf("small entries retained caller buffers: %d bytes", retained)
			}
		})
	}
}

func TestSAMLRedirectReleasesQueryBuffer(t *testing.T) {
	key, _ := nativeIOSigner(t)
	doc, err := document.ParseReader(t.Context(), strings.NewReader(`<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0" IssueInstant="2026-01-02T03:04:05Z"/>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, withRelay := range []bool{false, true} {
		t.Run(fmt.Sprintf("Relay=%v", withRelay), func(t *testing.T) {
			var relay *string
			if withRelay {
				value := "opaque-state"
				relay = &value
			}
			options := binding.Options{SignatureMethod: xmldsig.ECDSASHA256}
			query, err := binding.SignRedirect(t.Context(), doc, binding.Request, relay, key, options)
			if err != nil {
				t.Fatal(err)
			}
			// SigAlg may use literal ':' and '/' while '#' must stay escaped.
			// Authentication covers this exact received encoding.
			unsigned, _, _ := strings.Cut(query, "&Signature=")
			unsigned = strings.Replace(unsigned, url.QueryEscape(xmldsig.ECDSASHA256), strings.ReplaceAll(xmldsig.ECDSASHA256, "#", "%23"), 1)
			signature, err := xmldsig.SignMessage(t.Context(), []byte(unsigned), key, xmldsig.ECDSASHA256, xmldsig.Policy{})
			if err != nil {
				t.Fatal(err)
			}
			query = unsigned + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
			retained := retainedHeapDuring(t, func() any {
				results := make([]*binding.RedirectResult, 8)
				for i := range results {
					source := query + strings.Repeat("x", 1<<20)
					results[i], err = binding.VerifyRedirect(t.Context(), source[:len(query)], key.Public(), options)
					if err != nil {
						t.Fatal(err)
					}
					relayState, present := results[i].RelayState()
					if present != withRelay || withRelay && relayState != *relay || results[i].SignatureMethod() != xmldsig.ECDSASHA256 {
						t.Fatal("authenticated metadata changed")
					}
				}
				return results
			})
			t.Logf("eight Redirect results: %d retained heap bytes", retained)
			if retained > 2<<20 {
				t.Fatalf("small Redirect results retained query buffers: %d bytes", retained)
			}
		})
	}
}

func TestSAMLServiceAndIdentityProvider(t *testing.T) {
	ctx := t.Context()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	const (
		spID      = "https://sp.test/entity"
		idpID     = "https://idp.test/entity"
		acs       = "https://sp.test/acs"
		sso       = "https://idp.test/sso"
		authClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	)
	spKey, idpKey := signingIdentity(t, at, 1), signingIdentity(t, at, 2)
	specs := []metadata.EntityDescriptor{
		{ID: "_sp", EntityID: spID, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: spKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {{Binding: metadata.HTTPPost, Location: acs, Indexed: true, Default: true}}}, NameIDFormats: []string{protocol.NameIDPersistent}, AuthnRequestsSigned: true, WantAssertionsSigned: true}},
		{ID: "_idp", EntityID: idpID, ValidUntil: at.Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: "signing", CertificateDER: idpKey.CertificateDER}}, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPRedirect, Location: sso}}}, NameIDFormats: []string{protocol.NameIDPersistent}, WantAuthnRequestsSigned: true}},
	}
	var aggregate bytes.Buffer
	aggregate.WriteString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_partners" validUntil="2026-01-02T04:04:05Z">`)
	for _, spec := range specs {
		d, err := metadata.Build(ctx, spec, at, metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := d.XML(ctx)
		if err != nil {
			t.Fatal(err)
		}
		aggregate.Write(raw)
	}
	aggregate.WriteString(`</md:EntitiesDescriptor>`)
	unsignedMetadata, err := document.Parse(ctx, aggregate.Bytes(), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	signedMetadata, err := metadata.Sign(ctx, unsignedMetadata, spKey.Key, spKey.CertificateDER, xmldsig.ECDSASHA256, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	metadataBytes, err := signedMetadata.XML(ctx)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{spKey.Key.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	partners, err := verifier.Verify(ctx, metadataBytes, at)
	if err != nil {
		t.Fatal(err)
	}
	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	spReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	idpReplay, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sp.NewServiceProvider(sp.Config{EntityID: spID, Metadata: partners, Signing: spKey, Requests: requests, Replay: spReplay})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := idp.NewIdentityProvider(idp.Config{EntityID: idpID, Metadata: partners, Signing: idpKey, Replay: idpReplay})
	if err != nil {
		t.Fatal(err)
	}
	browser := bytes.Repeat([]byte{7}, 32)
	outbound, err := service.Begin(ctx, sp.BeginOptions{IDP: idpID, At: at, BrowserBinding: browser, NameIDFormat: protocol.NameIDPersistent, RequestedContexts: []string{authClass}, ForceAuthn: true})
	if err != nil {
		t.Fatal(err)
	}
	request, err := identity.AcceptRedirect(ctx, outbound.RawQuery(), spID, sso, at)
	if err != nil {
		t.Fatal(err)
	}
	response, err := identity.Issue(ctx, request, idp.Authentication{NameID: "alice", NameIDFormat: protocol.NameIDPersistent, AuthnInstant: at.Add(time.Second), AuthnContext: authClass, FreshAuthentication: true, InteractionUsed: true}, at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var form bytes.Buffer
	if _, err := response.WritePOST(ctx, &form); err != nil {
		t.Fatal(err)
	}

	grant, err := service.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{At: at.Add(3 * time.Second), BrowserBinding: browser})
	if err != nil {
		t.Fatal(err)
	}
	if grant.NameID() != "alice" || grant.InResponseTo() != outbound.RequestID() {
		t.Fatal("incorrect grant")
	}
	if _, err := service.ConsumePOST(ctx, form.Bytes(), sp.ConsumeOptions{At: at.Add(3 * time.Second), BrowserBinding: browser}); !errors.Is(err, replay.ErrReplay) {
		t.Fatal(err)
	}
}

func signingIdentity(t *testing.T, at time.Time, serial int64) protocol.SigningKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "External consumer"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.SigningKey{Key: key, CertificateDER: der}
}

func TestMetadataVerifierRejectsMalformedKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  crypto.PublicKey
	}{
		{"nil", nil},
		{"nilRSA", (*rsa.PublicKey)(nil)},
		{"emptyRSA", &rsa.PublicKey{}},
		{"nilECDSA", (*ecdsa.PublicKey)(nil)},
		{"emptyECDSA", &ecdsa.PublicKey{}},
		{"nilEd25519", ed25519.PublicKey(nil)},
		{"shortEd25519", ed25519.PublicKey{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("constructor panicked: %v", value)
				}
			}()
			verifier, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{tc.key}})
			if verifier != nil || err == nil {
				t.Fatalf("invalid key accepted: verifier=%v err=%v", verifier, err)
			}
		})
	}
}

func TestSAMLStores(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	replays, err := replay.NewMemoryStore(replay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	entries := []replay.Entry{{Scope: "consumer", ID: "assertion", ExpiresAt: now.Add(time.Minute)}}
	if err := replays.Consume(ctx, entries, now); err != nil {
		t.Fatal(err)
	}
	if err := replays.Consume(ctx, entries, now); !errors.Is(err, replay.ErrReplay) {
		t.Fatal(err)
	}
	requests, err := state.NewMemoryStore(state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pending := state.Pending{SP: "https://sp.test", IDP: "https://idp.test", RequestID: "request", RelayState: "consumer-relay-state", ACS: "https://sp.test/acs", IssuedAt: now, ExpiresAt: now.Add(time.Minute), BrowserSHA256: [32]byte{1}}
	if err := requests.Put(ctx, pending, now); err != nil {
		t.Fatal(err)
	}
	if found, err := requests.Get(ctx, pending.SP, pending.RelayState, now); err != nil || found.RequestID != pending.RequestID {
		t.Fatal(found, err)
	}
}

func TestSAMLWritersBoundWorkingStorage(t *testing.T) {
	const size = 1 << 20
	doc, err := document.Parse(t.Context(), []byte(`<r>`+strings.Repeat("x", size)+`</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	limits := binding.POSTLimits{MaxXMLBytes: 2 << 20, MaxFormBytes: 4 << 20}
	relay := "opaque +&"
	for _, operation := range []struct {
		name  string
		write func(context.Context, io.Writer) (int64, error)
	}{
		{"form", func(ctx context.Context, dst io.Writer) (int64, error) {
			return binding.WritePOST(ctx, dst, doc, binding.Request, &relay, limits)
		}},
		{"HTML", func(ctx context.Context, dst io.Writer) (int64, error) {
			return binding.WritePOSTForm(ctx, dst, "https://idp.example.test/sso", doc, binding.Request, &relay, limits)
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if allocated := allocatedDuring(t, func() error { _, err := operation.write(t.Context(), sha256.New()); return err }); allocated > 128<<10 {
				t.Fatalf("writer allocated %d bytes", allocated)
			}
			failure := errors.New("destination stopped")
			if allocated := allocatedDuring(t, func() error {
				n, err := operation.write(t.Context(), &prefixFailure{remaining: 128, failure: failure})
				if n != 128 || !errors.Is(err, failure) {
					return errors.New("early destination error lost")
				}
				return nil
			}); allocated > 128<<10 {
				t.Fatalf("early output allocated %d bytes", allocated)
			}
		})
	}
	form, err := binding.EncodePOST(t.Context(), doc, binding.Request, &relay, limits)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := url.ParseQuery(string(form))
	if err != nil {
		t.Fatal(err)
	}
	encoded := fields.Get(string(binding.Request))
	baseline := allocatedDuring(t, func() error {
		_, err := document.ParseReader(t.Context(), base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(encoded)), document.DefaultLimits())
		return err
	})
	allocated := allocatedDuring(t, func() error {
		result, err := binding.DecodePOSTReader(t.Context(), bytes.NewReader(form), binding.Request, limits)
		if err != nil {
			return err
		}
		if value, ok := result.RelayState(); !ok || value != relay {
			return errors.New("RelayState changed")
		}
		return nil
	})
	if allocated > baseline+256<<10 {
		t.Fatalf("POST parser allocated %d bytes beyond XML/Base64 parsing baseline %d", allocated-baseline, baseline)
	}
	// A valid XML field cannot hide duplicate fields at the end of the stream.
	if result, err := binding.DecodePOSTReader(t.Context(), io.MultiReader(bytes.NewReader(form), strings.NewReader("&RelayState=second")), binding.Request, limits); result != nil || err == nil {
		t.Fatal("trailing duplicate accepted", result, err)
	}
}

func TestMetadataReaderUsesXMLParserStorage(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	spec := metadata.EntityDescriptor{EntityID: "urn:stream:idp", ValidUntil: now.Add(time.Hour), IDP: &metadata.RoleDescriptor{Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPRedirect, Location: "https://idp.example.test/sso"}}}}}
	doc, err := metadata.Build(t.Context(), spec, now, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rootEnd := bytes.IndexByte(raw, '>') + 1
	source := string(raw[:rootEnd]) + "<!--" + strings.Repeat("x", 1<<20) + "-->" + string(raw[rootEnd:])
	baseline := allocatedDuring(t, func() error {
		_, err := document.ParseReader(t.Context(), strings.NewReader(source), document.DefaultLimits())
		return err
	})
	allocated := allocatedDuring(t, func() error {
		result, err := metadata.ParseTrustedReader(t.Context(), strings.NewReader(source), now, metadata.Options{})
		if err != nil {
			return err
		}
		_, err = result.Find("urn:stream:idp", now)
		return err
	})
	if allocated > baseline+256<<10 {
		t.Fatalf("metadata allocated %d bytes beyond XML parser baseline %d", allocated-baseline, baseline)
	}
}

func TestSAMLRedirectWorkingStorage(t *testing.T) {
	signer, _ := nativeIOSigner(t)
	options := binding.Options{SignatureMethod: xmldsig.ECDSASHA256, MaxQueryBytes: 4 << 20, MaxCompressedBytes: 2 << 20}
	source := `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol">` + strings.Repeat(`<v a="x">kept</v>`, 5000) + `</p:AuthnRequest>`
	doc, err := document.ParseReader(t.Context(), strings.NewReader(source), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	baseline := allocatedDuring(t, func() error {
		compressor, err := flate.NewWriter(io.Discard, flate.DefaultCompression)
		if err != nil {
			return err
		}
		_, writeErr := doc.WriteXML(t.Context(), compressor, len(source)+1024)
		return errors.Join(writeErr, compressor.Close())
	})
	allocated := allocatedDuring(t, func() error {
		_, err := binding.SignRedirect(t.Context(), doc, binding.Request, nil, signer, options)
		return err
	})
	t.Logf("Redirect signing: %d allocated, %d compression baseline", allocated, baseline)
	if allocated > baseline+(256<<10) {
		t.Fatal("Redirect cloned the source tree", allocated, baseline)
	}
	noise := make([]byte, 256<<10)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	source = `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol">` + base64.StdEncoding.EncodeToString(noise) + `</p:AuthnRequest>`
	doc, err = document.ParseReader(t.Context(), strings.NewReader(source), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	query, err := binding.SignRedirect(t.Context(), doc, binding.Request, nil, signer, options)
	if err != nil {
		t.Fatal(err)
	}
	params, err := url.ParseQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := base64.StdEncoding.DecodeString(params.Get(string(binding.Request)))
	if err != nil {
		t.Fatal(err)
	}
	baseline = allocatedDuring(t, func() error {
		inflater := flate.NewReader(bytes.NewReader(compressed))
		_, err := document.ParseReader(t.Context(), inflater, document.DefaultLimits())
		return errors.Join(err, inflater.Close())
	})
	allocated = allocatedDuring(t, func() error {
		result, err := binding.VerifyRedirect(t.Context(), query, signer.Public(), options)
		if err == nil && result.Kind() != binding.Request {
			return errors.New("redirect kind changed")
		}
		return err
	})
	t.Logf("Redirect verification: %d query bytes, %d allocated, %d XML/DEFLATE baseline", len(query), allocated, baseline)
	if allocated > baseline+(128<<10) {
		t.Fatal("Redirect retained decoded query/compressed/signing copies", allocated, baseline)
	}
	manyFields := strings.Repeat("x=1&", 256<<10)
	allocated = allocatedDuring(t, func() error {
		result, err := binding.VerifyRedirect(t.Context(), manyFields, signer.Public(), options)
		if result != nil || err == nil {
			return errors.New("ambiguous query accepted")
		}
		return nil
	})
	if allocated > 64<<10 {
		t.Fatal("invalid query allocated a complete field table", allocated)
	}
}

func TestMetadataCertificateWorkingStorage(t *testing.T) {
	signer, _ := nativeIOSigner(t)
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "padded metadata"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{7}, 24<<10)}}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]metadata.KeyDescriptor, 16)
	for i := range keys {
		keys[i] = metadata.KeyDescriptor{CertificateDER: certificate}
	}
	options := metadata.Options{MaxKeysPerRole: 16}
	spec := metadata.EntityDescriptor{EntityID: "urn:stream:certificates", ValidUntil: now.Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: keys, Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HTTPRedirect, Location: "https://idp.example.test/sso"}}}}}
	doc, err := metadata.Build(t.Context(), spec, now, options)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	baseline := allocatedDuring(t, func() error {
		_, err := document.ParseReader(t.Context(), bytes.NewReader(wire), document.DefaultLimits())
		return err
	})
	var snapshot *metadata.Snapshot
	allocated := allocatedDuring(t, func() error {
		var err error
		snapshot, err = metadata.ParseTrustedReader(t.Context(), bytes.NewReader(wire), now, options)
		return err
	})
	t.Logf("metadata: %d DER bytes, %d allocated, %d XML baseline", len(certificate)*len(keys), allocated, baseline)
	if allocated > baseline+uint64(len(certificate)*len(keys))+(192<<10) {
		t.Fatal("metadata copied complete encoded text or owned certificates", allocated, baseline)
	}
	entity, err := snapshot.Find(spec.EntityID, now)
	if err != nil {
		t.Fatal(err)
	}
	role, err := entity.Role(metadata.IdentityProvider, now)
	if err != nil {
		t.Fatal(err)
	}
	owned := role.Certificates("signing")
	if len(owned) != len(keys) {
		t.Fatal("certificate descriptors lost", len(owned))
	}
	owned[0][0] ^= 1
	if !bytes.Equal(role.Certificates("signing")[0], certificate) {
		t.Fatal("certificate getter changed immutable metadata")
	}
}

func TestSAMLWritersObserveCancellationOnFinalWrite(t *testing.T) {
	doc, err := document.ParseReader(t.Context(), strings.NewReader("<r/>"), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, write := range []func(context.Context, io.Writer) (int64, error){
		func(ctx context.Context, dst io.Writer) (int64, error) {
			return binding.WritePOST(ctx, dst, doc, binding.Request, nil, binding.POSTLimits{})
		},
		func(ctx context.Context, dst io.Writer) (int64, error) {
			return binding.WritePOSTForm(ctx, dst, "https://idp.example.test/sso", doc, binding.Request, nil, binding.POSTLimits{})
		},
	} {
		var expected bytes.Buffer
		if _, err := write(t.Context(), &expected); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		sink := &streamingSink{}
		sink.afterWrite = func() {
			if sink.bytes == expected.Len() {
				cancel()
			}
		}
		n, err := write(ctx, sink)
		cancel()
		if n != int64(expected.Len()) || !errors.Is(err, context.Canceled) {
			t.Fatal("last-write cancellation lost", n, err)
		}
	}
}
