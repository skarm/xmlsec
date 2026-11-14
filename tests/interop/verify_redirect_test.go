//go:build interop

package interop_test

import (
	"bytes"
	"compress/flate"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

type redirectProfileCase struct {
	name string
	hash string
}

type redirectSignedQuery struct {
	parts     []string
	signature []byte
}

func TestRedirectProfiles(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	request := write(t, filepath.Join(dir, "request.xml"), []byte(`<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="request-1" Version="2.0" IssueInstant="2026-10-07T12:00:00Z"/>`))
	relay := "state/ü?x=1&y=two"

	cases := []redirectProfileCase{
		{nameRSASHA256, nameSHA256},
		{nameRSASHA384, "sha384"},
		{nameRSASHA512, "sha512"},
		{nameECDSASHA256, nameSHA256},
		{nameEd25519, nameSHA256},
	}
	for _, scenario := range cases {
		key := generateKey(t, dir, scenario.name)
		checkRedirectExchange(t, fixture, dir, request, relay, scenario, key)
	}
}

func checkRedirectExchange(t *testing.T, fixture *interopFixture, dir, request, relay string, scenario redirectProfileCase, key testKey) {
	t.Helper()

	task := map[string]any{nameMode: "redirect-sign", nameKey: key.private, nameInput: request, nameMethod: key.method, "Relay": relay}
	result := probe(t, fixture, "nextprobe", task, true)

	var query string
	decode(t, result[nameText], &query)

	signed := decodeRedirectSignedQuery(t, fixture, query, request)
	message := write(t, filepath.Join(dir, "query-message"), []byte(strings.Join(signed.parts, "&")))
	signature := write(t, filepath.Join(dir, "query-signature"), signed.signature)
	checkRedirectOpenSSL(t, fixture, scenario, key, message, signature, signed.signature)

	value := read(t, signature)
	if strings.HasPrefix(scenario.name, "ecdsa") {
		value = ecdsaRaw(t, value, 32)
	}

	reverse := strings.Join(signed.parts, "&") + "&Signature=" + url.QueryEscape(base64String(value))
	path := write(t, filepath.Join(dir, "query.txt"), []byte(reverse))
	verify := map[string]any{nameMode: "redirect-verify", nameKey: key.public, nameInput: path}
	probe(t, fixture, "nextprobe", verify, true)
	write(t, path, []byte(reverse+"&"+signed.parts[0]))
	probe(t, fixture, "nextprobe", verify, false)
}

func decodeRedirectSignedQuery(t *testing.T, fixture *interopFixture, query, request string) redirectSignedQuery {
	t.Helper()

	var signed redirectSignedQuery

	for _, part := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(part, "=")
		if key == "Signature" {
			raw, err := url.QueryUnescape(value)
			if err != nil {
				t.Fatal(err)
			}

			signed.signature = decode64(t, raw)
		} else {
			signed.parts = append(signed.parts, part)

			if key == "SAMLRequest" {
				checkRedirectRequest(t, fixture, value, request)
			}
		}
	}

	return signed
}

func checkRedirectRequest(t *testing.T, fixture *interopFixture, value, request string) {
	t.Helper()

	raw, err := url.QueryUnescape(value)
	if err != nil {
		t.Fatal(err)
	}

	compressed := decode64(t, raw)
	r := flate.NewReader(bytes.NewReader(compressed))

	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	r.Close()
	equalXML(t, fixture, body, read(t, request))
}

func checkRedirectOpenSSL(t *testing.T, fixture *interopFixture, scenario redirectProfileCase, key testKey, message, signature string, value []byte) {
	t.Helper()

	if scenario.name == nameEd25519 {
		command(t, fixture, true, nil, "openssl", "pkeyutl", flagVerify, "-pubin", flagInkey, key.public, "-rawin", flagIn, message, "-sigfile", signature)
		command(t, fixture, true, nil, "openssl", "pkeyutl", "-sign", flagInkey, key.private, "-rawin", flagIn, message, flagOut, signature)

		return
	}

	if strings.HasPrefix(scenario.name, "ecdsa") {
		write(t, signature, ecdsaDER(t, value))
	}

	command(t, fixture, true, nil, "openssl", "dgst", "-"+scenario.hash, flagVerify, key.public, "-signature", signature, message)
	command(t, fixture, true, nil, "openssl", "dgst", "-"+scenario.hash, "-sign", key.private, flagOut, signature, message)
}
