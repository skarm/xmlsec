package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/xmldsig"
)

func sourceMap(resources map[string][]byte) xmldsig.Resolver {
	return xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		data, ok := resources[uri]
		if !ok {
			return nil, fmt.Errorf("resource not allowed: %s", uri)
		}

		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

func keySelector(t testing.TB, expected crypto.PublicKey) xmldsig.TrustedKeySelector {
	t.Helper()

	spki, e := x509.MarshalPKIXPublicKey(expected)
	if e != nil {
		t.Fatal(e)
	}

	pin := sha256.Sum256(spki)

	return func(ctx context.Context, r *keyinfo.Result) (int, error) {
		if e := ctx.Err(); e != nil {
			return -1, e
		}

		for i, c := range r.Candidates() {
			if sha256.Sum256(c.SPKI()) == pin {
				return i, nil
			}
		}

		return -1, errors.New("expected partner key not found")
	}
}
