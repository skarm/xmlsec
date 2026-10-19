package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/xmldsig"
)

const flagPreserve = "-preserve"

func TestCoreCLI(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")

	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}

	if e = os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der}), 0o600); e != nil {
		t.Fatal(e)
	}

	der, e = x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		t.Fatal(e)
	}

	if e = os.WriteFile(public, pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: der}), 0o600); e != nil {
		t.Fatal(e)
	}

	sig := fmt.Sprintf(`<ds:Signature xmlns:ds="%s" Id="s0"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/><ds:Reference URI="#data"><ds:Transforms><ds:Transform Algorithm="%s"/></ds:Transforms><ds:DigestMethod Algorithm="%s"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>`, xmldsig.Namespace, c14n.Exclusive, xmldsig.ECDSASHA256, c14n.Exclusive, xmldsig.SHA256)
	raw := `<root><item ID="data">payload</item>` + sig + strings.Replace(sig, `Id="s0"`, `Id="s1"`, 1) + `</root>`

	var signed, stderr bytes.Buffer
	if e := run(ctx, []string{nameSignTemplate, flagKey, private, flagSignatureIndex, "0", "-expect-uri", "#data"}, strings.NewReader(raw), &signed, &stderr); e != nil {
		t.Fatal(e)
	}

	first := signed.String()
	signed.Reset()

	if e := run(ctx, []string{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "0=" + public}, strings.NewReader(first), &signed, &stderr); e != nil {
		t.Fatal(e)
	}

	both := signed.String()

	for _, i := range []string{"0", "1"} {
		var out bytes.Buffer
		if e := run(ctx, []string{nameVerifyCore, flagKey, public, flagSignatureIndex, i, "-expect-uri", "#data"}, strings.NewReader(both), &out, &stderr); e != nil {
			t.Fatal(e)
		}

		var report xmldsig.VerificationReport
		if e := json.Unmarshal(coreVerificationChecks(t, out.Bytes()), &report); e != nil {
			t.Fatal(e)
		}

		if report.Status != xmldsig.Valid || report.SignatureValue != xmldsig.Valid {
			t.Fatal(out.String())
		}
	}

	t.Run("failure-has-json", func(t *testing.T) {
		var out bytes.Buffer

		e := run(ctx, []string{nameVerifyCore, flagKey, public, flagSignatureIndex, "0", "-require-root"}, strings.NewReader(both), &out, &stderr)
		if e == nil {
			t.Fatal("unsigned root accepted")
		}

		var report xmldsig.VerificationReport
		if e := json.Unmarshal(coreVerificationChecks(t, out.Bytes()), &report); e != nil {
			t.Fatal(e)
		}

		if report.Status != xmldsig.Disallowed || report.SignatureValue != xmldsig.Valid || report.FailureStage != "coverage" {
			t.Fatal(report)
		}
	})

	for _, args := range [][]string{
		{nameVerifyCore},
		{nameVerifyCore, flagKey, public},
		{nameVerifyCore, flagKey, public, flagSignatureIndex, "99"},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1"},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "bad"},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "9=" + public},
		{nameSignTemplate, flagKey, private, flagSignatureIndex, "1", flagPreserve, "0=missing-file"},
		{nameVerifyCore, flagKey, public, flagSignatureIndex, "0", nameExtra},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			if e := run(ctx, args, strings.NewReader(first), &out, &stderr); e == nil {
				t.Fatal("invalid arguments accepted")
			}
		})
	}

	for _, cmd := range []string{nameSignTemplate, nameVerifyCore} {
		if e := run(ctx, []string{cmd, "-h"}, nil, &signed, &stderr); e != nil {
			t.Fatal(e)
		}
	}
}
