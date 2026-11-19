package xmldsig_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestSignTemplateRejectsInvalidPreservationBeforeSigning(t *testing.T) {
	t.Parallel()

	tmpl := func(id string) string {
		return coreTemplate(id, xmldsig.ECDSASHA256, c14n.Exclusive, coreRef("#data", c14n.Exclusive), "")
	}
	source := coreParse(t, `<r><v ID="data">payload</v>`+tmpl("first")+tmpl("second")+tmpl("third")+`</r>`)
	key := coreEC(t)
	signed, err := xmldsig.SignTemplate(t.Context(), source, xmldsig.Signatures(source)[0], key, xmldsig.TemplateSignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handles := xmldsig.Signatures(signed)
	if len(handles) != 3 {
		t.Fatalf("signature handles = %d, want three", len(handles))
	}
	before := coreXML(t, signed)
	preserve := xmldsig.SignatureRequirement{Signature: handles[0], PublicKey: key.Public()}
	tooMany := make([]xmldsig.SignatureRequirement, 65)
	for _, tc := range []struct {
		name, detail string
		requirements []xmldsig.SignatureRequirement
	}{
		{"too_many_requirements", "preservation count", tooMany},
		{"duplicate_signature", "duplicate preservation selection", []xmldsig.SignatureRequirement{preserve, preserve}},
		{"selected_signature", "invalid preservation selection", []xmldsig.SignatureRequirement{{Signature: handles[1], PublicKey: key.Public()}}},
		{"foreign_signature", "invalid preservation selection", []xmldsig.SignatureRequirement{{Signature: xmldsig.Signatures(source)[0], PublicKey: key.Public()}}},
		{"unsigned_template", "cannot preserve an unsigned template", []xmldsig.SignatureRequirement{preserve, {Signature: handles[2], PublicKey: key.Public()}}},
		{"two_credentials", "two credential types", []xmldsig.SignatureRequirement{{Signature: handles[0], PublicKey: key.Public(), SharedSecret: make([]byte, 32)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signer := &coreCountSigner{Signer: key}
			got, err := xmldsig.SignTemplate(t.Context(), signed, handles[1], signer, xmldsig.TemplateSignOptions{Preserve: tc.requirements})
			if got != nil || !errors.Is(err, xmldsig.ErrPolicy) || !strings.Contains(err.Error(), tc.detail) || signer.calls != 0 {
				t.Errorf("SignTemplate = (result present: %t, %v, signer calls: %d), want ErrPolicy for %q before signing", got != nil, err, signer.calls, tc.detail)
			}
			if coreXML(t, signed) != before {
				t.Error("preservation refusal changed the source document")
			}
		})
	}
}

func TestSignTemplateRejectsCanceledContextAndNilSigner(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	signer := &coreCountSigner{Signer: coreEC(t)}
	if got, err := xmldsig.SignTemplate(ctx, nil, document.Element{}, signer, xmldsig.TemplateSignOptions{}); got != nil || !errors.Is(err, context.Canceled) || signer.calls != 0 {
		t.Errorf("canceled SignTemplate = (result present: %t, %v, signer calls: %d), want context.Canceled before signing", got != nil, err, signer.calls)
	}
	if got, err := xmldsig.SignTemplate(t.Context(), nil, document.Element{}, nil, xmldsig.TemplateSignOptions{}); got != nil || !errors.Is(err, xmldsig.ErrKey) {
		t.Errorf("SignTemplate without signer = (result present: %t, %v), want ErrKey", got != nil, err)
	}
}

func TestTemplateInScopedDocument(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const input = `<outer xmlns:p="urn:record"><record><p:data ID="data">payload</p:data></record></outer>`
	envelope := coreParse(t, input)
	record, err := tree.ScopeDocument(envelope, envelope.Root().Children()[0])
	if err != nil {
		t.Fatal(err)
	}

	spec := xmldsig.SignatureTemplate{
		SignatureMethod: xmldsig.ECDSASHA256,
		References:      []xmldsig.ReferenceTemplate{{URI: "#data", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}},
	}
	draft, sig, err := xmldsig.BuildTemplate(ctx, record, record.Root(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.Same(draft.Root().Children()[1]) {
		t.Fatal("template handle did not identify the inserted scoped signature")
	}

	key := coreEC(t)
	options := xmldsig.SignatureOptions{RequiredElements: []document.Element{draft.Root().Children()[0]}}
	signed, err := xmldsig.SignTemplate(ctx, draft, sig, key, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}
	children := signed.Root().Children()
	options.RequiredElements = []document.Element{children[0]}
	verified, err := xmldsig.VerifySignature(ctx, signed, children[1], key.Public(), options)
	if err != nil || !verified.CoversElement(children[0]) || children[0].Name().Space != "urn:record" {
		t.Fatalf("scoped signature or inherited namespace was lost: %v", err)
	}
	if len(record.Root().Children()) != 1 || len(envelope.Root().Children()[0].Children()) != 1 {
		t.Fatal("template modified the original record or envelope")
	}
}
