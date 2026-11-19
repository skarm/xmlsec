//go:build interop

package interop_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const nameFresh = "fresh"

const uriAttachment = "urn:attachment"

const uriManifest = "urn:manifest"

func TestXMLSecExternalManifestURIContext(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	key := generateKey(t, fixture.work, nameRSASHA256)
	_, privateArg := nativeKeyArgs(nameRSA, "")

	const resourceURI = "urn:external#manifest"

	payload := []byte("external fragment payload")
	digest := sha256.Sum256(payload)
	manifestXML := `<ds:Manifest xmlns:ds="` + ds + `" Id="manifest"><ds:Reference URI="urn:attachment"><ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `"/><ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue></ds:Reference></ds:Manifest>`
	manifest := xmlDoc(t, []byte(manifestXML))

	var selectedXML bytes.Buffer
	if err := c14n.WriteElement(t.Context(), &selectedXML, manifest.Root(), c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
		t.Fatal(err)
	}

	// The native engine receives the original XML resource and performs its own
	// fragment selection. The Go resolver supplies the identified subresource
	// as octets, as required by the external-URI processing contract.
	nativeManifest := write(t, filepath.Join(fixture.work, "fragment-manifest.xml"), []byte(`<!DOCTYPE ds:Manifest [<!ATTLIST ds:Manifest Id ID #REQUIRED>]>`+manifestXML))
	payloadPath := write(t, filepath.Join(fixture.work, "fragment-payload.bin"), payload)
	opt := xmldsig.SignatureOptions{
		ExpectedURIs: []string{resourceURI},
		Manifests:    xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true},
		External: &xmldsig.ExternalReferences{AllowedURIs: []string{resourceURI, uriAttachment}, Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			switch uri {
			case resourceURI:
				return io.NopCloser(bytes.NewReader(selectedXML.Bytes())), ctx.Err()
			case uriAttachment:
				return os.Open(payloadPath)
			default:
				return nil, xmldsig.ErrPolicy
			}
		})},
	}

	draft, selectedSignature, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{
		SignatureMethod: key.method,
		References:      []xmldsig.ReferenceTemplate{{URI: resourceURI, Type: xmldsig.ManifestType, Transforms: []reference.Transform{{Algorithm: c14n.Canonical10}}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	template := write(t, filepath.Join(fixture.work, "fragment-template.xml"), xmlBytes(t, draft))

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selectedSignature, key.signer, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	ours := write(t, filepath.Join(fixture.work, "fragment-go.xml"), xmlBytes(t, signed))
	nativeArgs := []string{"--url-map:urn:external", nativeManifest, "--url-map:urn:attachment", payloadPath}
	native(t, fixture, true, nameVerify, append(append([]string{flagPublicKeyPEM, key.public}, nativeArgs...), ours)...)
	theirs := filepath.Join(fixture.work, "fragment-native.xml")
	native(t, fixture, true, nameSign, append(append([]string{privateArg, key.private, flagNativeOutput, theirs}, nativeArgs...), template)...)
	nativeDoc := xmlDoc(t, read(t, theirs))

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, nativeDoc.Root(), key.signer.Public(), opt)
	if err != nil || result == nil || len(result.Manifests()) != 1 || report.ManifestValidation != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	write(t, payloadPath, []byte("changed fragment payload"))

	result, report, err = xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, nativeDoc.Root(), key.signer.Public(), opt)
	// Verification reports retain diagnostics on failure.
	//noinspection GoDfaErrorMayBeNotNil
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || report.References[0].Status != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	// xmlsec1 validates this external Manifest's incoming Reference, but does
	// not recursively discover its children. Record that boundary explicitly.
	native(t, fixture, true, nameVerify, append(append([]string{flagPublicKeyPEM, key.public}, nativeArgs...), ours)...)

	changedDigest := sha256.Sum256([]byte("different nested digest"))
	changedManifest := strings.Replace(manifestXML, base64.StdEncoding.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(changedDigest[:]), 1)
	write(t, nativeManifest, []byte(`<!DOCTYPE ds:Manifest [<!ATTLIST ds:Manifest Id ID #REQUIRED>]>`+changedManifest))
	native(t, fixture, false, nameVerify, append(append([]string{flagPublicKeyPEM, key.public}, nativeArgs...), ours)...)
}

func TestXMLSecRelativeURIContext(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	key := generateKey(t, fixture.work, nameRSASHA256)
	_, privateArg := nativeKeyArgs(nameRSA, "")

	const resolved = "https://example.test/payload.bin?version=1"

	payload := write(t, filepath.Join(fixture.work, "relative-payload.bin"), []byte("relative resource"))
	input := xmlDoc(t, []byte(`<message xml:base="https://example.test/packages/"/>`))

	draft, selectedSignature, err := xmldsig.BuildTemplate(t.Context(), input, input.Root(), xmldsig.SignatureTemplate{SignatureMethod: key.method, References: []xmldsig.ReferenceTemplate{{URI: "../payload.bin?version=1"}}})
	if err != nil {
		t.Fatal(err)
	}

	opt := xmldsig.SignatureOptions{ExpectedURIs: []string{"../payload.bin?version=1"}, External: &xmldsig.ExternalReferences{BaseURI: "https://example.test/messages/signature.xml", AllowedURIs: []string{resolved}, Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if uri != resolved {
			return nil, xmldsig.ErrPolicy
		}

		return os.Open(payload)
	})}}

	signed, err := xmldsig.SignTemplate(t.Context(), draft, selectedSignature, key.signer, xmldsig.TemplateSignOptions{Validation: opt})
	if err != nil {
		t.Fatal(err)
	}

	ours := write(t, filepath.Join(fixture.work, "relative-go.xml"), xmlBytes(t, signed))
	args := []string{"--url-map:" + resolved, payload}
	// xmlsec1's CLI opens the literal relative URI in this profile instead of
	// applying inherited xml:base. Keep that difference visible, then exchange
	// identical octets through an explicit literal mapping in the native adapter.
	native(t, fixture, false, nameVerify, append(append([]string{flagPublicKeyPEM, key.public}, args...), ours)...)
	args = []string{"--url-map:../payload.bin?version=1", payload}
	native(t, fixture, true, nameVerify, append(append([]string{flagPublicKeyPEM, key.public}, args...), ours)...)
	template := write(t, filepath.Join(fixture.work, "relative-template.xml"), xmlBytes(t, draft))
	theirs := filepath.Join(fixture.work, "relative-native.xml")
	native(t, fixture, true, nameSign, append(append([]string{privateArg, key.private, flagNativeOutput, theirs}, args...), template)...)

	nativeDoc := xmlDoc(t, read(t, theirs))
	if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, xmldsig.Signatures(nativeDoc)[0], key.signer.Public(), opt); err != nil || result == nil || result.References()[0].ResourceURI() != resolved {
		t.Fatal(result, err)
	}

	write(t, payload, []byte("changed relative resource"))
	native(t, fixture, false, nameVerify, append(append([]string{flagPublicKeyPEM, key.public}, args...), ours)...)

	if result, _, err := xmldsig.VerifySignatureDetailed(t.Context(), nativeDoc, xmldsig.Signatures(nativeDoc)[0], key.signer.Public(), opt); !errors.Is(err, xmldsig.ErrDigest) || result != nil {
		t.Fatal(result, err)
	}
}

func TestExternalManifestInterop(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")
	key := generateKey(t, fixture.work, nameRSASHA256)
	theirs := filepath.Join(fixture.work, "jdk-external.xml")
	manifest := filepath.Join(fixture.work, "external-manifest.xml")
	payload := write(t, filepath.Join(fixture.work, "external-payload.bin"), []byte("external Manifest payload\x00\xff"))
	java(t, fixture, "ManifestOracle", "sign-external", key.private, theirs, manifest, payload, key.method)
	verifyJava(t, java(t, fixture, "ManifestOracle", "verify-external", key.public, theirs, manifest, payload), true)
	paths := map[string]string{uriManifest: manifest, uriAttachment: payload}
	options := xmldsig.SignatureOptions{
		Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, AllowExternal: true}, ExpectedURIs: []string{uriManifest},
		External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriManifest, uriAttachment}, Resolver: xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			path, ok := paths[uri]
			if !ok {
				return nil, xmldsig.ErrPolicy
			}

			return os.Open(path)
		})},
	}

	doc, err := document.Parse(t.Context(), read(t, theirs), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), doc, doc.Root(), key.signer.Public(), options)
	if err != nil || result == nil || len(result.Manifests()) != 1 || len(result.Manifests()[0].References()) != 1 || report.ManifestValidation != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	resources := write(t, filepath.Join(fixture.work, "resources.json"), []byte(`[{"uri":"urn:manifest","path":"external-manifest.xml"},{"uri":"urn:attachment","path":"external-payload.bin"}]`))
	cli := binary(t, fixture, "xmlsec")
	cliReport, _ := command(t, fixture, true, nil, cli, "verify-core", "-in", theirs, "-key", key.public, "-signature-index", "0", "-manifests", "recursive-external", "-resources", resources, "-expect-uri", uriManifest)
	verifyReport(t, cliReport, true)

	draft := xmlDoc(t, read(t, theirs))
	for _, value := range append(nodes(tree.Root(draft), ds, "SignatureValue"), nodes(tree.Root(draft), ds, "DigestValue")...) {
		value.Children = nil
	}

	template, err := document.Parse(t.Context(), xmlBytes(t, draft), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xmldsig.SignTemplate(t.Context(), template, template.Root(), key.signer, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := signed.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	ours := write(t, filepath.Join(fixture.work, "go-external.xml"), raw)
	verifyJava(t, java(t, fixture, "ManifestOracle", "verify-external", key.public, ours, manifest, payload), true)
	write(t, payload, []byte("changed external payload"))

	result, report, err = xmldsig.VerifySignatureDetailed(t.Context(), signed, signed.Root(), key.signer.Public(), options)
	// Verification reports retain diagnostics on failure.
	//noinspection GoDfaErrorMayBeNotNil
	if !errors.Is(err, xmldsig.ErrDigest) || result != nil || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid {
		t.Fatal(result, report, err)
	}

	verifyJava(t, java(t, fixture, "ManifestOracle", "verify-external", key.public, ours, manifest, payload), false)
}

func TestManifestProfiles(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	cli := binary(t, fixture, "xmlsec")
	attachment := write(t, filepath.Join(dir, "attachment.bin"), []byte("external bytes\x00\xff"))

	resources := write(t, filepath.Join(dir, "resources.json"), []byte(`[{"uri":"urn:attachment","path":"attachment.bin"}]`))
	for _, name := range []string{nameRSASHA256, nameRSASHA384, nameRSASHA512, nameECDSASHA256} {
		key := generateKey(t, dir, name)
		if strings.HasPrefix(name, nameRSA) {
			key.method = pssURI + strings.TrimPrefix(name, "rsa-") + "-rsa-MGF1"
		}

		theirs, ours, bad := filepath.Join(dir, "jdk.xml"), filepath.Join(dir, "go.xml"), filepath.Join(dir, "bad.xml")
		java(t, fixture, "ManifestOracle", nameSign, key.private, theirs, attachment, key.method)

		draft := xmlDoc(t, read(t, theirs))
		for _, value := range append(nodes(tree.Root(draft), ds, "SignatureValue"), nodes(tree.Root(draft), ds, "DigestValue")...) {
			value.Children = nil
		}

		template := write(t, filepath.Join(dir, "manifest-template.xml"), xmlBytes(t, draft))
		opts := []string{"-signature-index", "0", "-modern-algorithms", "-manifests", "recursive", "-resources", resources, "-expect-uri", "#top"}
		raw, _ := command(t, fixture, true, nil, cli, append([]string{"sign-template", flagIn, template, flagOut, ours, flagKey, key.private}, opts...)...)
		_ = raw

		verifyJava(t, java(t, fixture, "ManifestOracle", nameVerify, key.public, ours, attachment), true)
		raw, _ = command(t, fixture, true, nil, cli, append([]string{"verify-core", flagIn, theirs, flagKey, key.public}, opts...)...)
		verifyReport(t, raw, true)
		java(t, fixture, "ManifestOracle", "sign-bad", key.private, bad, attachment, key.method)

		v := verifyJava(t, java(t, fixture, "ManifestOracle", nameVerify, key.public, bad, attachment), false)
		if !slices.Equal(v.References, []bool{true}) {
			t.Fatalf("JDK direct Reference check in nested control: %v", v.References)
		}

		raw, _ = command(t, fixture, false, nil, cli, append([]string{"verify-core", flagIn, bad, flagKey, key.public}, opts...)...)

		r := verifyReport(t, raw, false)
		if r.FailureStage != "manifests" || r.ManifestValidation != "invalid" || len(r.References) != 1 || r.References[0].Status != nameValid {
			t.Fatalf("Go nested failure report: %s", raw)
		}
	}
	// Independently signed EdDSA and nested controls also run in the public
	// corpus without an external runtime.
	command(t, fixture, true, nil, "go", "test", "-count=1", "./tests/integration/xmldsig")
}

func referenceInput(t *testing.T, fixture *interopFixture, d *tree.Document, sig, ref *tree.Node, attachment []byte) []byte {
	t.Helper()

	uri := attr(ref, "URI")

	var (
		target *tree.Node
		octets []byte
	)
	if uri == uriAttachment {
		octets = bytes.Clone(attachment)
	} else if uri == "" {
		target = tree.Root(d)
	} else if strings.HasPrefix(uri, "#") {
		ident := strings.TrimPrefix(uri, "#")

		var walk func(*tree.Node)

		walk = func(n *tree.Node) { testreferenceInputCase(n, &ident, &target, &t, &walk) }
		walk(tree.Root(d))

		if target == nil {
			t.Fatalf("unresolved ID %s", uri)
		}
	} else {
		t.Fatalf("unallowlisted test URI %s", uri)
	}

	var canonical string

	enveloped := false

	for _, tr := range nodes(ref, ds, "Transform") {
		alg := attr(tr, "Algorithm")
		if alg == ds+"enveloped-signature" {
			enveloped = true
		} else if alg == ds+"base64" {
			if target != nil {
				octets = []byte(text(target))
				target = nil
			}

			octets = decode64(t, string(octets))
		} else if strings.HasPrefix(alg, exc) || strings.HasPrefix(alg, c10) || strings.HasPrefix(alg, c11) {
			canonical = alg
		} else {
			t.Fatalf("unsupported fixed profile transform %s", alg)
		}
	}

	if target == nil {
		if canonical != "" {
			doc := xmlDoc(t, octets)
			return externalCanonical(t, fixture, doc, nil, canonical)
		}

		return octets
	}

	if canonical == "" {
		canonical = c10
	}
	// Bare ID references strip comments before transforms, even WithComments.
	removed := make(map[*tree.Node][]*tree.Node)

	var prune func(*tree.Node)

	prune = func(n *tree.Node) { testreferenceInputCase2(n, &sig, &enveloped, &prune, &removed) }
	prune(target)

	defer func() {
		for n, children := range removed {
			n.Children = children
		}
	}()

	return externalCanonical(t, fixture, d, target, canonical)
}

func checkReferences(t *testing.T, fixture *interopFixture, d *tree.Document, sig *tree.Node) bool {
	t.Helper()

	refs := nodes(sig, ds, "Reference")
	if len(refs) == 0 {
		return false
	}

	valid := true

	for _, ref := range refs {
		alg := attr(one(t, ref, ds, "DigestMethod"), "Algorithm")

		var bits int

		switch alg {
		case enc + nameSHA256:
			bits = 256
		case more + "sha384":
			bits = 384
		case enc + "sha512":
			bits = 512
		default:
			t.Fatalf("unsupported digest method for reference oracle: %q", alg)
		}

		input := referenceInput(t, fixture, d, sig, ref, nil)

		digest := hashBytes(bits, input)
		if !bytes.Equal(digest, decode64(t, text(one(t, ref, ds, "DigestValue")))) {
			valid = false
		}
	}

	return valid
}

func TestCheckReferencesRequiresReferences(t *testing.T) {
	doc := xmlDoc(t, []byte(`<Signature xmlns="`+ds+`"><SignedInfo/></Signature>`))
	if checkReferences(t, nil, doc, tree.Root(doc)) {
		t.Fatal("reference checks succeeded with no references")
	}
}

func testreferenceInputCase(n *tree.Node, ident *string, target **tree.Node, t **testing.T, walk *func(*tree.Node)) {
	if attr(n, "Id") == (*ident) || attr(n, "ID") == (*ident) {
		if (*target) != nil {
			(*t).Fatal("duplicate ID")
		}

		(*target) = n
	}

	for _, c := range n.Children {
		(*walk)(c)
	}
}

func testreferenceInputCase2(n *tree.Node, sig **tree.Node, enveloped *bool, prune *func(*tree.Node), removed *map[*tree.Node][]*tree.Node) {
	original := n.Children

	var kept []*tree.Node

	for _, c := range original {
		if c == (*sig) && (*enveloped) || c.Kind == tree.CommentNode {
			continue
		}

		kept = append(kept, c)
		(*prune)(c)
	}

	(*removed)[n] = original
	n.Children = kept
}

func (r *dssReports) check(at time.Time, want dssExpectation, anchorID string) error {
	if want.BestSignatureTime.IsZero() || !r.DiagnosticData.ValidationDate.Equal(at) || !r.SimpleReport.ValidationTime.Equal(at) {
		return errors.New("missing/mismatched explicit validation or best-signature time")
	}

	if r.SimpleReport.Count != 1 || len(r.SimpleReport.Tokens) != 1 || len(r.DiagnosticData.Signatures) != 1 || r.DetailedReport == nil || len(r.DetailedReport.Tokens) != 1 {
		return errors.New("expected one signature in all three reports")
	}

	summary := r.SimpleReport.Tokens[0].Signature
	diagnostic := r.DiagnosticData.Signatures[0]
	if summary == nil || summary.ID == "" || summary.ID != diagnostic.ID || summary.Indication != want.Indication || summary.SubIndication != want.SubIndication || !summary.BestSignatureTime.Equal(want.BestSignatureTime) {
		return errors.New("signature identity, exact indication/reason or best-signature-time mismatch")
	}
	detailed := r.DetailedReport.Tokens[0].Signature
	if detailed == nil || detailed.ID != summary.ID || !r.DetailedReport.ValidationTime.Equal(at) {
		return errors.New("detailed report belongs to a different signature or validation time")
	}
	trustedAnchor := false
	for _, certificate := range summary.CertificateChain.Certificates {
		if certificate.ID == anchorID && dssTrue(certificate.Trusted) {
			trustedAnchor = true
		}
	}
	if !trustedAnchor {
		return errors.New("DSS report does not bind the configured trust-anchor certificate")
	}

	wantValid := 0
	if want.Indication == "TOTAL_PASSED" {
		wantValid = 1
	}

	if r.SimpleReport.ValidCount != wantValid || !dssTrue(diagnostic.StructuralValidation.Valid) || !dssTrue(diagnostic.BasicSignature.Intact) || !dssTrue(diagnostic.BasicSignature.Valid) || len(diagnostic.DigestMatchers) < 2 {
		return errors.New("pair does not retain an intact, structurally valid XAdES signature")
	}

	for _, matcher := range diagnostic.DigestMatchers {
		if !dssTrue(matcher.Found) || !dssTrue(matcher.Intact) {
			return errors.New("missing or damaged signed Reference in historical pair")
		}
	}

	return nil
}

// These pairs exercise archive recovery after both basic and LT processing
// remain indeterminate. A currently valid signature is a different control.
func (r *dssReports) checkArchiveRecovery(success bool) error {
	if r.DetailedReport == nil || len(r.DetailedReport.Tokens) != 1 || r.DetailedReport.Tokens[0].Signature == nil {
		return errors.New("missing detailed signature recovery report")
	}
	detail := r.DetailedReport.Tokens[0].Signature
	if detail.Basic.Conclusion.Indication != "INDETERMINATE" || detail.LongTerm.Conclusion.Indication != "INDETERMINATE" {
		return errors.New("fixture did not require historical archive recovery")
	}
	archive := detail.Archival.Conclusion.Indication
	if success && archive != "PASSED" || !success && archive != "INDETERMINATE" {
		return errors.New("unexpected archive validation process result")
	}

	var signatureTime, archiveTime bool
	for _, stamp := range r.DiagnosticData.Timestamps {
		signatureTime = signatureTime || stamp.Type == "SIGNATURE_TIMESTAMP"
		archiveTime = archiveTime || stamp.Type == "ARCHIVE_TIMESTAMP"
		if !dssTrue(stamp.BasicSignature.Intact) || !dssTrue(stamp.BasicSignature.Valid) || len(stamp.DigestMatchers) == 0 {
			return errors.New("invalid timestamp cryptographic diagnostic")
		}
		for _, match := range stamp.DigestMatchers {
			if !dssTrue(match.Found) || !dssTrue(match.Intact) {
				return errors.New("timestamp imprint does not match its covered objects")
			}
		}
	}
	if !signatureTime || success && !archiveTime {
		return errors.New("required historical timestamps are absent")
	}
	if success {
		accepted := make(map[string]struct{}, len(detail.Timestamps))
		for _, stamp := range detail.Timestamps {
			if _, exists := accepted[stamp.ID]; stamp.ID == "" || exists || stamp.Conclusion.Indication != "PASSED" {
				return errors.New("an old timestamp was ignored instead of historically validated")
			}
			accepted[stamp.ID] = struct{}{}
		}
		if len(accepted) != len(r.DiagnosticData.Timestamps) {
			return errors.New("missing detailed timestamp trust results")
		}
		for _, stamp := range r.DiagnosticData.Timestamps {
			if _, exists := accepted[stamp.ID]; !exists {
				return errors.New("detailed timestamp result has a different token identity")
			}
		}
	}
	return nil
}
