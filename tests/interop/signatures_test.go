//go:build interop

package interop_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	nameEnveloping = "enveloping"
	nameMulti      = "multi"
)

func TestCoreSignatures(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")
	coreSignatures(t, fixture, false)
}

func TestXMLSecSignatures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "xmlsec")
	checkXMLSec(t, fixture)
	coreSignatures(t, fixture, true)
}

func checkXMLSec(t *testing.T, fixture *interopFixture) {
	t.Helper()
	version, _ := command(t, fixture, true, nil, xmlsecExecutable(), "--version")
	t.Log(strings.TrimSpace(string(version)))

	transforms, _ := command(t, fixture, true, nil, xmlsecExecutable(), "--list-transforms")
	for _, name := range []string{"eddsa-ed25519", "rsa-pss-sha256", "aes128-gcm", "kw-aes256", "xpath2"} {
		if !bytes.Contains(transforms, []byte(`"`+name+`"`)) {
			t.Fatalf("xmlsec1 lacks %s", name)
		}
	}
}

func TestDetachedSignatures(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	cli := binary(t, fixture, "xmlsec")
	// Reuse immutable public resources; signing keys are fresh for every run.
	resourceDir := filepath.Join(fixture.root, "testdata/detached")
	manifest := filepath.Join(resourceDir, "resources.json")

	var entries []struct {
		URI        string `json:"uri"`
		Path       string `json:"path"`
		Digest     string `json:"digest_method"`
		Transforms []struct {
			Algorithm string `json:"algorithm"`
		} `json:"transforms"`
	}
	decode(t, read(t, manifest), &entries)

	signResources := make([]string, 0, 4*len(entries))
	verifyResources := make([]string, 0, 4*len(entries))
	allowlist := make([]map[string]string, 0, len(entries))

	for _, e := range entries {
		path := filepath.Join(resourceDir, e.Path)

		var transforms []string
		for _, tr := range e.Transforms {
			transforms = append(transforms, tr.Algorithm)
		}

		chain := strings.Join(transforms, "|")
		if chain == "" {
			chain = "-"
		}

		signResources = append(signResources, e.URI, path, e.Digest, chain)
		verifyResources = append(verifyResources, e.URI, path)
		allowlist = append(allowlist, map[string]string{"uri": e.URI, "path": path})
	}

	encoded, err := json.Marshal(allowlist)
	if err != nil {
		t.Fatal(err)
	}

	verificationManifest := write(t, filepath.Join(dir, "verify-resources.json"), encoded)
	count := 0

	for _, name := range []string{nameRsaSha256, nameRsaSha384, nameRsaSha512, nameEcdsaSha256, nameEcdsaSha384, nameEcdsaSha512} {
		key := generateKey(t, dir, name)
		for _, cm := range canonicalizations() {
			ours, theirs := filepath.Join(dir, "go.xml"), filepath.Join(dir, "jdk.xml")
			command(t, fixture, true, nil, cli, "sign-detached", flagKey, key.private, "-method", key.method, "-resources", manifest, "-c14n", cm, flagOut, ours)
			java(t, fixture, "DetachedOracle", append([]string{nameSign, key.private, theirs, cm, key.method}, signResources...)...)
			verifyJava(t, java(t, fixture, "DetachedOracle", append([]string{nameVerify, key.public, ours}, verifyResources...)...), true)
			raw, _ := command(t, fixture, true, nil, cli, "verify-detached", flagKey, key.public, "-resources", verificationManifest, "-c14n", cm, flagIn, theirs)

			var r struct {
				Version   int    `json:"schema_version"`
				Operation string `json:"operation"`
				Status    string `json:"status"`
				Details   struct {
					References []json.RawMessage `json:"references"`
				} `json:"details"`
			}
			decode(t, raw, &r)

			if r.Version != 1 || r.Operation != "signature verify-detached" || r.Status != nameValid || len(r.Details.References) != len(entries) {
				t.Fatalf("detached: %s", raw)
			}

			count++
		}

		bad := filepath.Join(dir, "bad.xml")
		java(t, fixture, "DetachedOracle", append([]string{"sign-bad-second", key.private, bad, exc, key.method}, signResources...)...)

		v := verifyJava(t, java(t, fixture, "DetachedOracle", append([]string{nameVerify, key.public, bad}, verifyResources...)...), false)
		if !v.References[0] || v.References[1] {
			t.Fatal(v)
		}

		_, errout := command(t, fixture, false, nil, cli, "verify-detached", flagKey, key.public, "-resources", verificationManifest, flagIn, bad)
		if !bytes.Contains(errout, []byte("reference 1")) || !bytes.Contains(errout, []byte("digest mismatch")) {
			t.Fatalf("negative stage: %s", errout)
		}
	}

	t.Logf("%d detached exchanges each direction, %d references per signature, 6 bad-second controls", count, len(entries))
}

type javaVerdict struct {
	Core           bool   `json:"core"`
	Valid          bool   `json:"valid"`
	SignatureValue bool   `json:"signature_value"`
	References     []bool `json:"references"`
}

func verifyJava(t *testing.T, raw []byte, valid bool) javaVerdict {
	t.Helper()

	var r javaVerdict
	decode(t, raw, &r)

	if (r.Core || r.Valid) != valid || !r.SignatureValue {
		t.Fatalf("JDK verdict: %s", raw)
	}

	if valid {
		for _, ref := range r.References {
			if !ref {
				t.Fatalf("JDK reference: %s", raw)
			}
		}
	}

	return r
}

func coreSignatures(t *testing.T, fixture *interopFixture, externalXMLSec bool) {
	t.Helper()
	cli := binary(t, fixture, "xmlsec")

	names := []string{nameRsaSha256, nameRsaSha384, nameRsaSha512, nameEcdsaSha256, nameEcdsaSha384, nameEcdsaSha512}
	if externalXMLSec {
		names = append(names, "rsa-pss256", "rsa-pss384", "rsa-pss512", nameEd25519)
	}

	suite := coreSignatureSuite{fixture: fixture, cli: cli, externalXMLSec: externalXMLSec}

	for number, name := range names {
		t.Run(name, func(t *testing.T) { suite.algorithm(t, name, number) })
	}

	t.Logf("%d generated signature exchanges in each direction", suite.count)
}

type coreSignatureRecipe struct{ form, cm string }

type coreSignatureSuite struct {
	fixture        *interopFixture
	cli            string
	externalXMLSec bool
	count          int
}

func (suite *coreSignatureSuite) algorithm(t *testing.T, name string, number int) {
	t.Helper()
	dir := t.TempDir()

	keyName := name
	if strings.HasPrefix(name, "rsa-pss") {
		keyName = nameRsaSha256
	}

	key := generateKey(t, dir, keyName)
	if strings.HasPrefix(name, "rsa-pss") {
		key.method = "http://www.w3.org/2007/05/xmldsig-more#sha" + strings.TrimPrefix(name, "rsa-pss") + "-rsa-MGF1"
	}

	scenario := coreSignatureCase{suite: suite, dir: dir, key: key, digest: digests()[number%3]}

	for _, recipe := range coreSignatureRecipes() {
		t.Run(recipe.form+"/"+strconv.Itoa(slices.Index(canonicalizations(), recipe.cm)), func(t *testing.T) {
			scenario.exchange(t, recipe)
		})
	}

	if !suite.externalXMLSec {
		scenario.rejectBadSecond(t)
	}
}

func coreSignatureRecipes() []coreSignatureRecipe {
	recipes := make([]coreSignatureRecipe, 0, 2*len(canonicalizations()))
	for _, cm := range canonicalizations() {
		for _, form := range []string{nameEnveloping, "whole"} {
			recipes = append(recipes, coreSignatureRecipe{form, cm})
		}
	}

	for _, form := range []string{"sibling", "xpointer", nameMulti} {
		recipes = append(recipes, coreSignatureRecipe{form, exc})
	}

	return recipes
}

type verification struct {
	Status         string `json:"status"`
	SignatureValue string `json:"signature_value"`
	References     []struct {
		Status string `json:"status"`
	} `json:"references"`
}

type coreSignatureExchange struct {
	recipe               coreSignatureRecipe
	source, ours, theirs string
	total                int
}

type coreSignatureCase struct {
	suite  *coreSignatureSuite
	dir    string
	key    testKey
	digest string
}

func (scenario coreSignatureCase) exchange(t *testing.T, recipe coreSignatureRecipe) {
	t.Helper()
	source := write(t, filepath.Join(scenario.dir, "template.xml"), []byte(strings.ReplaceAll(coreTemplate(recipe.form, scenario.key.method, recipe.cm), digests()[0], scenario.digest)))

	exchange := coreSignatureExchange{
		recipe: recipe,
		source: source,
		ours:   filepath.Join(scenario.dir, "go.xml"),
		theirs: filepath.Join(scenario.dir, "reference.xml"),
		total:  1,
	}
	if recipe.form == nameMulti {
		exchange.total = 2
	}

	scenario.signExchange(t, exchange)
	scenario.verifyExchange(t, exchange)

	if scenario.suite.externalXMLSec {
		scenario.rejectTamper(t, exchange)
	}
}

func referenceTemplate(uri string, transforms ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<ds:Reference URI="%s">`, strings.ReplaceAll(uri, `"`, "&quot;"))

	if len(transforms) > 0 {
		b.WriteString("<ds:Transforms>")

		for _, alg := range transforms {
			fmt.Fprintf(&b, `<ds:Transform Algorithm="%s"/>`, alg)
		}

		b.WriteString("</ds:Transforms>")
	}

	fmt.Fprintf(&b, `<ds:DigestMethod Algorithm="%s"/><ds:DigestValue/></ds:Reference>`, digests()[0])

	return b.String()
}

func signatureTemplate(index int, method, cm, refs, objects string) string {
	return fmt.Sprintf(`<ds:Signature xmlns:ds="%s" Id="s%d"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/>%s</ds:SignedInfo><ds:SignatureValue/>%s</ds:Signature>`, ds, index, cm, method, refs, objects)
}

func coreTemplate(form, method, cm string) string {
	if form == nameEnveloping {
		refs := referenceTemplate("#data", cm) + referenceTemplate("#bin", ds+"base64") + referenceTemplate("#data", exc)
		return signatureTemplate(0, method, cm, refs, `<ds:Object Id="data" MimeType="text/xml"><p:item xmlns:p="urn:payload">one<!--comment--></p:item></ds:Object><ds:Object Id="bin">aGVsbG8=</ds:Object>`)
	}

	var refs string

	switch form {
	case "whole":
		refs = referenceTemplate("", ds+"enveloped-signature", cm) + referenceTemplate("#root", ds+"enveloped-signature", exc)
	case "xpointer":
		refs = referenceTemplate("#xpointer(id('data'))", exc+"WithComments") + referenceTemplate("#data", exc+"WithComments")
	default:
		refs = referenceTemplate("#data", cm) + referenceTemplate("#other", c11)
	}

	sigs := signatureTemplate(0, method, cm, refs, "")
	if form == nameMulti {
		sigs += signatureTemplate(1, method, cm, refs, "")
	}

	return `<root xmlns:z="urn:unused" ID="root"><item ID="data">one<!--comment--></item><item ID="other">two<!--comment--></item>` + sigs + `</root>`
}

func (scenario coreSignatureCase) signExchange(t *testing.T, exchange coreSignatureExchange) {
	t.Helper()

	for index := range exchange.total {
		input := exchange.source
		if index > 0 {
			input = exchange.ours
		}

		args := []string{"sign-template", flagKey, scenario.key.private, "-signature-index", strconv.Itoa(index), "-c14n", exchange.recipe.cm, "-modern-algorithms", flagIn, input, flagOut, exchange.ours}
		if index > 0 {
			args = append(args, "-preserve", "0="+scenario.key.public)
		}

		command(t, scenario.suite.fixture, true, nil, scenario.suite.cli, args...)

		if scenario.suite.externalXMLSec {
			input = exchange.source
			if index > 0 {
				input = exchange.theirs
			}

			args = append([]string{"--privkey-pem", scenario.key.private, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
			args = append(args, "--node-id", "s"+strconv.Itoa(index), "--output", exchange.theirs, input)
			native(t, scenario.suite.fixture, true, nameSign, args...)
		}
	}

	if !scenario.suite.externalXMLSec {
		java(t, scenario.suite.fixture, "CoreOracle", nameSign, scenario.key.private, exchange.theirs, exchange.recipe.cm, scenario.key.method, exchange.recipe.form)
	}
}

func (scenario coreSignatureCase) verifyExchange(t *testing.T, exchange coreSignatureExchange) {
	t.Helper()

	for index := range exchange.total {
		if scenario.suite.externalXMLSec {
			args := append([]string{flagPubkeyPem, scenario.key.public, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
			native(t, scenario.suite.fixture, true, nameVerify, append(args, "--node-id", "s"+strconv.Itoa(index), exchange.ours)...)
		} else {
			verifyJava(t, java(t, scenario.suite.fixture, "CoreOracle", nameVerify, scenario.key.public, exchange.ours, strconv.Itoa(index)), true)
		}

		raw, _ := command(t, scenario.suite.fixture, true, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", strconv.Itoa(index), "-modern-algorithms", "-c14n", exchange.recipe.cm, flagIn, exchange.theirs)
		verifyReport(t, raw, true)

		scenario.suite.count++
	}
}

func (scenario coreSignatureCase) rejectTamper(t *testing.T, exchange coreSignatureExchange) {
	t.Helper()
	original := read(t, exchange.theirs)

	changed := bytes.Replace(original, []byte(">one<"), []byte(">changed<"), 1)
	if bytes.Equal(original, changed) {
		t.Fatal("negative control did not alter input")
	}

	bad := write(t, filepath.Join(scenario.dir, "bad.xml"), changed)
	args := append([]string{flagPubkeyPem, scenario.key.public, flagEnabledReferenceUris, nameEmptySameDoc}, idArgs()...)
	native(t, scenario.suite.fixture, false, nameVerify, append(args, "--node-id", "s0", bad)...)
	raw, _ := command(t, scenario.suite.fixture, false, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", "0", "-modern-algorithms", "-c14n", exchange.recipe.cm, flagIn, bad)
	verifyReport(t, raw, false)

	if exchange.recipe.form == nameEnveloping && exchange.recipe.cm == exc {
		write(t, bad, bytes.Replace(original, []byte("aGVsbG8="), []byte("aGVsbG8h"), 1))
		native(t, scenario.suite.fixture, false, nameVerify, append(args, bad)...)
		raw, _ = command(t, scenario.suite.fixture, false, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", "0", "-modern-algorithms", flagIn, bad)
		badSecond(t, verifyReport(t, raw, false))
	}
}

func (scenario coreSignatureCase) rejectBadSecond(t *testing.T) {
	t.Helper()

	bad := filepath.Join(scenario.dir, "bad-second.xml")
	java(t, scenario.suite.fixture, "CoreOracle", "sign-bad-second", scenario.key.private, bad, exc, scenario.key.method, nameEnveloping)

	oracle := verifyJava(t, java(t, scenario.suite.fixture, "CoreOracle", nameVerify, scenario.key.public, bad, "0"), false)
	if !slices.Equal(oracle.References, []bool{true, false, true}) {
		t.Fatal(oracle)
	}

	raw, _ := command(t, scenario.suite.fixture, false, nil, scenario.suite.cli, "verify-core", flagKey, scenario.key.public, "-signature-index", "0", flagIn, bad)
	badSecond(t, verifyReport(t, raw, false))
}

func verifyReport(t *testing.T, raw []byte, valid bool) verification {
	t.Helper()

	var envelope struct {
		Version   int    `json:"schema_version"`
		Operation string `json:"operation"`
		Status    string `json:"status"`
		Details   struct {
			Checks verification `json:"checks"`
		} `json:"details"`
	}
	decode(t, raw, &envelope)

	r := envelope.Details.Checks
	if envelope.Version != 1 || envelope.Operation != "signature verify-core" || envelope.Status != r.Status || len(r.References) == 0 {
		t.Fatalf("verification report schema: %s", raw)
	}

	if (r.Status == nameValid) != valid || r.SignatureValue != nameValid {
		t.Fatalf("verification: %s", raw)
	}

	if valid {
		for _, ref := range r.References {
			if ref.Status != nameValid {
				t.Fatalf("reference: %s", raw)
			}
		}
	}

	return r
}

func badSecond(t *testing.T, r verification) {
	t.Helper()

	statuses := make([]string, 0, len(r.References))
	for _, ref := range r.References {
		statuses = append(statuses, ref.Status)
	}

	if !slices.Equal(statuses, []string{nameValid, "invalid", "not-checked"}) {
		t.Fatalf("bad second reference: %v", statuses)
	}
}

func idArgs() []string {
	return []string{flagIDAttrID, nameRoot, flagIDAttrID, "item", flagIDAttrID, "payload", "--id-attr:Id", ds + ":Object", "--id-attr:Id", ds + ":Signature"}
}

func native(t *testing.T, fixture *interopFixture, success bool, mode string, args ...string) []byte {
	t.Helper()

	all := append([]string{mode, "--lax-key-search"}, args...)
	out, _ := command(t, fixture, success, nil, xmlsecExecutable(), all...)

	return out
}
