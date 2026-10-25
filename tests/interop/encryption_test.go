//go:build interop

package interop_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html"
	"math/bits"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/xmlenc"
)

const (
	nameDirect    = "direct"
	nameEmpty     = "empty"
	nameInherited = "inherited"
	nameWrap      = "wrap"
)

func TestXMLSecEncryption(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")

	dir := t.TempDir()
	key := generateKey(t, dir, nameRsaSha256)
	suite := encryptionSuite{fixture: fixture, dir: dir, key: key}

	recipes := encryptionRecipes()
	for i, r := range recipes {
		for _, xml := range []bool{false, true} {
			t.Run(fmt.Sprintf("suite%d/xml=%v", i, xml), func(t *testing.T) {
				suite.checkCase(t, r, xml, i == len(recipes)-1)
			})
		}
	}

	t.Logf("%d generated encryption exchanges each direction with rejected tags; %d CipherReference direction/transform controls", suite.count, suite.resources)
}

func encryptionRecipes() []encryptionRecipe {
	recipes := make([]encryptionRecipe, 0, 80)

	for _, bits := range []int{128, 192, 256} {
		for _, wrap := range []int{0, 128, 192, 256} {
			mode := nameRsa
			if wrap > 0 {
				mode = nameWrap
			}

			recipes = append(recipes, encryptionRecipe{mode: mode, bits: bits, wrap: wrap})
		}

		recipes = append(recipes, encryptionRecipe{mode: nameDirect, bits: bits})
	}

	recipes = append(recipes, encryptionRecipe{mode: nameDirect, bits: 256, keyName: "explicit-test-key"})

	for _, h := range []string{"256", "384", "512"} {
		for _, label := range [][]byte{nil, []byte("application\x00label\xff")} {
			recipes = append(recipes, encryptionRecipe{mode: nameRsa, bits: 256, hash: h, label: label})
		}
	}

	for _, h := range []string{"1", "224", "256", "384", "512"} {
		for _, mgf := range []string{"1", "224", "256", "384", "512"} {
			if h == mgf && h != "1" && h != "224" {
				continue // Already covered above with both empty and nonempty labels.
			}

			for _, label := range [][]byte{nil, []byte("application\x00label\xff")} {
				recipes = append(recipes, encryptionRecipe{mode: nameRsa, bits: 256, hash: h, mgf: mgf, legacy: h == "1" || mgf == "1", label: label})
			}
		}

		for _, label := range [][]byte{nil, []byte("application\x00label\xff")} {
			recipes = append(recipes, encryptionRecipe{mode: nameRsa, bits: 256, hash: h, mgf: "1", algorithm: enc + "rsa-oaep-mgf1p", legacy: true, label: label})
		}
	}

	recipes = append(recipes, encryptionRecipe{mode: nameWrap, bits: 256, wrap: 256})

	return recipes
}

func TestXMLSecSelectedEncryption(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")

	dir := t.TempDir()
	key := generateKey(t, dir, nameRsaSha256)
	cli := binary(t, fixture, "xmlsec")
	buffer := bufferOracle(t, fixture)
	element, content := selectedEncryptionForms()

	for _, kind := range []string{nameElement, nameContent} {
		forms := element
		if kind == nameContent {
			forms = content
		}

		suite := selectedEncryptionSuite{fixture: fixture, dir: dir, key: key, cli: cli, buffer: buffer, kind: kind}

		recipes := selectedEncryptionRecipes(kind)
		for i, r := range recipes {
			t.Run(kind+"/"+strconv.Itoa(i), func(t *testing.T) {
				scenario := suite.prepare(t, forms, r)
				suite.decryptOurs(t, scenario)
				suite.encryptTheirs(t, scenario)
				suite.rejectTamper(t, scenario)
			})
		}

		t.Logf("%s: %d selected exchanges each direction; %d empty-content diagnostics; %d rejected-tag controls", kind, suite.count, suite.emptyCount, len(recipes))
	}
}

func selectedEncryptionForms() (map[string]string, map[string]string) {
	inherited := `<?before ok?><!--before--><r xmlns="urn:r" xmlns:p="urn:p" xmlns:q="urn:unused" xml:lang="ru" xml:base="https://example.test/"><head>visible</head><box xmlns:p="urn:shadow"><p:secret ID="secret" p:flag="é"><p:v>й 😀</p:v><!--inside--></p:secret><tail/></box></r><!--after-->`
	rootInput := `<?before ok?><!--before--><secret xmlns="urn:p" xmlns:q="urn:unused">й 😀<!--inside--></secret><!--after-->`
	element := map[string]string{nameInherited: inherited, "reset": strings.ReplaceAll(strings.ReplaceAll(inherited, `<p:secret ID=`, `<p:secret xmlns="" ID=`), `<p:v>й 😀</p:v>`, `<bare>й 😀</bare>`), nameRoot: rootInput}
	content := map[string]string{nameInherited: strings.ReplaceAll(strings.ReplaceAll(inherited, `<p:secret ID="secret" p:flag="é">`, `<p:secret ID="secret" p:flag="é">before`), `</p:v><!--inside-->`, `</p:v><!--inside--><?inside ok?><bare xmlns=""/>after`), nameEmpty: strings.ReplaceAll(inherited, `<p:v>й 😀</p:v><!--inside-->`, ""), nameText: strings.ReplaceAll(inherited, `<p:v>й 😀</p:v><!--inside-->`, `й 😀 &amp; protected text`), nameRoot: rootInput}

	return element, content
}

func selectedEncryptionRecipes(kind string) []selectedEncryptionRecipe {
	recipes := make([]selectedEncryptionRecipe, 0, 3*4*4+3*4*len(canonicalizations()))

	formNames := []string{nameInherited, "reset", nameRoot}
	if kind == nameContent {
		formNames = []string{nameInherited, nameEmpty, nameText, nameRoot}
	}

	for _, bits := range []int{128, 192, 256} {
		for _, wrap := range []int{0, 128, 192, 256} {
			for _, form := range formNames {
				recipes = append(recipes, selectedEncryptionRecipe{bits: bits, wrap: wrap, form: form})
			}
		}
	}

	for _, cm := range canonicalizations() {
		recipes = append(recipes, selectedEncryptionRecipe{bits: 256, wrap: 256, form: nameInherited, cm: cm})
	}

	return recipes
}

func bufferOracle(t *testing.T, fixture *interopFixture) string {
	t.Helper()

	path := filepath.Join(fixture.work, "buffer-oracle")
	flags, _ := command(t, fixture, true, nil, "pkg-config", "--cflags", "--libs", "xmlsec1-openssl")
	libraryFlags := strings.Fields(string(flags))
	args := make([]string, 0, 8+len(libraryFlags))
	args = append(args, "-std=c11", flagO2, flagWall, flagWextra, flagWerror, filepath.Join(fixture.root, "tests/interop/testdata/buffer_probe.c"))
	args = append(args, libraryFlags...)
	command(t, fixture, true, nil, "cc", append(args, "-o", path)...)

	return path
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}

	return b
}

type encryptionRecipe struct {
	mode       string
	bits       int
	wrap       int
	hash       string
	mgf        string
	algorithm  string
	keyName    string
	data       string
	tripleWrap bool
	dataLegacy bool
	legacy     bool
	label      []byte
}

type encryptionCase struct {
	recipe     encryptionRecipe
	xml        bool
	plain      []byte
	source     string
	ours       string
	theirs     string
	output     string
	keyfile    string
	decryptKey string
	encryptArg string
	decryptArg string
	suffix     string
	task       map[string]any
}

type encryptionSuite struct {
	fixture   *interopFixture
	dir       string
	key       testKey
	count     int
	resources int
}

func (suite *encryptionSuite) prepare(t *testing.T, r encryptionRecipe, xml bool) *encryptionCase {
	t.Helper()

	plain := []byte("\x00\xffopaque\nbytes")
	if xml {
		plain = []byte(`<r xmlns:p="urn:p"><p:v>й é 😀</p:v><!--inside--></r>`)
	}

	source := write(t, filepath.Join(suite.dir, "plain"), plain)
	ours, theirs, output := filepath.Join(suite.dir, "go.xml"), filepath.Join(suite.dir, "ref.xml"), filepath.Join(suite.dir, "output")
	keyfile, decryptKey := suite.key.public, suite.key.private

	if r.mode != nameRsa {
		n := r.bits / 8
		if r.mode == nameWrap {
			n = r.wrap / 8
		}
		if r.tripleWrap {
			n = 24
		}

		keyfile = write(t, filepath.Join(suite.dir, "kek"), randomBytes(t, n))
		decryptKey = keyfile
	}

	encryptArg, decryptArg := nativeKeyArgs(r.mode, r.keyName)
	if r.tripleWrap || r.mode == nameDirect && r.data == enc+"tripledes-cbc" {
		encryptArg, decryptArg = "--deskey", "--deskey"
	}

	suffix := ""
	if r.mode != nameRsa {
		suffix = "-" + r.mode
	}

	keyAlgorithm := enc11 + "rsa-oaep"
	if r.mode == nameWrap {
		keyAlgorithm = enc + "kw-aes" + strconv.Itoa(r.wrap)
	}
	if r.tripleWrap {
		keyAlgorithm = enc + "kw-tripledes"
	}
	dataAlgorithm := enc11 + fmt.Sprintf("aes%d-gcm", r.bits)
	if r.data != "" {
		dataAlgorithm = r.data
	}

	task := map[string]any{nameMode: "encrypt" + suffix, nameKey: keyfile, nameInput: source, "XML": xml, nameDataAlgorithm: dataAlgorithm, "AllowLegacy": r.dataLegacy, nameKeyAlgorithm: keyAlgorithm, "OAEPAlgorithm": r.algorithm, "OAEPHash": r.hash, "OAEPMGFHash": r.mgf, "OAEPAllowLegacy": r.legacy, "OAEPLabel": r.label, "KeyName": r.keyName}

	return &encryptionCase{recipe: r, xml: xml, plain: plain, source: source, ours: ours, theirs: theirs, output: output, keyfile: keyfile, decryptKey: decryptKey, encryptArg: encryptArg, decryptArg: decryptArg, suffix: suffix, task: task}
}

func (suite *encryptionSuite) checkCase(t *testing.T, r encryptionRecipe, xml, last bool) {
	t.Helper()

	scenario := suite.prepare(t, r, xml)
	suite.exchange(t, scenario)
	suite.rejectTamper(t, scenario)

	external := r.keyName == "" && (r.mode == nameRsa && r.hash == "384" && len(r.label) > 0 || r.mode == nameWrap && last || r.mode == nameDirect && r.bits == 256)
	if external {
		suite.checkCipherReferences(t, scenario)
	}
}

func (suite *encryptionSuite) exchange(t *testing.T, scenario *encryptionCase) {
	t.Helper()

	raw := probeData(t, suite.fixture, "nextprobe", scenario.task)
	write(t, scenario.ours, raw)
	native(t, suite.fixture, true, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, scenario.ours)
	comparePlain(t, suite.fixture, read(t, scenario.output), scenario.plain, scenario.xml)
	pattern := write(t, filepath.Join(suite.dir, "template.xml"), clearCipherValues(t, raw))

	args := []string{scenario.encryptArg, scenario.keyfile}
	if scenario.recipe.mode != nameDirect {
		session := fmt.Sprintf("aes-%d", scenario.recipe.bits)
		if scenario.recipe.data == enc+"tripledes-cbc" {
			session = "des-192"
		}
		args = append(args, "--session-key", session)
	}

	inputArg := "--binary-data"
	if scenario.xml {
		inputArg = "--xml-data"
	}

	native(t, suite.fixture, true, "encrypt", append(args, inputArg, scenario.source, "--output", scenario.theirs, pattern)...)

	scenario.task[nameMode] = "decrypt" + scenario.suffix
	scenario.task[nameInput] = scenario.theirs
	scenario.task[nameKey] = scenario.decryptKey
	comparePlain(t, suite.fixture, probeData(t, suite.fixture, "nextprobe", scenario.task), scenario.plain, scenario.xml)

	suite.count++
}

func (suite *encryptionSuite) rejectTamper(t *testing.T, scenario *encryptionCase) {
	t.Helper()

	bad := write(t, filepath.Join(suite.dir, "bad.xml"), corruptCipher(t, read(t, scenario.theirs)))

	os.Remove(scenario.output)
	native(t, suite.fixture, false, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, bad)
	noOutput(t, scenario.output)

	negative := copyTask(scenario.task)
	negative[nameInput] = bad
	probe(t, suite.fixture, "nextprobe", negative, false)

	if scenario.recipe.hash != "" {
		negative = copyTask(scenario.task)

		negative["OAEPHash"] = "384"
		if scenario.recipe.hash == "384" {
			negative["OAEPHash"] = "512"
		}

		probe(t, suite.fixture, "nextprobe", negative, false)

		if len(scenario.recipe.label) > 0 {
			negative = copyTask(scenario.task)
			negative["OAEPLabel"] = []byte("wrong")
			probe(t, suite.fixture, "nextprobe", negative, false)
		}
	}

	if scenario.recipe.mgf != "" {
		negative = copyTask(scenario.task)

		negative["OAEPMGFHash"] = "256"
		if scenario.recipe.mgf == "256" {
			negative["OAEPMGFHash"] = "512"
		}

		probe(t, suite.fixture, "nextprobe", negative, false)
	}

	if scenario.recipe.legacy {
		negative = copyTask(scenario.task)
		negative["OAEPAllowLegacy"] = false
		probe(t, suite.fixture, "nextprobe", negative, false)
	}
}

func (suite *encryptionSuite) checkCipherReferences(t *testing.T, scenario *encryptionCase) {
	t.Helper()

	resource := filepath.Join(suite.dir, "ciphertext.bin")
	uri := (&url.URL{Scheme: "file", Path: resource}).String()

	for _, encoded := range []bool{false, true} {
		for _, forward := range []bool{true, false} {
			suite.checkCipherReference(t, scenario, resource, uri, encoded, forward)
		}
	}
}

func (suite *encryptionSuite) checkCipherReference(t *testing.T, scenario *encryptionCase, resource, uri string, encoded, forward bool) {
	t.Helper()

	input := scenario.ours
	if !forward {
		input = scenario.theirs
	}

	envelope, body := cipherReference(t, read(t, input), uri, encoded)
	path := write(t, filepath.Join(suite.dir, "external.xml"), envelope)
	write(t, resource, body)

	resourceTask := copyTask(scenario.task)
	resourceTask[nameInput] = path
	resourceTask["Resource"] = resource
	resourceTask["CipherURI"] = uri

	if forward {
		native(t, suite.fixture, true, "decrypt", scenario.decryptArg, scenario.decryptKey, "--enabled-cipher-reference-uris", "local", "--output", scenario.output, path)
		comparePlain(t, suite.fixture, read(t, scenario.output), scenario.plain, scenario.xml)
	} else {
		comparePlain(t, suite.fixture, probeData(t, suite.fixture, "nextprobe", resourceTask), scenario.plain, scenario.xml)

		noResolver := copyTask(scenario.task)
		noResolver[nameInput] = path
		probe(t, suite.fixture, "nextprobe", noResolver, false)

		wrongURI := copyTask(resourceTask)
		wrongURI["CipherURI"] = uri + "-wrong"
		probe(t, suite.fixture, "nextprobe", wrongURI, false)
	}
	// Corrupt actual decoded bytes while preserving valid base64 syntax.
	altered := bytes.Clone(body)
	if encoded {
		altered = decode64(t, string(body))
		altered[len(altered)-1] ^= 1
		altered = []byte(base64String(altered))
	} else {
		altered[len(altered)-1] ^= 1
	}

	write(t, resource, altered)
	probe(t, suite.fixture, "nextprobe", resourceTask, false)
	os.Remove(scenario.output)
	native(t, suite.fixture, false, "decrypt", scenario.decryptArg, scenario.decryptKey, "--enabled-cipher-reference-uris", "local", "--output", scenario.output, path)
	noOutput(t, scenario.output)

	suite.resources++
}

func comparePlain(t *testing.T, fixture *interopFixture, actual, expected []byte, xml bool) {
	t.Helper()

	if xml {
		equalXML(t, fixture, actual, expected)
	} else if !bytes.Equal(actual, expected) {
		t.Fatalf("plaintext differs: %x != %x", actual, expected)
	}
}

type selectedEncryptionRecipe struct {
	bits int
	wrap int
	form string
	cm   string
}

type selectedEncryptionCase struct {
	recipe     selectedEncryptionRecipe
	original   []byte
	raw        []byte
	source     string
	ours       string
	theirs     string
	output     string
	keyfile    string
	decryptKey string
	encryptArg string
	decryptArg string
	suffix     string
	task       map[string]any
	empty      bool
}

type selectedEncryptionSuite struct {
	fixture    *interopFixture
	dir        string
	cli        string
	buffer     string
	kind       string
	key        testKey
	count      int
	emptyCount int
}

func (suite *selectedEncryptionSuite) prepare(t *testing.T, forms map[string]string, r selectedEncryptionRecipe) *selectedEncryptionCase {
	t.Helper()

	source := write(t, filepath.Join(suite.dir, "source.xml"), []byte(forms[r.form]))
	if r.cm != "" {
		signature := signatureTemplate(0, more+nameRsaSha256, r.cm, referenceTemplate("#secret", ds+"enveloped-signature", r.cm), "")
		write(t, source, bytes.Replace(read(t, source), []byte("</p:secret>"), []byte(signature+"</p:secret>"), 1))
		command(t, suite.fixture, true, nil, suite.cli, "sign-template", flagKey, suite.key.private, "-signature-index", "0", "-c14n", r.cm, flagIn, source, flagOut, source)
	}

	original := read(t, source)
	mode, keyfile, decryptKey, suffix := nameRsa, suite.key.public, suite.key.private, ""
	algorithm := enc11 + "rsa-oaep"

	if r.wrap > 0 {
		mode = nameWrap
		suffix = "-wrap"
		keyfile = write(t, filepath.Join(suite.dir, "kek"), randomBytes(t, r.wrap/8))
		decryptKey = keyfile
		algorithm = enc + fmt.Sprintf("kw-aes%d", r.wrap)
	}

	encryptArg, decryptArg := nativeKeyArgs(mode, "")
	task := map[string]any{nameMode: "encrypt-" + suite.kind + suffix, nameInput: source, "Selection": "secret", nameKey: keyfile, nameDataAlgorithm: enc11 + fmt.Sprintf("aes%d-gcm", r.bits), nameKeyAlgorithm: algorithm}
	raw := probeData(t, suite.fixture, "nextprobe", task)
	ours := write(t, filepath.Join(suite.dir, "ours.xml"), raw)
	theirs, output := filepath.Join(suite.dir, "theirs.xml"), filepath.Join(suite.dir, "output.xml")
	empty := suite.kind == nameContent && r.form == nameEmpty

	return &selectedEncryptionCase{recipe: r, original: original, raw: raw, source: source, ours: ours, theirs: theirs, output: output, keyfile: keyfile, decryptKey: decryptKey, encryptArg: encryptArg, decryptArg: decryptArg, suffix: suffix, task: task, empty: empty}
}

func (suite *selectedEncryptionSuite) decryptOurs(t *testing.T, scenario *selectedEncryptionCase) {
	t.Helper()

	if scenario.empty {
		bufferKind := nameRsa
		if scenario.recipe.wrap > 0 {
			bufferKind = "aes"
		}

		raw, _ := command(t, suite.fixture, true, nil, suite.buffer, scenario.ours, bufferKind, scenario.decryptKey)
		if strings.TrimSpace(string(raw)) != `{"size":0}` {
			t.Fatalf("empty native buffer: %s", raw)
		}
	}

	os.Remove(scenario.output)
	native(t, suite.fixture, !scenario.empty, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, scenario.ours)

	if scenario.empty {
		noOutput(t, scenario.output)

		self := copyTask(scenario.task)
		self[nameMode] = "decrypt-content" + scenario.suffix
		self[nameInput] = scenario.ours
		self["Selection"] = nameEncryptedData
		self[nameKey] = scenario.decryptKey
		equalXML(t, suite.fixture, scenario.original, probeData(t, suite.fixture, "nextprobe", self))

		suite.emptyCount++

		t.Log("DIAGNOSTIC authenticated empty buffer valid; xmlsec1 empty XML replacement fails (excluded from exchanges)")
	} else {
		equalXML(t, suite.fixture, scenario.original, read(t, scenario.output))
	}
}

func (suite *selectedEncryptionSuite) encryptTheirs(t *testing.T, scenario *selectedEncryptionCase) {
	t.Helper()

	d := xmlDoc(t, scenario.raw)
	envelope := one(t, tree.Root(d), enc, nameEncryptedData)
	pattern := write(t, filepath.Join(suite.dir, "template.xml"), clearCipherValues(t, xmlElement(t, d, envelope)))

	os.Remove(scenario.theirs)
	args := []string{scenario.encryptArg, scenario.keyfile, "--session-key", fmt.Sprintf("aes-%d", scenario.recipe.bits), "--xml-data", scenario.source, "--node-xpath", "//*[local-name()='secret']", "--output", scenario.theirs, pattern}
	native(t, suite.fixture, !scenario.empty, "encrypt", args...)

	if scenario.empty {
		noOutput(t, scenario.theirs)
	} else {
		scenario.task[nameMode] = "decrypt-" + suite.kind + scenario.suffix
		scenario.task[nameInput] = scenario.theirs
		scenario.task["Selection"] = nameEncryptedData
		scenario.task[nameKey] = scenario.decryptKey
		restored := probeData(t, suite.fixture, "nextprobe", scenario.task)
		equalXML(t, suite.fixture, scenario.original, restored)

		if scenario.recipe.cm != "" {
			write(t, scenario.output, restored)
			raw, _ := command(t, suite.fixture, true, nil, suite.cli, "verify-core", flagKey, suite.key.public, "-signature-index", "0", "-c14n", scenario.recipe.cm, flagIn, scenario.output)
			verifyReport(t, raw, true)
			native(t, suite.fixture, true, nameVerify, flagPubkeyPem, suite.key.public, flagIDAttrID, "urn:shadow:secret", flagEnabledReferenceUris, "same-doc", scenario.output)
		}

		suite.count++
	}
}

func (suite *selectedEncryptionSuite) rejectTamper(t *testing.T, scenario *selectedEncryptionCase) {
	t.Helper()

	input := scenario.ours
	if !scenario.empty {
		input = scenario.theirs
	}

	bad := write(t, filepath.Join(suite.dir, "bad.xml"), corruptCipher(t, read(t, input)))

	os.Remove(scenario.output)
	native(t, suite.fixture, false, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, bad)
	noOutput(t, scenario.output)

	scenario.task[nameMode] = "decrypt-" + suite.kind + scenario.suffix
	scenario.task[nameInput] = bad
	scenario.task["Selection"] = nameEncryptedData
	scenario.task[nameKey] = scenario.decryptKey
	probe(t, suite.fixture, "nextprobe", scenario.task, false)

	if scenario.empty {
		bufferKind := nameRsa
		if scenario.recipe.wrap > 0 {
			bufferKind = "aes"
		}

		command(t, suite.fixture, false, nil, suite.buffer, bad, bufferKind, scenario.decryptKey)
	}
}

func TestXMLSecLegacyEncryption(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	dir := t.TempDir()
	key := generateKey(t, dir, nameRsaSha256)
	suite := encryptionSuite{fixture: fixture, dir: dir, key: key}
	for _, data := range []struct {
		uri  string
		bits int
	}{{enc + "aes128-cbc", 128}, {enc + "aes192-cbc", 192}, {enc + "aes256-cbc", 256}, {enc + "tripledes-cbc", 192}} {
		routes := []encryptionRecipe{{mode: nameRsa, bits: data.bits, data: data.uri, dataLegacy: true}, {mode: nameRsa, bits: data.bits, data: data.uri, dataLegacy: true, algorithm: enc + "rsa-oaep-mgf1p", hash: "1", mgf: "1", legacy: true}, {mode: nameDirect, bits: data.bits, data: data.uri, dataLegacy: true}, {mode: nameWrap, bits: data.bits, wrap: 128, data: data.uri, dataLegacy: true}, {mode: nameWrap, bits: data.bits, wrap: 256, data: data.uri, dataLegacy: true}}
		if strings.HasSuffix(data.uri, "tripledes-cbc") {
			routes = append(routes, encryptionRecipe{mode: nameWrap, bits: 192, data: data.uri, dataLegacy: true, tripleWrap: true})
		}
		for index, r := range routes {
			t.Run(data.uri+"/"+strconv.Itoa(index), func(t *testing.T) {
				scenario := suite.prepare(t, r, false)
				if r.tripleWrap {
					suite.exchangeTripleDESWrap(t, scenario)
				} else {
					suite.exchange(t, scenario)
				}
				if r.mode == nameDirect {
					suite.checkZeroCBCPadding(t, scenario)
				}
				denied := copyTask(scenario.task)
				denied["AllowLegacy"] = false
				probe(t, fixture, "nextprobe", denied, false)
				// Incomplete CBC blocks are rejected in both implementations.
				// Pad-length-zero acceptance differs in xmlsec1; exact padding
				// validation is covered separately by the normative native cases.
				raw := read(t, scenario.theirs)
				doc := xmlDoc(t, raw)
				cv := legacyDataCipherValue(t, doc)
				ciphertext := decode64(t, text(cv))
				ciphertext = ciphertext[:len(ciphertext)-1]

				bad := write(t, filepath.Join(dir, "bad-padding.xml"), bytes.Replace(raw, []byte(text(cv)), []byte(base64String(ciphertext)), 1))
				negative := copyTask(scenario.task)
				negative[nameInput] = bad
				probe(t, fixture, "nextprobe", negative, false)
				os.Remove(scenario.output)
				native(t, fixture, false, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, bad)
				noOutput(t, scenario.output)
			})
		}
	}
}

func (suite *encryptionSuite) checkZeroCBCPadding(t *testing.T, scenario *encryptionCase) {
	t.Helper()
	blockBytes, algorithm := 16, "aes-"+strconv.Itoa(scenario.recipe.bits)+"-cbc"
	if scenario.recipe.data == enc+"tripledes-cbc" {
		blockBytes, algorithm = 8, "des-ede3-cbc"
	}
	plain := bytes.Repeat([]byte{'A'}, blockBytes)
	plain[len(plain)-1] = 0
	input := filepath.Join(suite.dir, "padding-input")
	output := filepath.Join(suite.dir, "padding-ciphertext")
	wire := read(t, scenario.theirs)
	cv := legacyDataCipherValue(t, xmlDoc(t, wire))
	for _, length := range []byte{0, 1} {
		plain[len(plain)-1] = length
		write(t, input, plain)
		command(t, suite.fixture, true, nil, "openssl", "enc", "-"+algorithm, "-nopad", "-K", hex.EncodeToString(read(t, scenario.keyfile)), "-iv", strings.Repeat("0", 2*blockBytes), "-in", input, "-out", output)
		ciphertext := append(make([]byte, blockBytes), read(t, output)...)
		modified := bytes.Replace(wire, []byte(text(cv)), []byte(base64String(ciphertext)), 1)
		path := write(t, filepath.Join(suite.dir, "padding-envelope.xml"), modified)
		check := copyTask(scenario.task)
		check[nameInput] = path
		if length == 0 {
			probe(t, suite.fixture, "nextprobe", check, false)
			native(t, suite.fixture, true, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, path)
			comparePlain(t, suite.fixture, read(t, scenario.output), plain, false)
			t.Log("DIAGNOSTIC xmlsec1 accepts a zero XMLENC CBC padding length; one-octet correction to1 restores valid Go/native agreement. Zero-length acceptance is excluded from agreement.")
		} else {
			comparePlain(t, suite.fixture, probeData(t, suite.fixture, "nextprobe", check), plain[:len(plain)-1], false)
			native(t, suite.fixture, true, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, path)
			comparePlain(t, suite.fixture, read(t, scenario.output), plain[:len(plain)-1], false)
		}
	}
}

func TestXMLSecEncryptionMethodKeySize(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	dir := t.TempDir()
	key := generateKey(t, dir, nameRsaSha256)
	suite := encryptionSuite{fixture: fixture, dir: dir, key: key}
	for _, recipe := range []encryptionRecipe{{mode: nameDirect, bits: 256}, {mode: nameWrap, bits: 256, wrap: 128}, {mode: nameRsa, bits: 256}} {
		t.Run(recipe.mode, func(t *testing.T) {
			scenario := suite.prepare(t, recipe, false)
			raw := probeData(t, fixture, "nextprobe", scenario.task)
			method := `<xenc:EncryptionMethod Algorithm="` + enc11 + `aes256-gcm">`
			raw = bytes.Replace(raw, []byte(method), []byte(method+`<xenc:KeySize>256</xenc:KeySize>`), 1)
			if recipe.mode != nameDirect {
				algorithm, size := enc11+"rsa-oaep", "2048"
				if recipe.mode == nameWrap {
					algorithm, size = enc+"kw-aes128", "128"
				}
				method = `<xenc:EncryptionMethod Algorithm="` + algorithm + `">`
				raw = bytes.Replace(raw, []byte(method), []byte(method+`<xenc:KeySize>`+size+`</xenc:KeySize>`), 1)
			}
			write(t, scenario.ours, raw)
			scenario.task[nameMode] = "decrypt" + scenario.suffix
			scenario.task[nameInput] = scenario.ours
			scenario.task[nameKey] = scenario.decryptKey
			comparePlain(t, fixture, probeData(t, fixture, "nextprobe", scenario.task), scenario.plain, false)
			if recipe.mode == nameRsa {
				// XMLENC3.2 permits KeySize; the explicitly supplied RSA key
				// has a2048-bit modulus. This native key-search outcome is a
				// diagnostic, rather than agreement for the RSA-size branch.
				os.Remove(scenario.output)
				native(t, fixture, false, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, scenario.ours)
				noOutput(t, scenario.output)
				withoutRSAKeySize := bytes.Replace(raw, []byte(`<xenc:KeySize>2048</xenc:KeySize>`), nil, 1)
				write(t, scenario.ours, withoutRSAKeySize)
				t.Log("DIAGNOSTIC xmlsec1 rejects RSA-OAEP KeySize2048 during key search; removing only this optional parameter succeeds. Excluded from RSA KeySize agreement.")
			}
			native(t, fixture, true, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, scenario.ours)
			comparePlain(t, fixture, read(t, scenario.output), scenario.plain, false)
		})
	}
}

func legacyDataCipherValue(t *testing.T, doc *tree.Document) *tree.Node {
	t.Helper()
	for _, child := range tree.Root(doc).Children {
		if child.Name.Space == enc && child.Name.Local == nameCipherData {
			return one(t, child, enc, "CipherValue")
		}
	}
	t.Fatal("missing data CipherValue")
	return nil
}

func (suite *encryptionSuite) exchangeTripleDESWrap(t *testing.T, scenario *encryptionCase) {
	t.Helper()
	raw := probeData(t, suite.fixture, "nextprobe", scenario.task)
	write(t, scenario.ours, raw)
	native(t, suite.fixture, true, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, scenario.ours)
	comparePlain(t, suite.fixture, read(t, scenario.output), scenario.plain, false)
	pattern := write(t, filepath.Join(suite.dir, "template.xml"), clearCipherValues(t, raw))
	native(t, suite.fixture, true, "encrypt", scenario.encryptArg, scenario.keyfile, "--session-key", "des-192", "--binary-data", scenario.source, "--output", scenario.theirs, pattern)
	foreign := xmlDoc(t, read(t, scenario.theirs))
	ek := one(t, tree.Root(foreign), enc, "EncryptedKey")
	cv := one(t, ek, enc, "CipherValue")
	wrapped := write(t, filepath.Join(suite.dir, "foreign-wrapped"), decode64(t, text(cv)))
	cekPath := filepath.Join(suite.dir, "foreign-cek")
	command(t, suite.fixture, true, nil, "openssl", "enc", "-d", "-id-smime-alg-CMS3DESwrap", "-K", hex.EncodeToString(read(t, scenario.keyfile)), "-in", wrapped, "-out", cekPath)
	cek := read(t, cekPath)
	odd := len(cek) == 24
	for _, b := range cek {
		if bits.OnesCount8(b)%2 != 1 {
			odd = false
		}
	}
	check := copyTask(scenario.task)
	check[nameMode] = "decrypt-wrap"
	check[nameKey] = scenario.decryptKey
	check[nameInput] = scenario.theirs
	if !odd {
		probe(t, suite.fixture, "nextprobe", check, false)
		// Parity bits do not change the effective DES key. Rewrapping the
		// same key with corrected parity changes only the wrapped key value;
		// the native CBC ciphertext remains byte-for-byte unchanged.
		for i, b := range cek {
			cek[i] = b & 0xfe
			if bits.OnesCount8(cek[i])%2 == 0 {
				cek[i] |= 1
			}
		}
		corrected := write(t, filepath.Join(suite.dir, "corrected-cek"), cek)
		correctedWrap := filepath.Join(suite.dir, "corrected-wrap")
		command(t, suite.fixture, true, nil, "openssl", "enc", "-id-smime-alg-CMS3DESwrap", "-K", hex.EncodeToString(read(t, scenario.keyfile)), "-in", corrected, "-out", correctedWrap)
		correctedWire := bytes.Replace(read(t, scenario.theirs), []byte(text(cv)), []byte(base64String(read(t, correctedWrap))), 1)
		correctedEnvelope := write(t, filepath.Join(suite.dir, "corrected.xml"), correctedWire)
		check[nameInput] = correctedEnvelope
		comparePlain(t, suite.fixture, probeData(t, suite.fixture, "nextprobe", check), scenario.plain, false)
		t.Log("DIAGNOSTIC xmlsec1 session-key generator emitted non-odd-parity CEK; RFC3217 3.2step8 requires rejection. Excluded from reverse agreement.")
	} else {
		comparePlain(t, suite.fixture, probeData(t, suite.fixture, "nextprobe", check), scenario.plain, false)
	}
	// Independent reverse primitive composition: OpenSSL performs both
	// CBC encryption and CMS3DESwrap using an explicitly selected RFC3217
	// odd-parity CEK. The original generated Go XML supplies only wire syntax.
	cek, _ = hex.DecodeString("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98")
	cekPath = write(t, filepath.Join(suite.dir, "odd-cek"), cek)
	pad := 8 - len(scenario.plain)%8
	padded := append(bytes.Clone(scenario.plain), make([]byte, pad)...)
	padded[len(padded)-1] = byte(pad)
	input := write(t, filepath.Join(suite.dir, "padded"), padded)
	cipherPath := filepath.Join(suite.dir, "cbc.bin")
	command(t, suite.fixture, true, nil, "openssl", "enc", "-des-ede3-cbc", "-nopad", "-K", hex.EncodeToString(cek), "-iv", "0000000000000000", "-in", input, "-out", cipherPath)
	wrappedPath := filepath.Join(suite.dir, "wrapped.bin")
	command(t, suite.fixture, true, nil, "openssl", "enc", "-id-smime-alg-CMS3DESwrap", "-K", hex.EncodeToString(read(t, scenario.keyfile)), "-in", cekPath, "-out", wrappedPath)
	ours := xmlDoc(t, raw)
	keyNode := one(t, tree.Root(ours), enc, "EncryptedKey")
	keyValue := one(t, keyNode, enc, "CipherValue")
	dataValue := legacyDataCipherValue(t, ours)
	external := bytes.Replace(raw, []byte(text(keyValue)), []byte(base64String(read(t, wrappedPath))), 1)
	ciphertext := append(make([]byte, 8), read(t, cipherPath)...)
	external = bytes.Replace(external, []byte(text(dataValue)), []byte(base64String(ciphertext)), 1)
	write(t, scenario.theirs, external)
	scenario.task[nameMode] = "decrypt-wrap"
	scenario.task[nameKey] = scenario.decryptKey
	scenario.task[nameInput] = scenario.theirs
	comparePlain(t, suite.fixture, probeData(t, suite.fixture, "nextprobe", scenario.task), scenario.plain, false)
	suite.count++
}

const ecdhKeyData = "ec,key-value,key-name,enc-key,agreement-method,aes,concatkdf"

func TestXMLSecECDHAgreement(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	for _, curve := range []struct {
		name    string
		openssl string
		curve   ecdh.Curve
	}{{"P256", "P-256", ecdh.P256()}, {"P384", "P-384", ecdh.P384()}, {"P521", "P-521", ecdh.P521()}} {
		recipient, err := curve.curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, data := range []struct {
			name string
			uri  string
			bits int
		}{{"GCM128", xmlenc.AES128GCM, 128}, {"GCM192", xmlenc.AES192GCM, 192}, {"GCM256", xmlenc.AES256GCM, 256}} {
			for _, wrap := range []struct {
				name  string
				uri   string
				bytes int
			}{{"KW128", xmlenc.AES128KeyWrap, 16}, {"KW192", xmlenc.AES192KeyWrap, 24}, {"KW256", xmlenc.AES256KeyWrap, 32}} {
				for _, hash := range []struct {
					name string
					hash crypto.Hash
				}{{"default", 0}, {"SHA256", crypto.SHA256}, {"SHA1", crypto.SHA1}} {
					t.Run(curve.name+"/"+data.name+"/"+wrap.name+"/"+hash.name, func(t *testing.T) {
						options := xmlenc.ECDHOptions{Data: xmlenc.Options{DataAlgorithm: data.uri}, KeyAlgorithm: wrap.uri, RecipientKeyName: "recipient"}
						if hash.hash != 0 {
							options.KDF = &xmlenc.ConcatKDFParameters{Hash: hash.hash, AlgorithmID: append([]byte{0}, []byte(wrap.uri)...), PartyUInfo: []byte{0, 'U'}, PartyVInfo: []byte{0, 'V'}, SuppPubInfo: []byte{0, 0, 0, 1, 0}, SuppPrivInfo: []byte{0, 0x42}, AllowLegacy: hash.hash == crypto.SHA1}
						}
						ecdhExchange(t, fixture, recipient, curve.openssl, data.bits, wrap.bytes, options)
					})
				}
			}
		}
	}
}

func ecdhPEM(t *testing.T, fixture *interopFixture, key *ecdh.PrivateKey) (string, string) {
	t.Helper()
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return write(t, filepath.Join(fixture.work, "ecdh-private.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})), write(t, filepath.Join(fixture.work, "ecdh-public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
}

func ecdhExchange(t *testing.T, fixture *interopFixture, recipient *ecdh.PrivateKey, curve string, dataBits, kekBytes int, options xmlenc.ECDHOptions) {
	t.Helper()
	private, public := ecdhPEM(t, fixture, recipient)
	plain := []byte("XMLENC ECDH interoperability\x00\xff")
	doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), plain, recipient.PublicKey(), options)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ours := write(t, filepath.Join(fixture.work, "ecdh-ours.xml"), raw)
	output := filepath.Join(fixture.work, "ecdh-plain.bin")
	// Modern xmlsec intentionally disables KeyValue data by default. Enable only
	// this fixture's finite EC/agreement/key-wrap vocabulary explicitly.
	native(t, fixture, true, "decrypt", "--enabled-key-data", ecdhKeyData, "--privkey-pem:recipient", private, "--output", output, ours)
	if !bytes.Equal(read(t, output), plain) {
		t.Fatal("xmlsec decrypt differs")
	}
	source := xmlDoc(t, clearCipherValues(t, raw))
	originator := one(t, tree.Root(source), enc, "OriginatorKeyInfo")
	originator.Children = []*tree.Node{{Kind: tree.ElementNode, Name: tree.Name{Space: ds, Local: "KeyName"}, Prefix: "ds", Children: []*tree.Node{{Kind: tree.TextNode, Data: "originator"}}}, {Kind: tree.ElementNode, Name: tree.Name{Space: ds, Local: "KeyValue"}, Prefix: "ds"}}
	receiver := one(t, tree.Root(source), enc, "RecipientKeyInfo")
	receiver.Children = receiver.Children[:1] // exact configured recipient KeyName
	template := write(t, filepath.Join(fixture.work, "ecdh-template.xml"), xmlBytes(t, source))
	sender := filepath.Join(fixture.work, "ecdh-originator.pem")
	command(t, fixture, true, nil, "openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:"+curve, "-out", sender)
	input := write(t, filepath.Join(fixture.work, "ecdh-input.bin"), plain)
	theirs := filepath.Join(fixture.work, "ecdh-theirs.xml")
	native(t, fixture, true, "encrypt", "--enabled-key-data", ecdhKeyData, "--privkey-pem:originator", sender, "--pubkey-pem:recipient", public, "--session-key", "aes-"+strconv.Itoa(dataBits), "--binary-data", input, "--output", theirs, template)
	external := read(t, theirs)
	imported, err := document.Parse(t.Context(), external, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if decrypted, err := xmlenc.DecryptBytesWithECDH(t.Context(), imported, recipient, options); err != nil || !bytes.Equal(decrypted, plain) {
		t.Fatal(decrypted, err)
	}
	ecdhOpenSSL(t, fixture, recipient, private, sender, external, kekBytes, options)
	if options.KDF == nil && dataBits == 128 && kekBytes == 32 && strings.HasSuffix(options.Data.DataAlgorithm, "-gcm") {
		corrupt := corruptCipher(t, raw)
		path := write(t, filepath.Join(fixture.work, "ecdh-corrupt.xml"), corrupt)
		native(t, fixture, false, "decrypt", "--enabled-key-data", ecdhKeyData, "--privkey-pem:recipient", private, path)
		if got, err := xmlenc.DecryptBytesWithECDH(t.Context(), xmlDoc(t, corrupt), recipient, options); got != nil || err == nil {
			t.Fatal(got, err)
		}
	}
	t.Log("P5_ORACLE xmlsec1 OpenSSL ECDH+ConcatKDF bidirectional")
}

func ecdhOpenSSL(t *testing.T, fixture *interopFixture, recipient *ecdh.PrivateKey, private, sender string, external []byte, kekBytes int, options xmlenc.ECDHOptions) {
	t.Helper()
	public := filepath.Join(fixture.work, "ecdh-sender-public.pem")
	command(t, fixture, true, nil, "openssl", "pkey", "-in", sender, "-pubout", "-out", public)
	secretFile := filepath.Join(fixture.work, "ecdh-secret.bin")
	command(t, fixture, true, nil, "openssl", "pkeyutl", "-derive", "-inkey", private, "-peerkey", public, "-out", secretFile)
	point := one(t, tree.Root(xmlDoc(t, external)), xmlenc.SignatureNamespace11, "PublicKey")
	peer, err := recipient.Curve().NewPublicKey(decode64(t, text(point)))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := recipient.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	if !bytes.Equal(secret, read(t, secretFile)) {
		t.Fatal("OpenSSL full-width ECDH secret differs")
	}
	var parameters xmlenc.ConcatKDFParameters
	if options.KDF != nil {
		parameters = *options.KDF
	} else {
		digest := sha256.Sum256(recipient.PublicKey().Bytes())
		parameters = xmlenc.ConcatKDFParameters{Hash: crypto.SHA256, AlgorithmID: append([]byte{0}, []byte(options.KeyAlgorithm)...), PartyUInfo: []byte{0}, PartyVInfo: append([]byte{0}, digest[:]...)}
	}
	ecdhOpenSSLKDF(t, fixture, secret, kekBytes, parameters)
}

func ecdhOpenSSLKDF(t *testing.T, fixture *interopFixture, secret []byte, kekBytes int, parameters xmlenc.ConcatKDFParameters) {
	t.Helper()
	other := []byte{}
	for _, field := range [][]byte{parameters.AlgorithmID, parameters.PartyUInfo, parameters.PartyVInfo, parameters.SuppPubInfo, parameters.SuppPrivInfo} {
		if len(field) > 0 {
			if field[0] != 0 {
				t.Fatal("whole-octet OpenSSL fixture required")
			}
			other = append(other, field[1:]...)
		}
	}
	digest := "SHA256"
	if parameters.Hash == crypto.SHA1 {
		digest = "SHA1"
	}
	out := filepath.Join(fixture.work, "ecdh-kdf.bin")
	command(t, fixture, true, nil, "openssl", "kdf", "-binary", "-out", out, "-keylen", strconv.Itoa(kekBytes), "-kdfopt", "digest:"+digest, "-kdfopt", "hexsecret:"+hex.EncodeToString(secret), "-kdfopt", "hexinfo:"+hex.EncodeToString(other), "SSKDF")
	ours, err := xmlenc.DeriveConcatKey(t.Context(), secret, kekBytes*8, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ours)
	if !bytes.Equal(ours, read(t, out)) {
		t.Fatal("OpenSSL ConcatKDF differs")
	}
}

func TestXMLSecECDHLegacyData(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	recipient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []struct {
		name string
		uri  string
		bits int
	}{{"CBC128", xmlenc.AES128CBC, 128}, {"CBC192", xmlenc.AES192CBC, 192}, {"CBC256", xmlenc.AES256CBC, 256}, {"TripleDES", xmlenc.TripleDESCBC, 192}} {
		t.Run(data.name, func(t *testing.T) {
			options := xmlenc.ECDHOptions{Data: xmlenc.Options{DataAlgorithm: data.uri, AllowLegacy: true}, KeyAlgorithm: xmlenc.AES256KeyWrap, RecipientKeyName: "recipient"}
			if data.uri != xmlenc.TripleDESCBC {
				ecdhExchange(t, fixture, recipient, "P-256", data.bits, 32, options)
				return
			}
			private, _ := ecdhPEM(t, fixture, recipient)
			plain := []byte("ECDH and legacy TripleDES\x00\xff")
			doc, err := xmlenc.EncryptBytesWithECDH(t.Context(), plain, recipient.PublicKey(), options)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := doc.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			input := write(t, filepath.Join(fixture.work, "ecdh-3des.xml"), raw)
			output := filepath.Join(fixture.work, "ecdh-3des-plain.bin")
			native(t, fixture, true, "decrypt", "--enabled-key-data", ecdhKeyData+",des", "--privkey-pem:recipient", private, "--output", output, input)
			if !bytes.Equal(read(t, output), plain) {
				t.Fatal("xmlsec TripleDES decrypt differs")
			}
			t.Log("P5_ORACLE xmlsec1 ECDH/AES256KW/TripleDES decryption; reverse DES CEK parity independently covered by LegacyEncryption")
		})
	}
}

func TestXMLSecECDHLeadingZero(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	scalar := make([]byte, 32)
	scalar[31] = 1
	recipient, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	scalar[30], scalar[31] = 1, 123 // 379G begins with the zero x-coordinate octet.
	originator, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := ecdhPEM(t, fixture, recipient)
	senderDER, err := x509.MarshalPKIXPublicKey(originator.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sender := write(t, filepath.Join(fixture.work, "zero-peer.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: senderDER}))
	out := filepath.Join(fixture.work, "zero-secret.bin")
	command(t, fixture, true, nil, "openssl", "pkeyutl", "-derive", "-inkey", private, "-peerkey", sender, "-out", out)
	secret, err := recipient.ECDH(originator.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	if len(secret) != 32 || secret[0] != 0 || !bytes.Equal(read(t, out), secret) {
		t.Fatal("leading-zero ECDH octet was lost")
	}
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA1} {
		t.Run(hash.String(), func(t *testing.T) {
			parameters := xmlenc.ConcatKDFParameters{Hash: hash, AlgorithmID: []byte{0}, PartyUInfo: []byte{0}, PartyVInfo: []byte{0}, AllowLegacy: hash == crypto.SHA1}
			ecdhOpenSSLKDF(t, fixture, secret, 32, parameters)
		})
	}
	t.Log("P5_ORACLE OpenSSL full-width leading-zero ECDH and multi-round ConcatKDF")
}

// TestXMLSecEncryptionGrammar checks exact XMLENC field grammar against the
// published schemas, independently of cryptographic provider failure handling.
func TestXMLSecEncryptionGrammar(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	schema := encryptionSchema(t, fixture)
	dir := t.TempDir()
	key := generateKey(t, dir, nameRsaSha256)
	suite := encryptionSuite{fixture: fixture, dir: dir, key: key}
	scenario := suite.prepare(t, encryptionRecipe{mode: nameRsa, bits: 256, label: []byte("schema-label")}, false)
	raw := probeData(t, fixture, "nextprobe", scenario.task)
	for name, c := range encryptionGrammarCases(t, raw) {
		t.Run(name, func(t *testing.T) {
			path := write(t, filepath.Join(t.TempDir(), "input.xml"), c.wire)
			schemaValid := c.valid
			if name == "CipherValue lexical base64" {
				// XSD1.0 section3.2.16's B64 production excludes '!':
				// https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary
				// This libxml2 validator accepts it; the corresponding native
				// rejection is enforced under the published lexical grammar.
				schemaValid = true
				t.Log("DIAGNOSTIC libxml2 schema validation accepts CipherValue '!'; excluded from Base64 lexical rejection agreement")
			}
			command(t, fixture, schemaValid, nil, "xmllint", "--nonet", "--noout", "--schema", schema, path)
			check := copyTask(scenario.task)
			check[nameMode], check[nameInput], check[nameKey] = "decrypt", path, scenario.decryptKey
			if c.valid {
				comparePlain(t, fixture, probeData(t, fixture, "nextprobe", check), scenario.plain, false)
				native(t, fixture, true, "decrypt", scenario.decryptArg, scenario.decryptKey, "--output", scenario.output, path)
				comparePlain(t, fixture, read(t, scenario.output), scenario.plain, false)
			} else {
				probe(t, fixture, "nextprobe", check, false)
			}
		})
	}
}

type encryptionGrammarCase struct {
	wire  []byte
	valid bool
}

func encryptionGrammarCases(t *testing.T, wire []byte) map[string]encryptionGrammarCase {
	t.Helper()
	change := func(from, to string) []byte {
		t.Helper()
		if !bytes.Contains(wire, []byte(from)) {
			t.Fatal("ineffective schema control", from)
		}
		return bytes.Replace(wire, []byte(from), []byte(to), 1)
	}
	root := xmlDoc(t, wire)
	value := `<xenc:CipherValue>` + text(legacyDataCipherValue(t, root)) + `</xenc:CipherValue>`
	data := `<xenc:CipherData>` + value + `</xenc:CipherData>`
	label := `<xenc:OAEPparams>` + base64String([]byte("schema-label")) + `</xenc:OAEPparams>`
	digest := `<ds:DigestMethod Algorithm="` + enc + `sha256"></ds:DigestMethod>`
	mgf := `<xenc11:MGF Algorithm="` + enc11 + `mgf1sha256"></xenc11:MGF>`
	method := `<xenc:EncryptionMethod Algorithm="` + enc11 + `rsa-oaep">`
	dataMethod := `<xenc:EncryptionMethod Algorithm="` + enc11 + `aes256-gcm">`
	aliases := strings.NewReplacer("xmlns:xenc11=", "xmlns:new11=", "xenc11:", "new11:", "xmlns:xenc=", "xmlns:new=", "xenc:", "new:", "xmlns:ds=", "xmlns:sig=", "ds:", "sig:")
	cases := map[string]encryptionGrammarCase{
		"original":                       {wire, true},
		"renamed prefixes":               {[]byte(aliases.Replace(string(wire))), true},
		"default XMLENC namespace":       {[]byte(strings.NewReplacer("xmlns:xenc=", "xmlns=", "xenc:", "").Replace(string(wire))), true},
		"foreign parameter order":        {change(digest+mgf, mgf+digest), true},
		"KeySize first":                  {change(dataMethod, dataMethod+`<xenc:KeySize>256</xenc:KeySize>`), true},
		"duplicate KeySize":              {change(method, method+`<xenc:KeySize>2048</xenc:KeySize><xenc:KeySize>2048</xenc:KeySize>`), false},
		"misplaced KeySize":              {change(digest, digest+`<xenc:KeySize>2048</xenc:KeySize>`), false},
		"misplaced OAEPparams":           {change(label+digest, digest+label), false},
		"MGF missing Algorithm":          {change(mgf, `<xenc11:MGF/>`), false},
		"MGF unknown attribute":          {change(mgf, `<xenc11:MGF Algorithm="`+enc11+`mgf1sha256" other="1"/>`), false},
		"MGF child":                      {change(mgf, `<xenc11:MGF Algorithm="`+enc11+`mgf1sha256"><xenc11:Parameters/></xenc11:MGF>`), false},
		"neither CipherData alternative": {change(data, `<xenc:CipherData/>`), false},
		"both CipherData alternatives":   {change(data, `<xenc:CipherData>`+value+`<xenc:CipherReference URI="urn:unused"/></xenc:CipherData>`), false},
		"duplicate CipherValue":          {change(data, `<xenc:CipherData>`+value+value+`</xenc:CipherData>`), false},
		"CipherData character content":   {change(data, `<xenc:CipherData>unexpected`+value+`</xenc:CipherData>`), false},
		"CipherData unknown attribute":   {change(data, `<xenc:CipherData other="1">`+value+`</xenc:CipherData>`), false},
		"CipherValue child":              {change(data, `<xenc:CipherData><xenc:CipherValue><xenc:CipherValue/></xenc:CipherValue></xenc:CipherData>`), false},
		"CipherValue lexical base64":     {change(data, `<xenc:CipherData><xenc:CipherValue>!</xenc:CipherValue></xenc:CipherData>`), false},
	}
	for _, namespace := range []string{enc, enc11, ds} {
		cases["wrong namespace/"+namespace] = encryptionGrammarCase{change(`="`+namespace+`"`, `="urn:wrong-namespace"`), false}
	}
	return cases
}

func encryptionSchema(t *testing.T, fixture *interopFixture) string {
	t.Helper()
	dir := os.Getenv("XMLENC_SCHEMA_DIR")
	if dir == "" {
		if os.Getenv("XMLSEC_REQUIRE_P5_PROOFS") == "1" {
			t.Fatal("XMLENC_SCHEMA_DIR is required for the published XMLENC schema proof")
		}
		t.Skip("set XMLENC_SCHEMA_DIR to the four pinned published XMLENC/XMLDSig schemas")
	}
	pins := map[string]string{
		"xenc-schema.xsd":         "c5301a890b0265a705f0806269aa37345aa47d7245a78900b941af65290b16fa",
		"xenc-schema-11.xsd":      "2b48432f036262345638536601d4ea3224897e2d41901163c04eebf350477958",
		"xenc-schema-2002.xsd":    "5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e",
		"xmldsig-core-schema.xsd": "35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c",
	}
	local := t.TempDir()
	for name, pin := range pins {
		data := read(t, filepath.Join(dir, name))
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != pin {
			t.Fatal("published schema pin mismatch", name)
		}
		write(t, filepath.Join(local, name), data)
	}
	// XMLENC1.1 imports the exact2002 XMLENC/XMLDSig schemas. The entry
	// schema also loads the REC2013 core. A local catalog supplies original
	// published bytes without network access or rewriting schema definitions.
	uri := func(name string) string {
		return html.EscapeString((&url.URL{Scheme: "file", Path: filepath.Join(local, name)}).String())
	}
	catalog := `<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog"><uri name="http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd" uri="` + uri("xmldsig-core-schema.xsd") + `"/><uri name="http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd" uri="` + uri("xenc-schema-2002.xsd") + `"/></catalog>`
	t.Setenv("XML_CATALOG_FILES", write(t, filepath.Join(local, "catalog.xml"), []byte(catalog)))
	entry := `<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:import namespace="` + enc + `" schemaLocation="` + uri("xenc-schema.xsd") + `"/><xs:import namespace="` + enc11 + `" schemaLocation="` + uri("xenc-schema-11.xsd") + `"/></xs:schema>`
	return write(t, filepath.Join(fixture.work, "xmlenc-proof-schema.xsd"), []byte(entry))
}

// TestXMLSecKeyGraph exercises actual XML relationships, in addition to the
// primitive RFC vectors. Every oracle result is checked against plaintext.
func TestXMLSecKeyGraph(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	plain := []byte("XMLENC key graph\x00\xff")
	secret, kek := bytes.Repeat([]byte{0x52}, 32), bytes.Repeat([]byte{0x93}, 32)
	wrap := func(raw, kek []byte, name, id, carried string) *document.Document {
		t.Helper()
		doc, err := xmlenc.EncryptKey(t.Context(), raw, xmlenc.KeyGraphKey{Name: name, Algorithm: xmlenc.AES256KeyWrap, Secret: kek}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap, ID: id, CarriedKeyName: carried})
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	wrapped := wrap(secret, kek, "master", "key", "session")
	options := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}}}
	for _, kind := range []string{"inline", "retrieval", "carried", "nested"} {
		t.Run(kind, func(t *testing.T) {
			data, err := xmlenc.EncryptBytesWithKey(t.Context(), plain, secret, xmlenc.SymmetricOptions{})
			if err != nil {
				t.Fatal(err)
			}
			raw := xmlBytes(t, data)
			info := string(xmlBytes(t, wrapped))
			sibling := ""
			switch kind {
			case "retrieval":
				info = `<ds:RetrievalMethod URI="#key" Type="` + enc + `EncryptedKey"/>`
				sibling = string(xmlBytes(t, wrapped))
			case "carried":
				info = `<ds:KeyName>session</ds:KeyName>`
				sibling = string(xmlBytes(t, wrapped))
			case "nested":
				intermediate := bytes.Repeat([]byte{0x24}, 32)
				outer := wrap(intermediate, kek, "master", "outer", "")
				inner := wrap(secret, intermediate, "intermediate", "inner", "")
				info = strings.Replace(string(xmlBytes(t, inner)), `<ds:KeyName>intermediate</ds:KeyName>`, string(xmlBytes(t, outer)), 1)
			}
			wire := strings.Replace(string(raw), "<xenc:CipherData>", "<ds:KeyInfo>"+info+"</ds:KeyInfo><xenc:CipherData>", 1)
			if sibling != "" {
				wire = "<root>" + wire + sibling + "</root>"
			}
			doc := xmlDoc(t, []byte(wire))
			target := doc.Root()
			if sibling != "" {
				target = target.Children()[0]
			}
			got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, target, options)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatal("native key relationship", err)
			}
			path := write(t, filepath.Join(t.TempDir(), "graph.xml"), []byte(wire))
			keyfile := write(t, filepath.Join(t.TempDir(), "kek.bin"), kek)
			output := filepath.Join(t.TempDir(), "plaintext.bin")
			if kind == "carried" {
				native(t, fixture, false, "decrypt", "--id-attr:Id", enc+":EncryptedKey", "--aeskey:master", keyfile, path)
				t.Log("DIAGNOSTIC xmlsec1 does not discover this sibling through CarriedKeyName alone; explicit RetrievalMethod control is compared separately")
				controlled := strings.Replace(wire, `<ds:KeyName>session</ds:KeyName>`, `<ds:RetrievalMethod URI="#key" Type="`+enc+`EncryptedKey"/>`, 1)
				if controlled == wire {
					t.Fatal("carried-name intervention did not change fixture")
				}
				controlledDoc := xmlDoc(t, []byte(controlled))
				controlledPlain, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), controlledDoc, controlledDoc.Root().Children()[0], options)
				if err != nil || !bytes.Equal(controlledPlain, plain) {
					t.Fatal("retrieval control", err)
				}
				path = write(t, filepath.Join(t.TempDir(), "carried-retrieval-control.xml"), []byte(controlled))
			}
			native(t, fixture, true, "decrypt", "--id-attr:Id", enc+":EncryptedKey", "--aeskey:master", keyfile, "--output", output, path)
			if !bytes.Equal(read(t, output), plain) {
				t.Fatal("xmlsec graph plaintext differs")
			}
			if kind == "carried" {
				t.Log("P5_ORACLE xmlsec1 carried-name explicit RetrievalMethod control")
			} else {
				t.Log("P5_ORACLE xmlsec1 AES key graph", kind)
			}
		})
	}
}

func TestXMLSecECDHKeyGraph(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	recipient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := ecdhPEM(t, fixture, recipient)
	plain := []byte("ECDH key graph\x00\xff")
	secret := bytes.Repeat([]byte{0x16}, 32)
	wrapped, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHPublicKey: recipient.PublicKey()}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap, ID: "outer"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"inline", "retrieval", "nested"} {
		t.Run(kind, func(t *testing.T) {
			data, err := xmlenc.EncryptBytesWithKey(t.Context(), plain, secret, xmlenc.SymmetricOptions{})
			if err != nil {
				t.Fatal(err)
			}
			keywire := string(xmlBytes(t, wrapped))
			outerwire := ""
			algorithms := []string(nil)
			if kind == "nested" {
				middle := bytes.Repeat([]byte{0x42}, 16)
				outer, err := xmlenc.EncryptKey(t.Context(), middle, xmlenc.KeyGraphKey{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHPublicKey: recipient.PublicKey()}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap, ID: "outer"})
				if err != nil {
					t.Fatal(err)
				}
				inner, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: "middle", Algorithm: xmlenc.AES128KeyWrap, Secret: middle}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES128KeyWrap, ID: "inner"})
				if err != nil {
					t.Fatal(err)
				}
				innerwire := strings.Replace(string(xmlBytes(t, inner)), `<ds:KeyName>middle</ds:KeyName>`, `<ds:RetrievalMethod URI="#outer" Type="`+enc+`EncryptedKey"/>`, 1)
				outerwire = string(xmlBytes(t, outer))
				keywire = innerwire + outerwire
				algorithms = []string{xmlenc.AES128KeyWrap}
			}
			info := string(xmlBytes(t, wrapped))
			if kind == "retrieval" || kind == "nested" {
				id := "outer"
				if kind == "nested" {
					id = "inner"
				}
				info = `<ds:RetrievalMethod URI="#` + id + `" Type="` + enc + `EncryptedKey"/>`
			}
			datawire := strings.Replace(string(xmlBytes(t, data)), "<xenc:CipherData>", `<ds:KeyInfo>`+info+`</ds:KeyInfo><xenc:CipherData>`, 1)
			wire := []byte(datawire)
			if kind != "inline" {
				wire = []byte("<root>" + datawire + keywire + "</root>")
			}
			doc := xmlDoc(t, wire)
			target := doc.Root()
			if kind != "inline" {
				target = target.Children()[0]
			}
			opts := xmlenc.KeyGraphOptions{Keys: []xmlenc.KeyGraphKey{{Name: "recipient", Algorithm: xmlenc.AES256KeyWrap, ECDHRecipient: recipient}}, KeyAlgorithms: algorithms}
			got, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, target, opts)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatal("ECDH graph", err)
			}
			path := write(t, filepath.Join(t.TempDir(), "ecdh-graph.xml"), wire)
			output := filepath.Join(t.TempDir(), "plain.bin")
			if kind == "nested" {
				native(t, fixture, false, "decrypt", "--id-attr:Id", enc+":EncryptedKey", "--enabled-key-data", ecdhKeyData+",retrieval-method", "--privkey-pem:recipient", private, path)
				t.Log("DIAGNOSTIC xmlsec1 refuses this two-hop RetrievalMethod chain; one-hop control with the same outer ECDH key inline is compared separately")
				controlled := strings.Replace(string(wire), `<ds:RetrievalMethod URI="#outer" Type="`+enc+`EncryptedKey"/>`, outerwire, 1)
				// Remove the detached copy after moving that exact key inline, preserving unique IDs.
				last := strings.LastIndex(controlled, outerwire)
				if last < 0 {
					t.Fatal("missing detached outer key")
				}
				controlled = controlled[:last] + controlled[last+len(outerwire):]
				controlledDoc := xmlDoc(t, []byte(controlled))
				controlledPlain, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), controlledDoc, controlledDoc.Root().Children()[0], opts)
				if err != nil || !bytes.Equal(controlledPlain, plain) {
					t.Fatal("single-retrieval ECDH control", err)
				}
				path = write(t, filepath.Join(t.TempDir(), "single-hop-control.xml"), []byte(controlled))
			}
			native(t, fixture, true, "decrypt", "--id-attr:Id", enc+":EncryptedKey", "--enabled-key-data", ecdhKeyData+",retrieval-method", "--privkey-pem:recipient", private, "--output", output, path)
			if !bytes.Equal(read(t, output), plain) {
				t.Fatal("xmlsec ECDH graph plaintext differs")
			}
			if kind == "nested" {
				t.Log("P5_ORACLE xmlsec1 mixed-size ECDH nested key graph one-hop control")
			} else {
				t.Log("P5_ORACLE xmlsec1 explicit ECDH standalone-key graph", kind)
			}
		})
	}
}

func TestXMLSecKeyGraphSchemas(t *testing.T) {
	fixture := newInteropFixture(t)
	schema := encryptionSchema(t, fixture)
	secret, kek := bytes.Repeat([]byte{0x52}, 32), bytes.Repeat([]byte{0x93}, 32)
	wrapped, err := xmlenc.EncryptKey(t.Context(), secret, xmlenc.KeyGraphKey{Name: "master", Algorithm: xmlenc.AES256KeyWrap, Secret: kek}, xmlenc.EncryptedKeyOptions{Algorithm: xmlenc.AES256KeyWrap, ID: "key", CarriedKeyName: " session "})
	if err != nil {
		t.Fatal(err)
	}
	path := write(t, filepath.Join(t.TempDir(), "encrypted-key.xml"), xmlBytes(t, wrapped))
	command(t, fixture, true, nil, "xmllint", "--nonet", "--noout", "--schema", schema, path)
	derived, err := xmlenc.BuildDerivedKey(t.Context(), xmlenc.DerivedKeyOptions{Parameters: xmlenc.ConcatKDFParameters{AlgorithmID: []byte{0, 1}, PartyUInfo: []byte{3, 0xd8}}, ID: "derived", MasterKeyName: "master", DerivedKeyName: "derived key", References: []xmlenc.KeyGraphReference{{URI: "#data"}, {URI: "#key", Key: true}}})
	if err != nil {
		t.Fatal(err)
	}
	path = write(t, filepath.Join(t.TempDir(), "derived-key.xml"), xmlBytes(t, derived))
	command(t, fixture, true, nil, "xmllint", "--nonet", "--noout", "--schema", schema, path)
	for _, body := range []struct {
		name    string
		content string
		valid   bool
	}{{"foreign element", `<app:note xmlns:app="urn:app">hint</app:note>`, true}, {"empty", "", false}, {"text only", "hint", false}, {"same namespace", `<xenc:note/>`, false}, {"no namespace", `<note/>`, false}} {
		t.Run(body.name, func(t *testing.T) {
			wire := strings.Replace(string(xmlBytes(t, wrapped)), "<xenc:CarriedKeyName>", `<xenc:EncryptionProperties Id="properties"><xenc:EncryptionProperty Target="#data">`+body.content+`</xenc:EncryptionProperty></xenc:EncryptionProperties><xenc:CarriedKeyName>`, 1)
			if !strings.Contains(wire, "EncryptionProperties") {
				t.Fatal("property intervention did not change fixture")
			}
			path := write(t, filepath.Join(t.TempDir(), "properties.xml"), []byte(wire))
			command(t, fixture, body.valid, nil, "xmllint", "--nonet", "--noout", "--schema", schema, path)
		})
	}
	t.Log("P5_ORACLE pinned published XMLENC schemas: standalone EncryptedKey, DerivedKey, and property cardinality/namespace")
}

func TestXMLSecImplicitCipherCanonicalization(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "xmlsec")
	key := bytes.Repeat([]byte{0x0e}, 16)
	keyfile := write(t, filepath.Join(t.TempDir(), "aes128.key"), key)
	want, err := hex.DecodeString("cea85e37d6cbce0572990f541088335ab8d6e8d01f385d6d19ad35c8d0fa0a")
	if err != nil {
		t.Fatal(err)
	}
	for name, node := range map[string]string{
		"canonical input":               `<b a="a" z="z" xml:id="c">AAAAAAAAAAAAAAAAAA</b>`,
		"reordered and commented input": `<b z='z' xml:id='c' a='a'>AAAAAAAAA<!--omitted-->AAAAAAAAA</b>`,
	} {
		t.Run(name, func(t *testing.T) {
			wire := `<r>` + node + `<xenc:EncryptedData xmlns:xenc="` + enc + `"><xenc:EncryptionMethod Algorithm="` + enc + `aes128-cbc"/><xenc:CipherData><xenc:CipherReference URI="#c"/></xenc:CipherData></xenc:EncryptedData></r>`
			doc, err := document.Parse(t.Context(), []byte(wire), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			options := xmlenc.KeyGraphOptions{Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128CBC, AllowLegacy: true}, Keys: []xmlenc.KeyGraphKey{{Algorithm: xmlenc.AES128CBC, Secret: key}}}
			out, err := xmlenc.DecryptBytesWithKeyGraph(t.Context(), doc, doc.Root().Children()[1], options)
			if err != nil || !bytes.Equal(out, want) {
				t.Fatal(out, err)
			}
			input := write(t, filepath.Join(t.TempDir(), "cipher.xml"), []byte(wire))
			output := filepath.Join(t.TempDir(), "plaintext")
			native(t, fixture, true, "decrypt", "--aeskey", keyfile, "--output", output, input)
			comparePlain(t, fixture, read(t, output), want, false)
		})
	}
}
