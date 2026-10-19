//go:build interop

package interop_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
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
	recipes := make([]encryptionRecipe, 0, 23)

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
	mode          string
	bits, wrap    int
	hash, keyName string
	label         []byte
}

type encryptionCase struct {
	recipe                                              encryptionRecipe
	xml                                                 bool
	plain                                               []byte
	source, ours, theirs, output                        string
	keyfile, decryptKey, encryptArg, decryptArg, suffix string
	task                                                map[string]any
}

type encryptionSuite struct {
	fixture          *interopFixture
	dir              string
	key              testKey
	count, resources int
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

		keyfile = write(t, filepath.Join(suite.dir, "kek"), randomBytes(t, n))
		decryptKey = keyfile
	}

	encryptArg, decryptArg := nativeKeyArgs(r.mode, r.keyName)

	suffix := ""
	if r.mode != nameRsa {
		suffix = "-" + r.mode
	}

	keyAlgorithm := enc11 + "rsa-oaep"
	if r.mode == nameWrap {
		keyAlgorithm = enc + "kw-aes" + strconv.Itoa(r.wrap)
	}

	task := map[string]any{nameMode: "encrypt" + suffix, nameKey: keyfile, nameInput: source, "XML": xml, nameDataAlgorithm: enc11 + fmt.Sprintf("aes%d-gcm", r.bits), nameKeyAlgorithm: keyAlgorithm, "OAEPHash": r.hash, "OAEPLabel": r.label, "KeyName": r.keyName}

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
		args = append(args, "--session-key", fmt.Sprintf("aes-%d", scenario.recipe.bits))
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
	bits, wrap int
	form, cm   string
}

type selectedEncryptionCase struct {
	recipe                                              selectedEncryptionRecipe
	original, raw                                       []byte
	source, ours, theirs, output                        string
	keyfile, decryptKey, encryptArg, decryptArg, suffix string
	task                                                map[string]any
	empty                                               bool
}

type selectedEncryptionSuite struct {
	fixture                *interopFixture
	dir, cli, buffer, kind string
	key                    testKey
	count, emptyCount      int
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
