//go:build interop

package interop_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

// TestEncryptionPrimitives compares all data/key-wrap sizes with OpenSSL EVP,
// including empty plaintext, which xmlsec1's XML output path cannot represent.
func TestEncryptionPrimitives(t *testing.T) {
	fixture := newInteropFixture(t)

	selected(t, "portable")
	dir := t.TempDir()
	key := generateKey(t, dir, nameRsaSha256)
	gcm := filepath.Join(dir, "openssl-gcm")
	flags, _ := command(t, fixture, true, nil, "pkg-config", "--cflags", "--libs", "openssl")
	libraryFlags := strings.Fields(string(flags))
	args := make([]string, 0, 8+len(libraryFlags))
	args = append(args, "-std=c11", flagO2, flagWall, flagWextra, flagWerror, filepath.Join(fixture.root, "tests/interop/testdata/openssl-gcm.c"))
	command(t, fixture, true, nil, "cc", append(append(args, libraryFlags...), "-o", gcm)...)

	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i)
	}

	payloads := [][]byte{{}, []byte("hello\x00\xff"), data, []byte(`<r>XML &amp; text</r>`)}
	count := 0

	for _, bits := range []int{128, 192, 256} {
		for _, wrap := range []int{0, 128, 192, 256} {
			for index, plain := range payloads {
				t.Run(fmt.Sprintf("gcm%d/wrap%d/payload%d", bits, wrap, index), func(t *testing.T) {
					testEncryptionPrimitivesCase(t, &dir, &plain, &key, &wrap, &index, &bits, &fixture, &gcm, &count)
				})
			}
		}
	}

	t.Logf("%d OpenSSL EVP encryption exchanges each direction, including empty input and key/tag/algorithm negative controls", count)
}

func testEncryptionPrimitivesCase(t *testing.T, dir *string, plain *[]byte, key *testKey, wrap *int, index *int, bits *int, fixture **interopFixture, gcm *string, count *int) {
	source := write(t, filepath.Join((*dir), "plain"), (*plain))
	keyfile, decryptKey, suffix := key.public, key.private, ""
	algorithm := enc11 + "rsa-oaep"

	var kek []byte
	if (*wrap) > 0 {
		kek = randomBytes(t, (*wrap)/8)
		keyfile = write(t, filepath.Join((*dir), "kek"), kek)
		decryptKey = keyfile
		suffix = "-wrap"
		algorithm = enc + fmt.Sprintf("kw-aes%d", (*wrap))
	}

	task := map[string]any{nameMode: "encrypt" + suffix, nameInput: source, nameKey: keyfile, "XML": (*index) == 3, nameDataAlgorithm: enc11 + fmt.Sprintf("aes%d-gcm", (*bits)), nameKeyAlgorithm: algorithm}
	raw := probeData(t, (*fixture), "nextprobe", task)
	d := xmlDoc(t, raw)
	envelope := one(t, tree.Root(d), enc, nameEncryptedData)
	wrappedKey := one(t, envelope, enc, "EncryptedKey")
	wrappedValue := one(t, wrappedKey, enc, "CipherValue")

	var dataValue *tree.Node

	for _, n := range envelope.Children {
		if n.Name.Space == enc && n.Name.Local == nameCipherData {
			dataValue = one(t, n, enc, "CipherValue")
		}
	}

	if dataValue == nil {
		t.Fatal("data ciphertext")
	}

	wrappedPath := write(t, filepath.Join((*dir), "wrapped"), decode64(t, text(wrappedValue)))
	symmetric := filepath.Join((*dir), "symmetric")
	ciphertext := write(t, filepath.Join((*dir), "ciphertext"), decode64(t, text(dataValue)))
	output := filepath.Join((*dir), "output")
	wrapKey := func(encrypt bool) {
		if (*wrap) == 0 {
			mode := "-decrypt"
			k := key.private
			extra := []string{}

			if encrypt {
				mode = "-encrypt"
				k = key.public
				extra = []string{"-pubin"}
			}

			in, out := wrappedPath, symmetric
			if encrypt {
				in, out = symmetric, wrappedPath
			}

			params := append(make([]string, 0, 4+len(extra)+10), []string{"pkeyutl", mode, flagInkey, k}...)
			params = append(params, extra...)
			command(t, (*fixture), true, nil, "openssl", append(params, flagIn, in, flagOut, out, "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256")...)
		} else {
			params := []string{"enc", fmt.Sprintf("-id-aes%d-wrap", (*wrap)), "-K", hex.EncodeToString(kek), "-iv", "A6A6A6A6A6A6A6A6"}
			in, out := symmetric, wrappedPath

			if !encrypt {
				params = append(params, "-d")
				in, out = wrappedPath, symmetric
			}

			command(t, (*fixture), true, nil, "openssl", append(params, flagIn, in, flagOut, out)...)
		}
	}
	wrapKey(false)

	if len(read(t, symmetric)) != (*bits)/8 {
		t.Fatal("session key length")
	}

	command(t, (*fixture), true, nil, (*gcm), "decrypt", symmetric, ciphertext, output)

	if !bytes.Equal(read(t, output), (*plain)) {
		t.Fatal("OpenSSL plaintext differs")
	}

	write(t, symmetric, randomBytes(t, (*bits)/8))
	command(t, (*fixture), true, nil, (*gcm), "encrypt", symmetric, source, ciphertext)
	wrapKey(true)
	setText(wrappedValue, base64String(read(t, wrappedPath)))
	setText(dataValue, base64String(read(t, ciphertext)))
	reverse := write(t, filepath.Join((*dir), "reverse.xml"), xmlBytes(t, d))
	task[nameMode] = "decrypt" + suffix
	task[nameInput] = reverse
	task[nameKey] = decryptKey
	comparePlain(t, (*fixture), probeData(t, (*fixture), "nextprobe", task), (*plain), (*index) == 3)

	for _, value := range []*tree.Node{wrappedValue, dataValue} {
		original := text(value)
		b := decode64(t, original)
		b[len(b)-1] ^= 1
		setText(value, base64String(b))
		write(t, reverse, xmlBytes(t, d))
		probe(t, (*fixture), "nextprobe", task, false)
		setText(value, original)
	}

	wrong := copyTask(task)

	wrong[nameDataAlgorithm] = enc11 + "aes128-gcm"
	if (*bits) == 128 {
		wrong[nameDataAlgorithm] = enc11 + "aes192-gcm"
	}

	write(t, reverse, xmlBytes(t, d))
	probe(t, (*fixture), "nextprobe", wrong, false)
	badCipher := read(t, ciphertext)
	badCipher[len(badCipher)-1] ^= 1
	write(t, ciphertext, badCipher)
	os.Remove(output)
	command(t, (*fixture), false, nil, (*gcm), "decrypt", symmetric, ciphertext, output)
	noOutput(t, output)

	(*count)++
}
