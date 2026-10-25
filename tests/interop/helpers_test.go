//go:build interop

// Package interop_test runs optional comparisons against independent engines.
// Keys and inputs are generated locally; tests never resolve network resources.
package interop_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil"
)

const (
	ds    = "http://www.w3.org/2000/09/xmldsig#"
	more  = "http://www.w3.org/2001/04/xmldsig-more#"
	exc   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	c10   = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	c11   = "http://www.w3.org/2006/12/xml-c14n11"
	enc   = "http://www.w3.org/2001/04/xmlenc#"
	enc11 = "http://www.w3.org/2009/xmlenc11#"
)

func canonicalizations() []string {
	return []string{exc, exc + "WithComments", c10, c10 + "#WithComments", c11, c11 + "#WithComments"}
}

func digests() []string { return []string{enc + nameSha256, more + "sha384", enc + "sha512"} }

func javaExports() []string {
	return []string{"--add-exports=java.xml.crypto/com.sun.org.apache.xml.internal.security=ALL-UNNAMED", "--add-exports=java.xml.crypto/com.sun.org.apache.xml.internal.security.c14n=ALL-UNNAMED"}
}

func selected(t *testing.T, suite string) {
	t.Helper()

	for _, s := range strings.Split(flag.Lookup("suite").Value.String(), ",") {
		if s == suite || s == "all" {
			return
		}
	}

	t.Skip("optional suite:", suite)
}

func command(t *testing.T, fixture *interopFixture, success bool, input []byte, name string, args ...string) ([]byte, []byte) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	c := exec.CommandContext(ctx, name, args...)
	c.Dir = fixture.root
	c.Stdin = bytes.NewReader(input)

	var out, errout bytes.Buffer

	c.Stdout = &out
	c.Stderr = &errout
	err := c.Run()

	if ctx.Err() != nil {
		t.Fatalf("%s: %v", name, ctx.Err())
	}

	if (err == nil) != success {
		t.Fatalf("%s %q: error=%v, expected success=%v\n%s\n%s", name, args, err, success, out.Bytes(), errout.Bytes())
	}

	return out.Bytes(), errout.Bytes()
}

func write(t *testing.T, path string, data []byte) string {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func read(t *testing.T, path string) []byte {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func decode(t *testing.T, data []byte, out any) {
	t.Helper()

	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("JSON: %v: %s", err, data)
	}
}

func probe(t *testing.T, fixture *interopFixture, name string, task any, success bool) map[string]json.RawMessage {
	t.Helper()

	data, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := command(t, fixture, true, data, binary(t, fixture, name))

	var result map[string]json.RawMessage
	decode(t, raw, &result)

	if (len(result["error"]) == 0) != success {
		t.Fatalf("probe %s: expected success=%v: %s", name, success, raw)
	}

	if !success && len(result["data"]) != 0 {
		t.Fatalf("probe returned data after error: %s", raw)
	}

	return result
}

func probeData(t *testing.T, fixture *interopFixture, name string, task any) []byte {
	t.Helper()

	r := probe(t, fixture, name, task, true)
	if len(r["data"]) == 0 {
		return []byte{}
	}

	var b []byte
	decode(t, r["data"], &b)

	return b
}

func binary(t *testing.T, fixture *interopFixture, name string) string {
	t.Helper()

	if path := fixture.binaries[name]; path != "" {
		return path
	}

	path := filepath.Join(fixture.work, name)

	source := "./tests/interop/cmd/" + name
	if name == "xmlsec" {
		source = "./cmd/xmlsec"
	}

	command(t, fixture, true, nil, "go", "build", "-o", path, source)
	fixture.binaries[name] = path

	return path
}

func java(t *testing.T, fixture *interopFixture, class string, args ...string) []byte {
	t.Helper()
	compileJava(t, fixture)

	params := append(append([]string{}, javaExports()...), "-Djdk.xml.xpathExprOpLimit=10000", "-Djdk.xml.xpathExprGrpLimit=10000", "-cp", fixture.work, class)
	data, _ := command(t, fixture, true, nil, "java", append(params, args...)...)

	return data
}

func compileJava(t *testing.T, fixture *interopFixture) {
	t.Helper()

	if fixture.javaReady {
		return
	}

	args := append(append([]string{}, javaExports()...), "-d", fixture.work)
	for _, name := range []string{"DetachedOracle", "CoreOracle", "TransformOracle", "ManifestOracle", "C14NOracle"} {
		args = append(args, filepath.Join(fixture.root, "tests/interop/testdata", name+".java"))
	}

	command(t, fixture, true, nil, "javac", args...)

	fixture.javaReady = true
	_, v := command(t, fixture, true, nil, "java", "-version")
	t.Log(strings.TrimSpace(string(v)))
}

func cOracle(t *testing.T, fixture *interopFixture) string {
	t.Helper()

	path := filepath.Join(fixture.work, "c14n-oracle")
	if fixture.cReady {
		return path
	}

	flags, _ := command(t, fixture, true, nil, "pkg-config", "--cflags", "--libs", "libxml-2.0")
	libraryFlags := strings.Fields(string(flags))
	args := make([]string, 0, 7+len(libraryFlags))
	args = append(args, flagWall, flagWextra, flagWerror, flagO2, filepath.Join(fixture.root, "tests/interop/testdata/c14n-oracle.c"))
	args = append(args, libraryFlags...)
	args = append(args, "-o", path)
	command(t, fixture, true, nil, "cc", args...)

	fixture.cReady = true
	version, _ := command(t, fixture, true, nil, path, "--version")
	t.Log("libxml2", strings.TrimSpace(string(version)))

	return path
}

type testKey struct {
	name        string
	method      string
	private     string
	public      string
	certificate string
	signer      crypto.Signer
	cert        *x509.Certificate
}

func generateKey(t *testing.T, dir, name string) testKey {
	t.Helper()

	var (
		signer crypto.Signer
		err    error
	)

	method := more + name
	switch name {
	case nameRsaSha256, nameRsaSha384, nameRsaSha512:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case nameEcdsaSha256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case nameEcdsaSha384:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case nameEcdsaSha512:
		signer, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case nameEd25519:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
		method = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
	default:
		t.Fatalf("unknown key: %s", name)
	}

	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "temporary explicit test pin"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return testKey{
		name: name, method: method, signer: signer, cert: cert,
		private:     testutil.WritePrivateKey(t, dir, name+".key.pem", signer),
		public:      testutil.WritePublicKey(t, dir, name+".pub.pem", signer.Public()),
		certificate: write(t, filepath.Join(dir, name+".cert.pem"), pem.EncodeToMemory(&pem.Block{Type: nameCERTIFICATE, Bytes: certDER})),
	}
}

// interopFixture owns the external tools and scratch files of one top-level test.
type interopFixture struct {
	root      string
	work      string
	binaries  map[string]string
	javaReady bool
	cReady    bool
}

func newInteropFixture(t *testing.T) *interopFixture {
	t.Helper()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	return &interopFixture{root: root, work: t.TempDir(), binaries: make(map[string]string)}
}

func xmlsecExecutable() string { return flag.Lookup("xmlsec1").Value.String() }
