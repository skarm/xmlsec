//go:build interop

package interop_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	byteorder "encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestCanonicalVectorsAgainstJDK(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")
	compileJava(t, fixture)

	var corpus struct {
		Producer struct {
			OracleSHA256 string `json:"oracle_sha256"`
		} `json:"producer"`
		Cases []struct {
			Name, Expected string
			JDKDiagnostic  string `json:"jdk_diagnostic"`
			JDKError       string `json:"jdk_error"`
			canonicalRequest
		} `json:"cases"`
	}
	decode(t, read(t, filepath.Join(fixture.root, "c14n/testdata/normative-vectors.json")), &corpus)

	oracle := read(t, filepath.Join(fixture.root, "tests/interop/testdata/C14NOracle.java"))
	if fmt.Sprintf("%x", sha256.Sum256(oracle)) != corpus.Producer.OracleSHA256 {
		t.Fatal("fixture oracle source changed; review provenance and regenerate vectors")
	}

	params := append(javaExports(), "-cp", fixture.work, "C14NOracle")

	session := canonicalSession{jdk: lines(t, fixture, "java", params...)}
	matches, diagnostics := 0, 0

	for _, vector := range corpus.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			got, err := session.jdkResult(t, vector.canonicalRequest)

			knownError := err != nil && vector.JDKError != "" && strings.Contains(err.Error(), vector.JDKError)
			if vector.JDKDiagnostic != "" && (knownError || err == nil && string(got) != vector.Expected) {
				diagnostics++

				t.Logf("DIAGNOSTIC %s: JDK bytes=%q error=%v", vector.JDKDiagnostic, got, err)

				return
			}

			if err != nil || string(got) != vector.Expected {
				t.Fatalf("JDK bytes = %q, committed normative bytes = %q, error=%v", got, vector.Expected, err)
			}

			matches++
		})
	}

	if t.Failed() {
		return
	}

	t.Logf("fixed canonical vectors: JDK matches=%d diagnostics=%d (excluded from matches)", matches, diagnostics)
}

func TestCanonicalVectorsAgainstLibXML(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")

	var corpus struct {
		Producer struct {
			OracleSHA256 string `json:"libxml2_oracle_sha256"`
		} `json:"producer"`
		Cases []struct {
			Name, Expected   string
			LibXMLDiagnostic string `json:"libxml2_diagnostic"`
			canonicalRequest
		} `json:"cases"`
	}
	decode(t, read(t, filepath.Join(fixture.root, "c14n/testdata/normative-vectors.json")), &corpus)

	oracle := read(t, filepath.Join(fixture.root, "tests/interop/testdata/c14n-oracle.c"))
	if fmt.Sprintf("%x", sha256.Sum256(oracle)) != corpus.Producer.OracleSHA256 {
		t.Fatal("fixture oracle source changed; review provenance and regenerate vectors")
	}

	session := canonicalSession{fixture: fixture, nativeProgram: cOracle(t, fixture)}
	matches, diagnostics := 0, 0

	for _, vector := range corpus.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			got := session.native(t, vector.canonicalRequest)
			if string(got) != vector.Expected && vector.LibXMLDiagnostic != "" {
				diagnostics++

				t.Logf("DIAGNOSTIC %s: libxml2 bytes=%q", vector.LibXMLDiagnostic, got)

				return
			}

			if string(got) != vector.Expected {
				t.Fatalf("libxml2 bytes = %q, committed normative bytes = %q", got, vector.Expected)
			}

			matches++
		})
	}

	t.Logf("fixed canonical vectors: libxml2 matches=%d diagnostics=%d (excluded from matches)", matches, diagnostics)
}

func TestCanonicalization(t *testing.T) {
	fixture := newInteropFixture(t)
	selected(t, "portable")

	session := newCanonicalSession(t, fixture)

	documents := canonicalCorpus()
	for _, xml := range documents {
		session.compareDocument(t, xml)
	}

	for _, xml := range documents[:6] {
		session.compareSparseSubtrees(t, xml)
	}

	session.compareUTF16(t)
	session.checkDiagnostics(t)

	t.Logf("independent C14N matches: libxml2=%d JDK=%d; diagnostics=%d (excluded from matches)", session.matches, session.javaMatches, session.diagnostics)
}

func canonicalCorpus() []string {
	docs := append(make([]string, 0, 42), []string{
		`<r/>`, `<?p before?><!--before--><r a="&#x9;&#xA;&#xD;">&lt;&amp;&gt;&#xD;<!--inside--></r><?p after?><!--after-->`,
		`<r xmlns="urn:r" xmlns:p="urn:p"><c xmlns=""><p:x p:a="a" a="b">txt</p:x></c><d/></r>`,
		`<r xmlns:p="urn:p"><a><p:b/></a><p:c xmlns:p="urn:q"/></r>`,
		`<r xml:lang="en" xml:space="preserve"><a><c/></a><b xml:lang="ru"/></r>`,
		`<r xml:id="top"><c xml:id="child"><d/></c><e/></r>`,
		`<r xml:base="http://example.test/a/b/"><c xml:base="../c/"><d xml:base="x"/></c></r>`,
		`<r xml:base=".."><c xml:base=".."><d xml:base="x"/></c></r>`,
		`<r xml:base="abc/"><c xml:base="../"/></r>`, `<r>Привет<é a="😀">&amp;</é></r>`,
		`<r xmlns="urn:r"><a xmlns="urn:a"><b xmlns=""><c/></b></a></r>`,
		`<p:r xmlns="urn:unused" xmlns:p="urn:p"><p:a xmlns:q="urn:q" q:a="1"/><p:b/></p:r>`,
	}...)
	rng := rand.New(rand.NewPCG(14351, 14351))

	for i := range 30 {
		var b strings.Builder
		fmt.Fprintf(&b, `<r xmlns="urn:root:%d" xmlns:p="urn:p" xml:lang="en">`, i%3)

		for j := range 1 + rng.IntN(4) {
			ns := []string{"", "urn:a", "urn:b"}[rng.IntN(3)]
			prefix := []string{"", "p:"}[rng.IntN(2)]
			fmt.Fprintf(&b, `<%sa xmlns="%s" z="%d" p:b="%d">t%d<!--c--><b/></%sa>`, prefix, ns, j, i, rng.IntN(99), prefix)
		}

		docs = append(docs, b.String()+"</r>")
	}

	return docs
}

type lineProcess struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
	stderr bytes.Buffer
	cancel context.CancelFunc
}

func (p *lineProcess) call(t *testing.T, data []byte) []byte {
	t.Helper()

	if _, err := p.input.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}

	line, err := p.output.ReadBytes('\n')
	if err != nil {
		t.Fatalf("helper response: %v: %s", err, p.stderr.Bytes())
	}

	return bytes.TrimSuffix(line, []byte{'\n'})
}

type selector struct {
	Path   []int  `json:"path"`
	Kind   string `json:"kind"`
	Local  string `json:"local,omitempty"`
	Space  string `json:"space,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

type canonicalRequest struct {
	XML       string      `json:"xml,omitempty"`
	Input     []byte      `json:"input,omitempty"`
	Algorithm string      `json:"algorithm,omitempty"`
	Comments  bool        `json:"comments,omitempty"`
	Prefixes  []string    `json:"prefixes,omitempty"`
	Select    *[]selector `json:"select,omitempty"`
	Subtree   []int       `json:"subtree,omitempty"`
	Describe  bool        `json:"describe,omitempty"`
}

type canonicalResponse struct {
	Canonical []byte     `json:"canonical"`
	Nodes     []selector `json:"nodes"`
	Error     string     `json:"error"`
}

type canonicalNewlineCase struct{ kind, xml, expected string }

type canonicalSession struct {
	fixture                           *interopFixture
	goRPC, jdk                        *lineProcess
	nativeProgram                     string
	matches, javaMatches, diagnostics int
}

func newCanonicalSession(t *testing.T, fixture *interopFixture) *canonicalSession {
	t.Helper()

	compileJava(t, fixture)
	c := cOracle(t, fixture)
	goRPC := lines(t, fixture, binary(t, fixture, "c14nprobe"))
	params := append(append([]string{}, javaExports()...), "-Djdk.xml.xpathExprOpLimit=10000", "-Djdk.xml.xpathExprGrpLimit=10000", "-cp", fixture.work, "C14NOracle")
	jdk := lines(t, fixture, "java", params...)

	return &canonicalSession{fixture: fixture, goRPC: goRPC, jdk: jdk, nativeProgram: c}
}

func lines(t *testing.T, fixture *interopFixture, name string, args ...string) *lineProcess {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	p := &lineProcess{cmd: exec.CommandContext(ctx, name, args...), cancel: cancel}
	p.cmd.Dir = fixture.root
	p.cmd.Stderr = &p.stderr

	var err error

	p.input, err = p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	p.output = bufio.NewReader(out)
	if err := p.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		p.input.Close()
		err := p.cmd.Wait()

		cancel()

		if err != nil {
			t.Errorf("helper exited: %v: %s", err, p.stderr.Bytes())
		}
	})

	return p
}

func (session *canonicalSession) request(t *testing.T, r canonicalRequest) canonicalResponse {
	t.Helper()

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	var response canonicalResponse
	decode(t, session.goRPC.call(t, data), &response)

	if response.Error != "" {
		t.Fatalf("Go canonicalization: %s: %+v", response.Error, r)
	}

	return response
}

func (session *canonicalSession) native(t *testing.T, r canonicalRequest) []byte {
	t.Helper()

	if strings.HasSuffix(r.Algorithm, "WithComments") {
		r.Algorithm = strings.TrimSuffix(strings.TrimSuffix(r.Algorithm, "WithComments"), "#")
		if r.Algorithm == strings.TrimSuffix(exc, "#") {
			r.Algorithm = exc
		}

		r.Comments = true
	}

	data := r.Input
	if data == nil {
		data = []byte(r.XML)
	}

	path := write(t, filepath.Join(session.fixture.work, "canonical-input.xml"), data)
	mode := slices.Index([]string{c10, exc, c11}, r.Algorithm)

	args := []string{path, strconv.Itoa(mode), strconv.FormatInt(int64(boolInt(r.Comments)), 10), selectionXPath(r, true)}
	if len(r.Prefixes) == 0 {
		args = append(args, "-")
	} else {
		args = append(args, r.Prefixes...)
	}

	out, _ := command(t, session.fixture, true, nil, session.nativeProgram, args...)

	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

func (session *canonicalSession) jdkBytes(t *testing.T, r canonicalRequest) []byte {
	t.Helper()

	result, err := session.jdkResult(t, r)
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func (session *canonicalSession) jdkResult(t *testing.T, r canonicalRequest) ([]byte, error) {
	t.Helper()

	data := r.Input
	if data == nil {
		data = []byte(r.XML)
	}

	alg := r.Algorithm
	if r.Comments {
		if strings.HasSuffix(alg, "#") {
			alg += "WithComments"
		} else {
			alg += "#WithComments"
		}
	}

	selection := selectionXPath(r, false)
	if r.Subtree != nil {
		// DOM namespace-axis nodes may belong to omitted ancestors. Use the
		// oracle's subtree API for a subtree request, rather than turning it
		// into an arbitrary DOM node-set with different visibility semantics.
		selection = "SUBTREE:" + nodeXPath(selector{Path: r.Subtree})
	}

	fields := []string{base64.StdEncoding.EncodeToString(data), alg, base64.StdEncoding.EncodeToString([]byte(selection)), base64.StdEncoding.EncodeToString([]byte(strings.Join(r.Prefixes, " ")))}

	line := strings.SplitN(string(session.jdk.call(t, []byte(strings.Join(fields, "\t")))), "\t", 2)
	if len(line) != 2 {
		t.Fatalf("JDK response: %v", line)
	}

	result, err := base64.StdEncoding.DecodeString(line[1])
	if err != nil {
		t.Fatal(err)
	}

	if line[0] != "OK" {
		return nil, fmt.Errorf("JDK: %s", result)
	}

	return result, nil
}

func (session *canonicalSession) compareDocument(t *testing.T, xml string) {
	t.Helper()

	nodes := session.request(t, canonicalRequest{XML: xml, Describe: true}).Nodes

	var elements []selector

	for _, n := range nodes {
		if n.Kind == nameElement {
			elements = append(elements, n)
		}
	}

	for _, alg := range []string{c10, exc, c11} {
		for _, comments := range []bool{false, true} {
			session.compareSelections(t, canonicalRequest{XML: xml, Algorithm: alg, Comments: comments}, nodes, elements)
		}
	}

	for _, kind := range []string{nameText, "comment", "processing-instruction"} {
		chosen := make([]selector, 0)

		for _, n := range nodes {
			if n.Kind == kind && len(n.Path) > 1 || slices.Equal(n.Path, elements[0].Path) && (n.Kind == nameElement || n.Kind == "attribute" || n.Kind == "namespace") {
				chosen = append(chosen, n)
			}
		}

		for _, alg := range []string{c10, exc, c11} {
			session.compare(t, canonicalRequest{XML: xml, Algorithm: alg, Comments: true, Select: &chosen}, false)
		}
	}
}

func (session *canonicalSession) compareSelections(t *testing.T, base canonicalRequest, nodes, elements []selector) {
	t.Helper()

	session.compare(t, base, true)
	all := base
	all.Select = &nodes
	session.compare(t, all, false)

	for _, n := range elements[:min(4, len(elements))] {
		sub := base
		sub.Subtree = n.Path
		session.compare(t, sub, false)
	}

	if base.Algorithm == exc {
		base.Prefixes = []string{"#default", "p", "missing"}
		session.compare(t, base, true)
	}
}

func (session *canonicalSession) compareSparseSubtrees(t *testing.T, xml string) {
	t.Helper()

	nodes := session.request(t, canonicalRequest{XML: xml, Describe: true}).Nodes

	var roots [][]int

	for _, n := range nodes {
		if n.Kind == nameElement && len(n.Path) == 2 {
			roots = append(roots, n.Path)
		}
	}

	chosen := make([]selector, 0)

	for _, n := range nodes {
		for _, p := range roots {
			if len(n.Path) >= len(p) && slices.Equal(n.Path[:len(p)], p) {
				chosen = append(chosen, n)
				break
			}
		}
	}

	for _, alg := range []string{c10, exc, c11} {
		session.compare(t, canonicalRequest{XML: xml, Algorithm: alg, Comments: true, Select: &chosen}, false)
	}
}

func (session *canonicalSession) compareUTF16(t *testing.T) {
	t.Helper()

	for _, order := range []byteorder.ByteOrder{byteorder.LittleEndian, byteorder.BigEndian} {
		words := utf16.Encode([]rune(`<?xml version="1.0" encoding="UTF-16"?><r a="é">Привет 😀</r>`))
		data := make([]byte, 2+2*len(words))
		order.PutUint16(data, 0xfeff)

		for i, w := range words {
			order.PutUint16(data[2+2*i:], w)
		}

		for _, alg := range []string{c10, exc, c11} {
			session.compare(t, canonicalRequest{Input: data, Algorithm: alg}, true)
		}
	}
}

func (session *canonicalSession) checkDiagnostics(t *testing.T) {
	t.Helper()

	diagnostic := canonicalRequest{XML: `<r xml:lang="en" xml:space="preserve"><c xml:lang="ru"/></r>`, Algorithm: c10, Select: &[]selector{{Path: []int{1, 1}, Kind: nameElement}}}
	if got := session.request(t, diagnostic).Canonical; string(got) != `<c xml:space="preserve"></c>` {
		t.Fatalf("omitted own xml:lang shadow: %s", got)
	}

	t.Logf("DIAGNOSTIC omitted own xml:lang: libxml2=%s JDK=%s", session.native(t, diagnostic), session.jdkBytes(t, diagnostic))

	session.diagnostics++

	for _, tc := range []canonicalNewlineCase{
		{"comment", `<!--before--><r><!--inside--></r><!--after-->`, "<!--before-->\n<!--inside-->\n<!--after-->"},
		{"processing-instruction", `<?p before?><r><?p inside?></r><?p after?>`, "<?p before?>\n<?p inside?>\n<?p after?>"},
	} {
		nodes := session.request(t, canonicalRequest{XML: tc.xml, Describe: true}).Nodes
		chosen := make([]selector, 0)

		for _, n := range nodes {
			if n.Kind == tc.kind {
				chosen = append(chosen, n)
			}
		}

		for _, alg := range []string{c10, exc, c11} {
			r := canonicalRequest{XML: tc.xml, Algorithm: alg, Comments: true, Select: &chosen}
			if string(session.request(t, r).Canonical) != tc.expected {
				t.Fatal("original document-order newline placement")
			}

			t.Logf("DIAGNOSTIC %s %s: libxml2=%q JDK=%q", tc.kind, alg, session.native(t, r), session.jdkBytes(t, r))

			session.diagnostics++
		}
	}
}

func (session *canonicalSession) compare(t *testing.T, r canonicalRequest, withJDK bool) {
	t.Helper()

	actual := session.request(t, r).Canonical

	var normative string

	if r.Algorithm == c11 && slices.Equal(r.Subtree, []int{1, 1}) {
		// C14N 1.1 §2.4 explicitly specifies both joins. libxml2 versions
		// differ on the empty join; an empty fixed-up xml:base must be omitted.
		switch r.XML {
		case `<r xml:base=".."><c xml:base=".."><d xml:base="x"/></c></r>`:
			normative = `<c xml:base="../../"><d xml:base="x"></d></c>`
		case `<r xml:base="abc/"><c xml:base="../"/></r>`:
			normative = `<c></c>`
		}
	}

	if normative != "" && string(actual) != normative {
		t.Fatalf("C14N 1.1 §2.4 xml:base: got %s, want %s", actual, normative)
	}

	expected := session.native(t, r)
	if !bytes.Equal(actual, expected) {
		if normative == "" {
			t.Fatalf("libxml2 mismatch: %+v\nGo: %s\nC: %s", r, actual, expected)
		}

		session.diagnostics++

		t.Logf("DIAGNOSTIC C14N 1.1 §2.4 xml:base; Go=%s libxml2=%s", actual, expected)
	} else {
		session.matches++
	}

	if withJDK {
		expected = session.jdkBytes(t, r)
		if !bytes.Equal(actual, expected) {
			if normative == "" {
				t.Fatalf("JDK mismatch: %+v\nGo: %s\nJDK: %s", r, actual, expected)
			}

			session.diagnostics++
		} else {
			session.javaMatches++
		}
	}
}

func xpathLiteral(s string) string {
	if !strings.Contains(s, "'") {
		return "'" + s + "'"
	}

	if !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}

	parts := strings.Split(s, "'")
	for i := range parts {
		parts[i] = "'" + parts[i] + "'"
	}

	return "concat(" + strings.Join(parts, `,"'",`) + ")"
}

func nodeXPath(n selector) string {
	var b strings.Builder
	for _, i := range n.Path {
		fmt.Fprintf(&b, "/node()[%d]", i)
	}

	path := b.String()
	if path == "" {
		path = "/"
	}

	if n.Kind == "attribute" {
		path += "/@*[local-name()=" + xpathLiteral(n.Local) + " and namespace-uri()=" + xpathLiteral(n.Space) + "]"
	}

	if n.Kind == "namespace" {
		path += "/namespace::*[name()=" + xpathLiteral(n.Prefix) + "]"
	}

	return path
}

func selectionXPath(r canonicalRequest, markers bool) string {
	if r.Subtree != nil {
		x := nodeXPath(selector{Path: r.Subtree})
		return x + "/descendant-or-self::node() | " + x + "/descendant-or-self::*/@* | " + x + "/descendant-or-self::*/namespace::*"
	}

	if r.Select == nil {
		return "-"
	}

	var terms []string
	for _, n := range *r.Select {
		terms = append(terms, nodeXPath(n))
		if markers && n.Kind == nameElement {
			terms = append(terms, nodeXPath(n)+"/namespace::*[name()='' and string()='']")
		}
	}

	if len(terms) == 0 {
		return "/*[false()]"
	}

	return strings.Join(terms, " | ")
}
