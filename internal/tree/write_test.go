package tree_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"runtime"
	"strings"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestXMLWriterRestoresNamespaceScopes(t *testing.T) {
	ctx := context.Background()

	d, err := treepkg.Parse(ctx, []byte(`<r xmlns="urn:r" xmlns:p="urn:p"><a xmlns="" xmlns:p="urn:a"><p:x/></a><p:y/><b xmlns:p="urn:b"><p:z/></b><p:w/></r>`), treepkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	inherited := map[string]string{"p": "urn:outside", "q": "urn:q"}
	before := maps.Clone(inherited)

	for _, selfClose := range []bool{false, true} {
		var out bytes.Buffer

		_, err := treepkg.WriteXMLFragmentOptions(ctx, &out, treepkg.Children(d), 4096, treepkg.XMLWriteOptions{Reconcile: true, SelfClose: selfClose, InheritedNamespaces: inherited})
		if err != nil {
			t.Fatal(err)
		}

		roundtrip, err := treepkg.Parse(ctx, out.Bytes(), treepkg.DefaultLimits())
		if err != nil {
			t.Fatal(out.String(), err)
		}

		children := roundtrip.Root().Children()
		if children[0].Name().Space != "" || children[0].Children()[0].Name().Space != "urn:a" || children[1].Name().Space != "urn:p" || children[2].Children()[0].Name().Space != "urn:b" || children[3].Name().Space != "urn:p" {
			t.Fatal("namespace scope leaked across siblings", out.String())
		}

		if !maps.Equal(inherited, before) {
			t.Fatal("caller namespace map mutated", inherited)
		}
	}
}

func TestXMLWriterCDATAUsesSharedEscapingAndNormalization(t *testing.T) {
	ctx := context.Background()

	d, err := treepkg.Parse(ctx, []byte("<r>e&#x301;]]&gt;ж&#13;</r>"), treepkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	options := treepkg.XMLWriteOptions{ASCII: true, Normalization: "NFC", CDATA: map[string]struct{}{"{}r": {}}}

	var b bytes.Buffer
	if _, err = treepkg.WriteXMLFragmentOptions(ctx, &b, treepkg.Children(d), 4096, options); err != nil {
		t.Fatal(err)
	}

	roundtrip, err := treepkg.Parse(ctx, b.Bytes(), treepkg.DefaultLimits())
	if err != nil || roundtrip.Root().Text() != "é]]>ж\r" || strings.ContainsAny(b.String(), "éж") {
		t.Fatal("CDATA normalization/character references lost", b.String(), err)
	}

	options.ASCII = false
	options.CharacterMap = map[rune]string{'@': "<p/>"}
	n := &treepkg.Node{Kind: treepkg.ElementNode, Name: treepkg.Name{Local: "r"}, Children: []*treepkg.Node{{Kind: treepkg.TextNode, Data: "a@b"}}}

	b.Reset()

	if _, err = treepkg.WriteXMLFragmentOptions(ctx, &b, []*treepkg.Node{n}, 4096, options); err != nil || b.String() != "<r><![CDATA[a]]><p/><![CDATA[b]]></r>" {
		t.Fatal("character map stayed inside CDATA", b.String(), err)
	}

	for _, bad := range []string{"\x00", "\xff", "\ufffe"} {
		n.Children[0].Data = bad

		b.Reset()

		if _, err = treepkg.WriteXMLFragmentOptions(ctx, &b, []*treepkg.Node{n}, 4096, options); !errors.Is(err, treepkg.ErrMalformed) {
			t.Fatalf("invalid CDATA accepted: %q, %v", bad, err)
		}
	}
}

func TestReparseUsesParserStorageWithoutSerializedCopy(t *testing.T) {
	raw := `<r xmlns:p="urn:p"><p:v a="test">` + strings.Repeat("x", 1<<20) + `</p:v></r>`

	source, err := treepkg.ParseReader(t.Context(), strings.NewReader(raw), treepkg.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	measure := func(run func() error) uint64 {
		t.Helper()

		best := ^uint64(0)

		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			if err := run(); err != nil {
				t.Fatal(err)
			}

			runtime.ReadMemStats(&after)
			best = min(best, after.TotalAlloc-before.TotalAlloc)
		}

		return best
	}
	baseline := measure(func() error {
		_, err := treepkg.ParseReader(t.Context(), strings.NewReader(raw), treepkg.DefaultLimits())
		return err
	})

	allocated := measure(func() error { _, err := treepkg.Reparse(t.Context(), source, treepkg.DefaultLimits()); return err })
	if allocated > baseline+128<<10 {
		t.Fatalf("reparse allocated %d bytes against parser baseline %d", allocated, baseline)
	}

	limits := treepkg.DefaultLimits()

	limits.MaxBytes = 1024
	if result, err := treepkg.Reparse(t.Context(), source, limits); result != nil || !errors.Is(err, treepkg.ErrLimit) {
		t.Fatal("output budget", result, err)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	if result, err := treepkg.Reparse(canceled, source, treepkg.DefaultLimits()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", result, err)
	}

	after, err := source.XML(t.Context())
	if err != nil || string(after) != raw {
		t.Fatal("reparse changed source", err)
	}
}

func TestBase64TextBoundaries(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []byte
	}{
		{"", []byte{}}, {" AA\tE=\r\n", []byte{0, 1}}, {"AAEC", []byte{0, 1, 2}},
	} {
		node := &treepkg.Node{Children: []*treepkg.Node{{Kind: treepkg.TextNode, Data: tc.text[:len(tc.text)/2]}, {Kind: treepkg.CommentNode, Data: "ignored"}, {Kind: treepkg.PINode, Data: "ignored"}, {Kind: treepkg.TextNode, Data: tc.text[len(tc.text)/2:]}}}

		got, err := treepkg.DecodeBase64(t.Context(), node, len(tc.text), len(tc.want))
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("%q: %x, %v", tc.text, got, err)
		}
	}

	for _, bad := range []string{"A", "AA=", "AA===", "=AAA", "AA==AAAA", "AA==AA==", "AB==", "AAB=", "AA==\v", "AA==\u00a0"} {
		node := &treepkg.Node{Children: []*treepkg.Node{{Kind: treepkg.TextNode, Data: bad}}}
		if got, err := treepkg.DecodeBase64(t.Context(), node, 1024, 1024); got != nil || !errors.Is(err, treepkg.ErrMalformed) {
			t.Fatalf("invalid text %q: %x, %v", bad, got, err)
		}
	}

	node := &treepkg.Node{Children: []*treepkg.Node{{Kind: treepkg.TextNode, Data: "AAE="}}}
	for _, limits := range [][2]int{{3, 2}, {4, 1}, {0, 0}} {
		if got, err := treepkg.DecodeBase64(t.Context(), node, limits[0], limits[1]); got != nil || !errors.Is(err, treepkg.ErrLimit) {
			t.Fatal("limit", limits, got, err)
		}
	}

	node.Children = append(node.Children, &treepkg.Node{Kind: treepkg.ElementNode})
	if got, err := treepkg.DecodeBase64(t.Context(), node, 1024, 1024); got != nil || !errors.Is(err, treepkg.ErrMalformed) {
		t.Fatal("nested element", got, err)
	}
}

func TestBase64TextWorkingStorage(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 1, 2, 253, 254}, 1<<18)
	encoded := base64.StdEncoding.EncodeToString(payload)
	node := &treepkg.Node{Children: []*treepkg.Node{{Kind: treepkg.TextNode, Data: encoded[:len(encoded)/2]}, {Kind: treepkg.CommentNode}, {Kind: treepkg.TextNode, Data: encoded[len(encoded)/2:]}}}
	measure := func(run func() error) uint64 {
		t.Helper()

		best := ^uint64(0)

		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			if err := run(); err != nil {
				t.Fatal(err)
			}

			runtime.ReadMemStats(&after)
			best = min(best, after.TotalAlloc-before.TotalAlloc)
		}

		return best
	}

	allocation := measure(func() error {
		got, err := treepkg.EncodeBase64(t.Context(), payload)
		if err == nil && got != encoded {
			return errors.New("Base64 output changed")
		}

		return err
	})
	if allocation > uint64(len(encoded))+(64<<10) {
		t.Fatal("encoding retained a complete intermediate copy", allocation)
	}

	allocation = measure(func() error {
		got, err := treepkg.DecodeBase64(t.Context(), node, len(encoded), len(payload))
		if err == nil && !bytes.Equal(got, payload) {
			return errors.New("decoded bytes changed")
		}

		return err
	})
	if allocation > uint64(len(payload))+(64<<10) {
		t.Fatal("decoding retained complete encoded text", allocation)
	}

	allocation = measure(func() error {
		got, err := treepkg.DecodeBase64(t.Context(), node, len(encoded), len(payload)-1)
		if got != nil || !errors.Is(err, treepkg.ErrLimit) {
			return errors.New("decoded limit lost")
		}

		return nil
	})
	if allocation > 32<<10 {
		t.Fatal("output allocated before decoded limit", allocation)
	}

	cancellable, cancel := context.WithCancel(t.Context())
	defer cancel()

	ctx := &countingContext{Context: cancellable, remaining: 32, cancel: cancel}
	if got, err := treepkg.DecodeBase64(ctx, node, len(encoded), len(payload)); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during scan", err)
	}

	cancellable, cancel = context.WithCancel(t.Context())
	defer cancel()

	ctx = &countingContext{Context: cancellable, remaining: 32, cancel: cancel}
	if got, err := treepkg.EncodeBase64(ctx, payload); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during encoding", err)
	}
}

func FuzzBase64Text(f *testing.F) {
	for _, seed := range []string{"", "AAE=", "AA\tE=\r\n", "AA==AAAA", "AB==", "AAB=", "====", "A"} {
		f.Add(seed, uint16(1))
	}

	f.Fuzz(func(t *testing.T, value string, split uint16) {
		if len(value) > 16<<10 {
			t.Skip()
		}

		at := int(split) % (len(value) + 1)
		node := &treepkg.Node{Children: []*treepkg.Node{{Kind: treepkg.TextNode, Data: value[:at]}, {Kind: treepkg.CommentNode}, {Kind: treepkg.TextNode, Data: value[at:]}}}
		filtered := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}

			return r
		}, value)
		want, wantErr := base64.StdEncoding.Strict().DecodeString(filtered)

		got, err := treepkg.DecodeBase64(t.Context(), node, len(value), len(value))
		if (err == nil) != (wantErr == nil) || err == nil && !bytes.Equal(got, want) {
			t.Fatalf("%q split %d: %x, %v; oracle %x, %v", value, at, got, err, want, wantErr)
		}
	})
}

func TestParseProducedRejectsProducerErrors(t *testing.T) {
	failure := errors.New("producer failed after complete XML")
	if got, err := treepkg.ParseProduced(t.Context(), func(dst io.Writer) error {
		if _, err := io.WriteString(dst, "<r/>"); err != nil {
			return err
		}

		return failure
	}, treepkg.DefaultLimits()); got != nil || !errors.Is(err, failure) {
		t.Fatal("producer error lost", got, err)
	}

	stopped := false
	if got, err := treepkg.ParseProduced(t.Context(), func(dst io.Writer) error {
		defer func() { stopped = true }()

		for range 10000 {
			if _, err := io.WriteString(dst, "<r>invalid"); err != nil {
				return err
			}
		}

		return nil
	}, treepkg.DefaultLimits()); got != nil || err == nil || !stopped {
		t.Fatal("producer was not stopped", got, err, stopped)
	}
}

type countingContext struct {
	context.Context
	remaining int
	cancel    context.CancelFunc
}

func (c *countingContext) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		c.cancel()
	}

	return c.Context.Err()
}
