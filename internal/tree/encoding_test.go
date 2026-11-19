package tree_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"math"
	"runtime"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestBase64TextBoundaries(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []byte
	}{
		{"", []byte{}}, {" AA\tE=\r\n", []byte{0, 1}}, {"AAEC", []byte{0, 1, 2}},
	} {
		node := &tree.Node{Children: []*tree.Node{{Kind: tree.TextNode, Data: tc.text[:len(tc.text)/2]}, {Kind: tree.CommentNode, Data: "ignored"}, {Kind: tree.PINode, Data: "ignored"}, {Kind: tree.TextNode, Data: tc.text[len(tc.text)/2:]}}}

		got, err := tree.DecodeBase64(t.Context(), node, len(tc.text), len(tc.want))
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("%q: %x, %v", tc.text, got, err)
		}
	}

	for _, bad := range []string{"A", "AA=", "AA===", "=AAA", "AA==AAAA", "AA==AA==", "AB==", "AAB=", "AA==\v", "AA==\u00a0"} {
		node := &tree.Node{Children: []*tree.Node{{Kind: tree.TextNode, Data: bad}}}
		if got, err := tree.DecodeBase64(t.Context(), node, 1024, 1024); got != nil || !errors.Is(err, tree.ErrMalformed) {
			t.Fatalf("invalid text %q: %x, %v", bad, got, err)
		}
	}

	node := &tree.Node{Children: []*tree.Node{{Kind: tree.TextNode, Data: "AAE="}}}
	for _, limit := range []int{math.MaxInt - 2, math.MaxInt} {
		if got, err := tree.DecodeBase64(t.Context(), node, 0, limit); err != nil || !bytes.Equal(got, []byte{0, 1}) {
			t.Fatal("large decoded limit rejected small input", limit, got, err)
		}
	}

	for _, limits := range [][2]int{{3, 2}, {4, 1}, {0, 0}} {
		if got, err := tree.DecodeBase64(t.Context(), node, limits[0], limits[1]); got != nil || !errors.Is(err, tree.ErrLimit) {
			t.Fatal("limit", limits, got, err)
		}
	}

	node.Children = append(node.Children, &tree.Node{Kind: tree.ElementNode})
	if got, err := tree.DecodeBase64(t.Context(), node, 1024, 1024); got != nil || !errors.Is(err, tree.ErrMalformed) {
		t.Fatal("nested element", got, err)
	}
}

func TestBase64TextWorkingStorage(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 1, 2, 253, 254}, 1<<18)
	encoded := base64.StdEncoding.EncodeToString(payload)
	node := &tree.Node{Children: []*tree.Node{{Kind: tree.TextNode, Data: encoded[:len(encoded)/2]}, {Kind: tree.CommentNode}, {Kind: tree.TextNode, Data: encoded[len(encoded)/2:]}}}
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
		got, err := tree.EncodeBase64(t.Context(), payload)
		if err == nil && got != encoded {
			return errors.New("base64 output changed")
		}

		return err
	})
	if allocation > uint64(len(encoded))+(64<<10) {
		t.Fatal("encoding retained a complete intermediate copy", allocation)
	}

	allocation = measure(func() error {
		got, err := tree.DecodeBase64(t.Context(), node, len(encoded), len(payload))
		if err == nil && !bytes.Equal(got, payload) {
			return errors.New("decoded bytes changed")
		}

		return err
	})
	if allocation > uint64(len(payload))+(64<<10) {
		t.Fatal("decoding retained complete encoded text", allocation)
	}

	allocation = measure(func() error {
		got, err := tree.DecodeBase64(t.Context(), node, len(encoded), len(payload)-1)
		if got != nil || !errors.Is(err, tree.ErrLimit) {
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
	if got, err := tree.DecodeBase64(ctx, node, len(encoded), len(payload)); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during scan", err)
	}

	cancellable, cancel = context.WithCancel(t.Context())
	defer cancel()

	ctx = &countingContext{Context: cancellable, remaining: 32, cancel: cancel}
	if got, err := tree.EncodeBase64(ctx, payload); got != "" || !errors.Is(err, context.Canceled) {
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
		node := &tree.Node{Children: []*tree.Node{{Kind: tree.TextNode, Data: value[:at]}, {Kind: tree.CommentNode}, {Kind: tree.TextNode, Data: value[at:]}}}
		filtered := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}

			return r
		}, value)
		want, wantErr := base64.StdEncoding.Strict().DecodeString(filtered)

		got, err := tree.DecodeBase64(t.Context(), node, len(value), len(value))
		if (err == nil) != (wantErr == nil) || err == nil && !bytes.Equal(got, want) {
			t.Fatalf("%q split %d: %x, %v; oracle %x, %v", value, at, got, err, want, wantErr)
		}
	})
}
