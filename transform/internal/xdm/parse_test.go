package xdm_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestParseOptionsByteCapIntersection(t *testing.T) {
	t.Parallel()

	limits := tree.DefaultLimits()
	limits.MaxBytes = 32
	limits.MaxDepth = 3
	original := xdm.ParseOptions{Limits: limits, BaseURI: "urn:source"}
	for _, byteCap := range []int64{-1, 0, 64} {
		if got := original.WithByteLimit(byteCap); got.Limits != limits || got.BaseURI != original.BaseURI {
			t.Fatalf("nonrestrictive byte cap %d altered policy: %+v", byteCap, got)
		}
	}
	narrowed := original.WithByteLimit(4)
	if narrowed.Limits.MaxBytes != 4 || narrowed.Limits.MaxDepth != 3 || original.Limits.MaxBytes != 32 {
		t.Fatal("byte cap did not intersect a copied policy")
	}
	if _, err := narrowed.Parse(t.Context(), []byte("<r/>")); err != nil {
		t.Fatal(err)
	}
	if _, err := narrowed.Parse(t.Context(), []byte("<root/>")); !errors.Is(err, tree.ErrLimit) {
		t.Fatalf("byte cap not enforced: %v", err)
	}
	defaults := (xdm.ParseOptions{}).WithByteLimit(128)
	want := tree.DefaultLimits()
	want.MaxBytes = 128
	if defaults.Limits != want {
		t.Fatalf("zero policy did not expand defaults before cap: %+v", defaults.Limits)
	}
}

func TestParseTextAndByteEncodingPolicies(t *testing.T) {
	t.Parallel()

	text := `<?xml version="1.0" encoding="ISO-8859-1"?><r>café</r>`
	doc, err := (xdm.ParseOptions{BaseURI: "urn:text"}).ParseText(t.Context(), text)
	if err != nil {
		t.Fatal(err)
	}
	if xdm.StringValue(doc.DocumentElement()) != "café" || doc.URL() != "urn:text" {
		t.Fatal("decoded text was reinterpreted or base lost")
	}
	source := []byte(`<?xml version="1.0" encoding="ISO-8859-1"?><r>caf`)
	source = append(source, 0xe9)
	source = append(source, []byte(`</r>`)...)
	if _, err = (xdm.ParseOptions{}).Parse(t.Context(), source); err == nil {
		t.Fatal("single-byte input accepted without opt-in")
	}
	doc, err = (xdm.ParseOptions{AllowSingleByteEncodings: true}).Parse(t.Context(), source)
	if err != nil || xdm.StringValue(doc.DocumentElement()) != "café" {
		t.Fatalf("single-byte opt-in: %v", err)
	}
	for _, allow := range []bool{false, true} {
		doc, err = (xdm.ParseOptions{AllowRelativeNamespaces: allow}).ParseText(t.Context(), `<r xmlns="relative"/>`)
		if allow {
			if err != nil || doc.DocumentElement().URI() != "relative" {
				t.Fatalf("relative namespace option: %v", err)
			}
		} else if err == nil {
			t.Fatal("relative namespace accepted without opt-in")
		}
	}
	for _, parse := range []func(context.Context) (*xdm.Document, error){func(ctx context.Context) (*xdm.Document, error) {
		return (xdm.ParseOptions{}).Parse(ctx, []byte("<r>"))
	}, func(ctx context.Context) (*xdm.Document, error) { return (xdm.ParseOptions{}).ParseText(ctx, "<r>") }, func(ctx context.Context) (*xdm.Document, error) {
		return (xdm.ParseOptions{}).ParseFragment(ctx, "<r>")
	}} {
		if _, err = parse(t.Context()); !errors.Is(err, tree.ErrMalformed) {
			t.Fatalf("malformed input error: %v", err)
		}
	}
}

type trackedEntity struct {
	*strings.Reader
	closed bool
}

func (e *trackedEntity) Close() error { e.closed = true; return nil }

func TestParseOptionsExternalEntityResolution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ base, want string }{{"https://example.test/a/doc.xml", "https://example.test/a/part.ent"}, {"/a/doc.xml", "file:///a/part.ent"}, {`C:\a\doc.xml`, "file:///C:/a/part.ent"}} {
		entity := &trackedEntity{Reader: strings.NewReader("resolved")}
		calls := 0
		options := xdm.ParseOptions{AllowDTD: true, BaseURI: tc.base, DTDOpen: func(ctx context.Context, uri string) (io.ReadCloser, error) {
			calls++
			if ctx == nil || uri != tc.want {
				t.Fatalf("resolved %q; want %q", uri, tc.want)
			}
			return entity, nil
		}}
		doc, err := options.ParseText(t.Context(), `<!DOCTYPE r [<!ENTITY e SYSTEM "part.ent">]><r>&e;</r>`)
		if err != nil {
			t.Fatal(err)
		}
		if calls != 1 || !entity.closed || xdm.StringValue(doc.DocumentElement()) != "resolved" || doc.URL() != tc.base {
			t.Fatal("external entity lifecycle/content/base")
		}
	}
	sentinel := errors.New("host refuses entity")
	calls := 0
	options := xdm.ParseOptions{AllowDTD: true, BaseURI: "https://example.test/doc.xml", DTDOpen: func(context.Context, string) (io.ReadCloser, error) { calls++; return nil, sentinel }}
	if _, err := options.ParseText(t.Context(), `<!DOCTYPE r [<!ENTITY e SYSTEM "part.ent">]><r>&e;</r>`); !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("opener cause lost: %v,calls%d", err, calls)
	}
	for _, tc := range []struct{ base, id string }{{"relative.xml", "part.ent"}, {"https://example.test/doc.xml", "part.ent#fragment"}, {"https://example.test/doc.xml", "http://[bad"}} {
		options.BaseURI = tc.base
		calls = 0
		_, err := options.ParseText(t.Context(), `<!DOCTYPE r [<!ENTITY e SYSTEM "`+tc.id+`">]><r>&e;</r>`)
		if err == nil || calls != 0 {
			t.Fatalf("invalid entity reference reached opener: %q,%q: %v calls%d", tc.base, tc.id, err, calls)
		}
	}
}

func TestParseOptionsStreamingWrappers(t *testing.T) {
	t.Parallel()

	options := xdm.ParseOptions{BaseURI: "urn:records"}
	if err := options.CheckXMLProlog(t.Context(), strings.NewReader("<r><unclosed")); err != nil {
		t.Fatalf("prolog checker read beyond first complete start tag: %v", err)
	}
	if err := options.CheckXMLProlog(t.Context(), strings.NewReader("<r")); err == nil {
		t.Fatal("incomplete prolog accepted")
	}
	fragment, err := options.ParseFragment(t.Context(), "text<a/>tail<b/>")
	if err != nil {
		t.Fatal(err)
	}
	if fragment.URL() != "urn:records" || xdm.StringValue(fragment) != "texttail" {
		t.Fatal("fragment text/base not preserved")
	}
	var values []string
	recordOptions := tree.RecordOptions{Path: []tree.Name{{Local: "r"}, {Local: "record"}}}
	err = options.ReadRecords(t.Context(), strings.NewReader("<r><record>first</record><record>second</record></r>"), recordOptions, func(doc *tree.Document) error {
		wrapped, err := xdm.WrapDocument(t.Context(), doc)
		if err != nil {
			return err
		}
		values = append(values, xdm.StringValue(wrapped))
		return nil
	})
	if err != nil || !reflect.DeepEqual(values, []string{"first", "second"}) {
		t.Fatalf("record sequence %q: %v", values, err)
	}
	sentinel := errors.New("stop records")
	calls := 0
	err = options.ReadRecords(t.Context(), strings.NewReader("<r><record/><record/></r>"), recordOptions, func(*tree.Document) error { calls++; return sentinel })
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("callback failure: %v,%d", err, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = options.ParseReader(ctx, strings.NewReader("<r/>")); !errors.Is(err, context.Canceled) {
		t.Fatalf("parse cancellation cause: %v", err)
	}
}
