package consumer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

// TestDocumentPublicMethods guards the immutable API against internal methods
// leaking through the document.Document alias. New public methods must be
// deliberately added here after reviewing their ownership contract.
func TestDocumentPublicMethods(t *testing.T) {
	want := []string{"AllNodes", "Node", "Root", "WriteXML", "XML"}
	typ := reflect.TypeFor[*document.Document]()
	got := make([]string, typ.NumMethod())
	for i := range got {
		got[i] = typ.Method(i).Name
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Document method set exposes unreviewed operations: got %v, want %v", got, want)
	}
}

func TestRecordsEmitBeforeReadingRemainder(t *testing.T) {
	emitted := 0
	reader := &gatedInput{first: strings.NewReader(`<feed xmlns:p="urn:p" xml:lang="ru" xml:base="https://input.test/a/"><p:item><p:value>1</p:value></p:item>`), rest: strings.NewReader(`<p:item><p:value>2</p:value></p:item></feed>`), ready: func() bool { return emitted > 0 }}
	var snapshots []*document.Document
	options := document.RecordOptions{Path: []document.Name{{Local: "feed"}, {Space: "urn:p", Local: "item"}}}
	err := document.ReadRecords(t.Context(), reader, options, func(record *document.Document) error {
		emitted++
		if record.Root().Name() != (document.Name{Space: "urn:p", Local: "item"}) {
			t.Fatal(record.Root().Name())
		}
		if lang, ok := record.Root().Attribute(document.Name{Space: document.XMLNamespace, Local: "lang"}); !ok || lang != "ru" {
			t.Fatal(lang, ok)
		}
		if base, ok := record.Root().Attribute(document.Name{Space: document.XMLNamespace, Local: "base"}); !ok || base != "https://input.test/a/" {
			t.Fatal(base, ok)
		}
		snapshots = append(snapshots, record)
		return nil
	})
	if err != nil || reader.early || emitted != 2 {
		t.Fatal(err, reader.early, emitted)
	}
	if snapshots[0].Root().Children()[0].Text() != "1" || snapshots[1].Root().Children()[0].Text() != "2" {
		t.Fatal("record snapshots reused mutable storage")
	}
}

func TestRecordsOwnLexicalTokenValues(t *testing.T) {
	var saved []*document.Document

	var source strings.Builder
	source.WriteString("<feed>")
	for _, value := range []string{"first", strings.Repeat("я", 4097), "last"} {
		source.WriteString(`<r a="` + value + `&amp;&#xD;" b="&quot;end">` + value + `&lt;<![CDATA[&raw]]><!--` + value + `--><?p ` + value + `?></r>`)
	}
	source.WriteString("</feed>")

	err := document.ReadRecords(t.Context(), iotest.OneByteReader(strings.NewReader(source.String())), document.RecordOptions{Path: []document.Name{{Local: "feed"}, {Local: "r"}}}, func(record *document.Document) error {
		saved = append(saved, record)
		return nil
	})
	if err != nil || len(saved) != 3 {
		t.Fatal("records lost", len(saved), err)
	}

	for i, value := range []string{"first", strings.Repeat("я", 4097), "last"} {
		xml, err := saved[i].XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if attribute, ok := saved[i].Root().Attribute(document.Name{Local: "a"}); !ok || attribute != value+"&\r" {
			t.Fatal("attribute storage was reused", i)
		}

		if saved[i].Root().Text() != value+"<&raw" || !bytes.Contains(xml, []byte("<!--"+value+"-->")) || !bytes.Contains(xml, []byte("<?p "+value+"?>")) {
			t.Fatal("text, comment or PI storage was reused", i)
		}
	}
}

func TestRecordsReleaseDiscardedInput(t *testing.T) {
	retained := retainedHeapDuring(t, func() any {
		var records []*document.Document
		for range 8 {
			source := "<feed><!--" + strings.Repeat("x", 1<<20) + "--><r>small</r></feed>"
			err := document.ReadRecords(t.Context(), strings.NewReader(source), document.RecordOptions{Path: []document.Name{{Local: "feed"}, {Local: "r"}}}, func(record *document.Document) error {
				if record.Root().Text() != "small" {
					t.Fatal("record changed")
				}
				records = append(records, record)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		if len(records) != 8 {
			t.Fatal("records lost")
		}
		return records
	})
	t.Logf("eight records: %d retained heap bytes", retained)
	if retained > 2<<20 {
		t.Fatalf("small records retained enclosing inputs: %d bytes", retained)
	}
}

func TestSmallCharacterReferenceResultsReleaseInput(t *testing.T) {
	retained := retainedHeapDuring(t, func() any {
		var results []*document.Document
		for range 8 {
			source := "<r>&#" + strings.Repeat("0", 1<<20) + "65;</r>"
			result, err := document.ParseReader(t.Context(), strings.NewReader(source), document.DefaultLimits())
			if err != nil || result.Root().Text() != "A" {
				t.Fatal("long character reference changed", err)
			}
			results = append(results, result)
		}
		return results
	})
	t.Logf("eight one-character documents: %d retained bytes", retained)
	if retained > 2<<20 {
		t.Fatal("small character-reference results retained large lexical buffers", retained)
	}
}

func TestXMLNamePartsReleaseDiscardedQNames(t *testing.T) {
	for _, name := range []string{"ElementLocal", "ElementPrefix", "AttributeLocal", "AttributePrefix"} {
		t.Run(name, func(t *testing.T) {
			retained := retainedHeapDuring(t, func() any {
				parts := make([]string, 4)
				for i := range parts {
					large := strings.Repeat("x", 1<<20)
					prefix, local := "p", large
					want := prefix
					if strings.HasSuffix(name, "Local") {
						prefix, local = large, "small"
						want = local
					}
					qualified := prefix + ":" + local
					source := "<" + qualified + ` xmlns:` + prefix + `="urn:test"/>`
					if strings.HasPrefix(name, "Attribute") {
						source = `<r xmlns:` + prefix + `="urn:test" ` + qualified + `="value"/>`
					}
					doc, err := document.ParseReader(t.Context(), strings.NewReader(source), document.DefaultLimits())
					if err != nil {
						t.Fatal(err)
					}
					switch name {
					case "ElementLocal":
						parts[i] = doc.Root().Name().Local
					case "ElementPrefix":
						parts[i] = doc.Root().Prefix()
					case "AttributeLocal":
						parts[i] = doc.Root().Attributes()[0].Name.Local
					case "AttributePrefix":
						parts[i] = doc.Root().Attributes()[0].Prefix
					}
					if parts[i] != want {
						t.Fatal("XML name changed")
					}
				}
				return parts
			})
			t.Logf("four XML name parts: %d retained heap bytes", retained)
			if retained > 1<<20 {
				t.Fatalf("small name parts retained qualified names: %d bytes", retained)
			}
		})
	}
}

func TestRecordLimitsAndLaterMalformedInput(t *testing.T) {
	limits := document.DefaultLimits()
	limits.MaxBytes = 32
	for _, input := range []string{`<f><r>` + strings.Repeat("x", 33) + `</r></f>`, `<f><r/><r/></f>`} {
		err := document.ReadRecords(t.Context(), strings.NewReader(input), document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}, Limits: limits, MaxRecords: 1}, func(*document.Document) error { return nil })
		if !errors.Is(err, document.ErrLimit) {
			t.Fatal(err)
		}
	}
	calls := 0
	err := document.ReadRecords(t.Context(), strings.NewReader(`<f><r/></f><bad/>`), document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}}, func(*document.Document) error { calls++; return nil })
	if !errors.Is(err, document.ErrMalformed) || calls != 1 {
		t.Fatal(err, calls)
	}
	failure := errors.New("stop consumer")
	err = document.ReadRecords(t.Context(), strings.NewReader(`<f><r/><r/></f>`), document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}}, func(*document.Document) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestRecordContextAndChunkBoundaries(t *testing.T) {
	source := `<f xmlns="urn:outer" xmlns:p="urn:old" xml:base="https://input.test/a/" xml:lang="ru"><ignored/><section xmlns:p="urn:new" xml:base="b/"><p:r xml:base="../record"><p:x>🙂&#xD;` + strings.Repeat("я", 4096) + `</p:x></p:r></section></f>`
	options := document.RecordOptions{Path: []document.Name{{Space: "urn:outer", Local: "f"}, {Space: "urn:outer", Local: "section"}, {Space: "urn:new", Local: "r"}}}
	var saved *document.Document
	err := document.ReadRecords(t.Context(), iotest.OneByteReader(strings.NewReader(source)), options, func(record *document.Document) error { saved = record; return nil })
	if err != nil || saved == nil {
		t.Fatal(err, saved)
	}
	if base, _ := saved.Root().Attribute(document.Name{Space: document.XMLNamespace, Local: "base"}); base != "https://input.test/a/record" {
		t.Fatal(base)
	}
	raw, err := saved.XML(t.Context())
	if err != nil || !bytes.Contains(raw, []byte(`xmlns:p="urn:new"`)) || !bytes.Contains(raw, []byte(`xml:lang="ru"`)) {
		t.Fatal(string(raw), err)
	}
	if saved.Root().Children()[0].Text() != "🙂\r"+strings.Repeat("я", 4096) {
		t.Fatal("split Unicode or character reference")
	}
	// UTF-16 is decoded incrementally, even when code units span reads.
	units := utf16.Encode([]rune(`<?xml version="1.0" encoding="UTF-16"?><f><r>🙂</r></f>`))
	data := []byte{0xff, 0xfe}
	for _, unit := range units {
		data = append(data, byte(unit), byte(unit>>8))
	}
	calls := 0
	err = document.ReadRecords(t.Context(), iotest.OneByteReader(bytes.NewReader(data)), document.RecordOptions{Path: []document.Name{{Local: "f"}, {Local: "r"}}}, func(record *document.Document) error {
		calls++
		if record.Root().Text() != "🙂" {
			t.Fatal(record.Root().Text())
		}
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
}

func TestXMLWritersBoundEscapingMemory(t *testing.T) {
	const size = 1 << 20
	for _, attribute := range []bool{false, true} {
		input := "<r>" + strings.Repeat("&amp;", size) + "</r>"
		if attribute {
			input = `<r a="` + strings.Repeat("&amp;", size) + `"/>`
		}
		doc, err := document.Parse(t.Context(), []byte(input), document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		writers := []struct {
			name  string
			write func(context.Context, io.Writer, int) error
		}{
			{"xml", func(ctx context.Context, w io.Writer, maximum int) error {
				_, err := doc.WriteXML(ctx, w, maximum)
				return err
			}},
			{"c14n", func(ctx context.Context, w io.Writer, maximum int) error {
				return c14n.WriteDocument(ctx, w, doc, c14n.Options{MaxOutputBytes: maximum})
			}},
		}
		for _, operation := range writers {
			t.Run(operation.name+map[bool]string{false: "/text", true: "/attribute"}[attribute], func(t *testing.T) {
				var sink streamingSink
				if err := operation.write(t.Context(), &sink, 8<<20); err != nil {
					t.Fatal(err)
				}
				if sink.bytes < 5*size || sink.largest > 32<<10 {
					t.Fatalf("output=%d largest chunk=%d", sink.bytes, sink.largest)
				}
				allocated := allocatedDuring(t, func() error { return operation.write(t.Context(), sha256.New(), 8<<20) })
				if allocated > 256<<10 {
					t.Fatalf("serialization allocated %d bytes for one large escaped node", allocated)
				}
				allocated = allocatedDuring(t, func() error {
					err := operation.write(t.Context(), io.Discard, 1024)
					if !errors.Is(err, document.ErrLimit) {
						return errors.New("small output limit not enforced")
					}
					return nil
				})
				if allocated > 256<<10 {
					t.Fatalf("small output limit still allocated %d bytes", allocated)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				sink = streamingSink{afterWrite: cancel}
				if err := operation.write(ctx, &sink, 8<<20); !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
				if sink.bytes > 32<<10 {
					t.Fatalf("cancellation consumed %d output bytes", sink.bytes)
				}
			})
		}
	}
}

func TestDocumentParserWorkingStorage(t *testing.T) {
	for _, size := range []int{16 << 10, 1 << 20} {
		source := []byte(`<r>` + strings.Repeat("x", size) + `</r>`)
		for _, reader := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/reader=%v", size, reader), func(t *testing.T) {
				allocated := allocatedDuring(t, func() error {
					var doc *document.Document
					var err error
					if reader {
						doc, err = document.ParseReader(t.Context(), bytes.NewReader(source), document.DefaultLimits())
					} else {
						doc, err = document.Parse(t.Context(), source, document.DefaultLimits())
					}
					if err == nil && len(doc.Root().Text()) != size {
						return errors.New("parser changed text")
					}
					return err
				})
				t.Logf("%d text bytes: %d allocated", size, allocated)
				if allocated > uint64(6*size+128<<10) {
					t.Fatalf("parser allocated %d bytes for %d text bytes", allocated, size)
				}
			})
		}
	}
}

func TestDocumentReaderAndWriterCompletion(t *testing.T) {
	failure := errors.New("source failed with its final bytes")
	data := []byte(`<r>ok</r>`)
	read := false
	source := readFunc(func(dst []byte) (int, error) {
		if read {
			return 0, io.EOF
		}
		read = true
		return copy(dst, data), failure
	})
	if doc, err := document.ParseReader(t.Context(), source, document.DefaultLimits()); doc != nil || !errors.Is(err, failure) {
		t.Fatal(doc, err)
	}
	doc, err := document.Parse(t.Context(), data, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sink := &streamingSink{}
	sink.afterWrite = func() {
		if sink.bytes == len(data) {
			cancel()
		}
	}
	if _, err := doc.WriteXML(ctx, sink, 1024); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var absent *streamingSink
	if _, err := doc.WriteXML(t.Context(), absent, 1024); !errors.Is(err, document.ErrMalformed) {
		t.Fatal(err)
	}
}

func TestFifthEditionNamesAcrossLibrary(t *testing.T) {
	const name = "\U00010000"
	input := `<` + name + ` xmlns:` + name + `="urn:n" ` + name + `:Ϳ="value"><Ϳ/></` + name + `>`
	doc, err := document.ParseReader(t.Context(), iotest.OneByteReader(strings.NewReader(input)), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var canonical bytes.Buffer
	if err := c14n.WriteDocument(t.Context(), &canonical, doc, c14n.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(canonical.String(), name+`:Ϳ="value"`) || doc.Root().Name().Local != name {
		t.Fatal("name identity changed")
	}
	count := 0
	err = document.ReadRecords(t.Context(), strings.NewReader(input), document.RecordOptions{Path: []document.Name{{Local: name}, {Local: "Ϳ"}}}, func(record *document.Document) error {
		count++
		if record.Root().Name().Local != "Ϳ" {
			t.Fatal("record name changed")
		}
		return nil
	})
	if err != nil || count != 1 {
		t.Fatal("record parsing", count, err)
	}
}
