package tree_test

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestReadRecordsPreservesInheritedContext(t *testing.T) {
	t.Parallel()

	const source = `<feed xmlns="urn:feed" xmlns:p="urn:outer" xml:lang="en" xml:space="preserve" xml:base="https://example.test/library/" catalog="catalog">
		<group xmlns:p="urn:entry" xml:lang="fr" xml:base="sub/">
			<item xml:lang="de" xml:base="../a.xml"><p:value>first</p:value></item>
			<item xmlns="urn:other"><p:value>excluded</p:value></item>
			<other><item>excluded by path depth</item></other>
			<item><p:value>second</p:value></item>
		</group>
		<group xml:space="default"><item><p:value>third</p:value></item></group>
	</feed>`
	name := func(local string) tree.Name { return tree.Name{Space: "urn:feed", Local: local} }
	var records []*tree.Document
	err := tree.ReadRecords(t.Context(), iotest.OneByteReader(strings.NewReader(source)), tree.RecordOptions{
		Path: []tree.Name{name("feed"), name("group"), name("item")},
	}, func(doc *tree.Document) error {
		records = append(records, doc)
		return nil
	})
	if err != nil || len(records) != 3 {
		t.Fatalf("ReadRecords emitted %d records, error %v, want three records", len(records), err)
	}

	for index, want := range []struct {
		value, namespace, lang, space, base string
	}{
		{"first", "urn:entry", "de", "preserve", "https://example.test/library/a.xml"},
		{"second", "urn:entry", "fr", "preserve", "https://example.test/library/sub/"},
		{"third", "urn:outer", "en", "default", "https://example.test/library/"},
	} {
		doc := records[index]
		root := doc.Root()
		if root.Name() != name("item") || tree.Root(doc).Parent != nil {
			t.Fatalf("record %d root is %v, want detached %v", index, root.Name(), name("item"))
		}
		children := root.Children()
		if len(children) != 1 || children[0].Name() != (tree.Name{Space: want.namespace, Local: "value"}) || children[0].Text() != want.value {
			t.Errorf("record %d children = %v, want one {%s}value containing %q", index, children, want.namespace, want.value)
		}
		if namespace, ok := root.Namespace("p"); !ok || namespace != want.namespace {
			t.Errorf("record %d prefix p = %q, want %q", index, namespace, want.namespace)
		}
		for _, attribute := range []struct{ name, value string }{
			{"lang", want.lang}, {"space", want.space}, {"base", want.base},
		} {
			if got, ok := root.Attribute(tree.Name{Space: tree.XMLNamespace, Local: attribute.name}); !ok || got != attribute.value {
				t.Errorf("record %d xml:%s = %q, want %q", index, attribute.name, got, attribute.value)
			}
		}
		if _, inherited := root.Attribute(tree.Name{Local: "catalog"}); inherited {
			t.Errorf("record %d inherited the enclosing catalog attribute", index)
		}
	}
	if records[0] == records[1] || records[0].Root().Same(records[1].Root()) {
		t.Error("successive records share their identities")
	}
}

func TestReadRecordsBoundsAndTerminalErrors(t *testing.T) {
	t.Parallel()

	const one = `<feed><item>first</item></feed>`
	const two = `<feed><item>first</item><item>second</item></feed>`
	stop := errors.New("stop record delivery")
	sourceFailure := errors.New("record source failure")
	bounds := tree.DefaultLimits()
	bounds.MaxBytes = len("<item>first</item>")
	materialized := tree.DefaultLimits()
	materialized.MaxAttributesPerElement = 2

	for _, tc := range []struct {
		name, source string
		options      tree.RecordOptions
		terminal     error
		callback     error
		cancel       bool
		want         []string
		wantErr      error
	}{
		{name: "input_exact_limit", source: one, options: tree.RecordOptions{MaxInputBytes: int64(len(one))}, want: []string{"first"}},
		{name: "input_exceeds_limit", source: one, options: tree.RecordOptions{MaxInputBytes: int64(len(one) - 1)}, want: []string{"first"}, wantErr: tree.ErrLimit},
		{name: "record_bytes_limit_is_independent", source: two, options: tree.RecordOptions{Limits: bounds}, want: []string{"first"}, wantErr: tree.ErrLimit},
		{name: "record_count_exact_limit", source: one, options: tree.RecordOptions{MaxRecords: 1}, want: []string{"first"}},
		{name: "record_count_exceeds_limit", source: two, options: tree.RecordOptions{MaxRecords: 1}, want: []string{"first"}, wantErr: tree.ErrLimit},
		{name: "attributes_after_inheritance_exceed_limit", source: `<feed xml:lang="en" xml:space="preserve"><item id="first"/></feed>`, options: tree.RecordOptions{Limits: materialized}, wantErr: tree.ErrLimit},
		{name: "invalid_inherited_base", source: `<feed xml:base="%GG"><item>first</item></feed>`, wantErr: tree.ErrMalformed},
		{name: "unclosed_record_preserves_prior_callback", source: `<feed><item>first</item><item>`, want: []string{"first"}, wantErr: tree.ErrMalformed},
		{name: "bad_trailer_preserves_prior_callback", source: one + `<other/>`, want: []string{"first"}, wantErr: tree.ErrMalformed},
		{name: "callback_failure_stops_delivery", source: two, callback: stop, want: []string{"first"}, wantErr: stop},
		{name: "callback_cancellation_stops_delivery", source: two, cancel: true, want: []string{"first"}, wantErr: context.Canceled},
		{name: "joined_source_failure_is_not_eof", source: one, terminal: errors.Join(io.EOF, sourceFailure), want: []string{"first"}, wantErr: sourceFailure},
		{name: "empty_input_rejected", wantErr: tree.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			options := tc.options
			options.Path = []tree.Name{{Local: "feed"}, {Local: "item"}}

			var src io.Reader = strings.NewReader(tc.source)
			if tc.terminal != nil {
				src = io.MultiReader(src, iotest.ErrReader(tc.terminal))
			}

			var records []string
			err := tree.ReadRecords(ctx, src, options, func(doc *tree.Document) error {
				records = append(records, doc.Root().Text())
				if tc.cancel {
					cancel()
				}
				return tc.callback
			})
			if !slices.Equal(records, tc.want) || !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadRecords emitted %q, error %v, want %q and %v", records, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestReadRecordsRejectsInvalidOptionsBeforeDelivery(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		options tree.RecordOptions
		wantErr error
	}{
		{name: "missing_path", wantErr: tree.ErrMalformed},
		{name: "non_ncname_path_step", options: tree.RecordOptions{Path: []tree.Name{{Local: "p:item"}}}, wantErr: tree.ErrMalformed},
		{name: "negative_input_limit", options: tree.RecordOptions{Path: []tree.Name{{Local: "feed"}}, MaxInputBytes: -1}, wantErr: tree.ErrLimit},
		{name: "negative_record_limit", options: tree.RecordOptions{Path: []tree.Name{{Local: "feed"}}, MaxRecords: -1}, wantErr: tree.ErrLimit},
		{name: "incomplete_limits", options: tree.RecordOptions{Path: []tree.Name{{Local: "feed"}}, Limits: tree.Limits{MaxDepth: 1}}, wantErr: tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			unexpectedRead := errors.New("invalid configuration must be rejected before reading")
			called := false
			err := tree.ReadRecords(t.Context(), iotest.ErrReader(unexpectedRead), tc.options, func(*tree.Document) error {
				called = true
				return nil
			})
			if called || !errors.Is(err, tc.wantErr) || errors.Is(err, unexpectedRead) {
				t.Fatalf("ReadRecords called emit=%t, error=%v, want no callback and %v", called, err, tc.wantErr)
			}
		})
	}
}

func TestParseOptionsReadRecordsAppliesInputPolicy(t *testing.T) {
	t.Parallel()

	const source = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><feed xmlns=\"entry\"><item>caf\xe9</item></feed>"
	options := tree.RecordOptions{Path: []tree.Name{{Space: "entry", Local: "feed"}, {Space: "entry", Local: "item"}}}
	for _, tc := range []struct {
		name   string
		parser tree.ParseOptions
		want   []string
	}{
		{name: "default_policy"},
		{name: "relative_namespaces_disabled", parser: tree.ParseOptions{AllowSingleByteEncodings: true}},
		{name: "legacy_encoding_and_literal_relative_namespace", parser: tree.ParseOptions{AllowSingleByteEncodings: true, AllowRelativeNamespaces: true}, want: []string{"café"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var records []string
			err := tc.parser.ReadRecords(t.Context(), strings.NewReader(source), options, func(doc *tree.Document) error {
				root := doc.Root()
				if root.Name() != options.Path[1] {
					t.Errorf("root expanded name = %v, want %v", root.Name(), options.Path[1])
				}
				records = append(records, root.Text())
				return nil
			})
			if !slices.Equal(records, tc.want) || (err == nil) != (tc.want != nil) {
				t.Fatalf("ReadRecords emitted %q, error %v, want %q", records, err, tc.want)
			}
		})
	}
}
