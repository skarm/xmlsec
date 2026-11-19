package xpath //nolint:testpackage // Exercises invocation-local text snapshots and resource controls directly.

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestUnparsedTextSharesSnapshotsByURIAndEncoding(t *testing.T) {
	t.Parallel()
	const base = "https://example.test/sample/query.xq"
	const resource = "https://example.test/sample/notes.txt"
	const source = `(unparsed-text-available('notes.txt'), unparsed-text-lines('./notes.txt'),
		unparsed-text('https://example.test/sample/notes.txt'),
		unparsed-text('notes.txt', 'ISO-8859-1'), unparsed-text('notes.txt', 'ISO-8859-1'))`
	expression, err := NewCompiler().Language(31, nil).Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	var readers []*documentTestReader
	resolver := documentResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
		calls = append(calls, uri)
		if uri != resource {
			return nil, fs.ErrNotExist
		}
		body := "alpha\r\n\rfin"
		if len(readers)%2 == 1 {
			body = "caf\xe9"
		} else if len(readers) > 1 {
			body = "beta\r\n\rfin"
		}
		reader := &documentTestReader{Reader: iotest.OneByteReader(strings.NewReader(body))}
		readers = append(readers, reader)
		return reader, nil
	})
	evaluator := NewEvaluator(DefaultEvaluatorOptions).BaseURI(base).URIResolver(resolver)
	for _, prefix := range []string{"alpha", "beta"} {
		result, err := evaluator.Evaluate(t.Context(), expression, nil)
		if err != nil {
			t.Fatalf("Evaluate (%s): %v", prefix, err)
		}
		assertAtomicSequence(t, result.Sequence(), []xdm.AtomicValue{
			{TypeName: xdm.TypeBoolean, Value: true},
			{TypeName: xdm.TypeString, Value: prefix},
			{TypeName: xdm.TypeString, Value: ""},
			{TypeName: xdm.TypeString, Value: "fin"},
			{TypeName: xdm.TypeString, Value: prefix + "\r\n\rfin"},
			{TypeName: xdm.TypeString, Value: "café"},
			{TypeName: xdm.TypeString, Value: "café"},
		})
	}
	if !slices.Equal(calls, []string{resource, resource, resource, resource}) {
		t.Errorf("resolved %q, want two opens of %q per evaluation", calls, resource)
	}
	for i, reader := range readers {
		if reader.closed != 1 {
			t.Errorf("reader %d closed %d times, want once", i, reader.closed)
		}
	}
}

func TestUnparsedTextAndJSONDocShareCompatibleSnapshot(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, source string
		want         []xdm.AtomicValue
	}{
		{"text_then_json", `(unparsed-text('urn:sample'),json-doc('urn:sample')?count eq 3)`, []xdm.AtomicValue{{TypeName: xdm.TypeString, Value: `{"count":3}`}, {TypeName: xdm.TypeBoolean, Value: true}}},
		{"json_then_text", `(json-doc('urn:sample')?count eq 3,unparsed-text('urn:sample'))`, []xdm.AtomicValue{{TypeName: xdm.TypeBoolean, Value: true}, {TypeName: xdm.TypeString, Value: `{"count":3}`}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := &documentTestReader{Reader: strings.NewReader(`{"count":3}`)}
			opens := 0
			resolver := documentResolverFunc(func(_ context.Context, uri string) (io.ReadCloser, error) {
				opens++
				if uri != "urn:sample" || opens != 1 {
					return nil, fs.ErrNotExist
				}
				return reader, nil
			})
			expression, err := NewCompiler().Language(31, nil).Compile(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewEvaluator(DefaultEvaluatorOptions).URIResolver(resolver).Evaluate(t.Context(), expression, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertAtomicSequence(t, result.Sequence(), tc.want)
			if opens != 1 || reader.closed != 1 {
				t.Errorf("opens=%d, closes=%d; want one open and one close", opens, reader.closed)
			}
		})
	}
}

func TestUnparsedTextRetrievalAndDecodingDiagnostics(t *testing.T) {
	t.Parallel()
	closeFailure := errors.New("resource close failed")
	for _, tc := range []struct {
		name, source, body, code string
		resolverErr, closeErr    error
		want                     []xdm.AtomicValue
		opens                    int
	}{
		{name: "availability_caches_missing_resource", source: `(unparsed-text-available('urn:missing'),unparsed-text-available('urn:missing'))`, resolverErr: fs.ErrNotExist, want: []xdm.AtomicValue{{TypeName: xdm.TypeBoolean, Value: false}, {TypeName: xdm.TypeBoolean, Value: false}}, opens: 1},
		{name: "retrieval_error_retains_resolver_cause", source: `unparsed-text('urn:missing')`, resolverErr: fs.ErrNotExist, code: "FOUT1170", opens: 1},
		{name: "empty_explicit_encoding_does_not_resolve", source: `unparsed-text-lines('urn:text','')`, code: "FOUT1190"},
		{name: "invalid_utf8_is_a_decoding_error", source: `unparsed-text('urn:text','UTF-8')`, body: "\xff", code: "FOUT1190", opens: 1},
		{name: "closing_error_is_not_a_successful_read", source: `unparsed-text('urn:text')`, body: "good", closeErr: closeFailure, opens: 1},
		{name: "empty_arguments_do_not_resolve", source: `(unparsed-text(()),unparsed-text-lines(()),unparsed-text-available(()))`, want: []xdm.AtomicValue{{TypeName: xdm.TypeBoolean, Value: false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := &documentTestReader{Reader: strings.NewReader(tc.body), err: tc.closeErr}
			opens := 0
			resolver := documentResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				opens++
				if tc.resolverErr != nil {
					return nil, tc.resolverErr
				}
				return reader, nil
			})
			expression, err := NewCompiler().Language(31, nil).Compile(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewEvaluator(DefaultEvaluatorOptions).URIResolver(resolver).Evaluate(t.Context(), expression, nil)
			if tc.want != nil {
				if err != nil || result == nil {
					t.Fatalf("Evaluate returned %v, %v; want %v", result, err, tc.want)
				}
				assertAtomicSequence(t, result.Sequence(), tc.want)
			} else {
				if result != nil || err == nil {
					t.Fatalf("Evaluate returned %v, %v; want only a diagnostic", result, err)
				}
				if tc.code != "" && !errors.Is(err, &xdm.Error{Code: tc.code}) {
					t.Errorf("Evaluate error = %v, want %s", err, tc.code)
				}
				if tc.resolverErr != nil && !errors.Is(err, tc.resolverErr) {
					t.Errorf("resolver cause missing from %v", err)
				}
				if tc.closeErr != nil && !errors.Is(err, tc.closeErr) {
					t.Errorf("close cause missing from %v", err)
				}
			}
			wantCloses := tc.opens
			if tc.resolverErr != nil {
				wantCloses = 0
			}
			if opens != tc.opens || reader.closed != wantCloses {
				t.Errorf("opens=%d, closes=%d; want %d and %d", opens, reader.closed, tc.opens, wantCloses)
			}
		})
	}
}

func TestUnparsedTextPreservesCancellationDuringResourceCallbacks(t *testing.T) {
	t.Parallel()

	const uri = "https://example.test/note.txt"
	args := []xdm.Sequence{xdm.SingleString(uri)}

	t.Run("resolver error and cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		ec := &evalContext{uriResolver: documentResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			cancel()
			return nil, fs.ErrNotExist
		})}
		result, err := fnUnparsedText(withFnContext(ctx, ec), args)
		if result != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, fs.ErrNotExist) || !errors.Is(err, &xdm.Error{Code: "FOUT1170"}) {
			t.Fatalf("got %v, %v; want FOUT1170 retaining both retrieval failure and cancellation", result, err)
		}
	})

	t.Run("cached availability", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		recorded := 0
		ec := &evalContext{
			uriResolver: documentResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("ordinary notes")), nil
			}),
			resourceReads: textReadRecorder(func() {
				recorded++
				if recorded == 2 {
					cancel()
				}
			}),
		}
		ctx = WithInvocationScope(withFnContext(ctx, ec))
		result, err := fnUnparsedTextAvailable(ctx, args)
		if err != nil {
			t.Fatal(err)
		}
		assertAtomicSequence(t, result, []xdm.AtomicValue{{TypeName: xdm.TypeBoolean, Value: true}})
		result, err = fnUnparsedTextAvailable(ctx, args)
		if result != nil || !errors.Is(err, context.Canceled) || recorded != 2 {
			t.Fatalf("cached availability = %v, %v with %d reads; want cancellation after the second record", result, err, recorded)
		}
	})
}

type textReadRecorder func()

func (textReadRecorder) CheckRead(context.Context, string) error { return nil }

func (record textReadRecorder) RecordRead(context.Context, string) error {
	record()

	return nil
}
