package transform

import (
	"context"
	"io"
	"math"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// StreamOptions configures XSLT execution over independent XML records.
// Each record gets its own dynamic context and execution budget. Cross-record
// XPath navigation, sorting and grouping are unavailable: each invocation's
// source document contains only that record.
type StreamOptions struct {
	// Records selects subtrees and bounds each record's input. Its limits are
	// intersected with the engine input limits.
	Records document.RecordOptions
	// Context is applied independently to each record invocation.
	Context XSLTContext
	// Separator is written between record serializations, without escaping.
	Separator string
	// OnMessage receives diagnostics after record execution and before serialization.
	// Nil discards messages; a callback error stops the stream.
	OnMessage func(Message) error
	// MaxOutputBytes bounds total output, including separators. Zero leaves the
	// total unbounded; each record still obeys the engine output limit.
	MaxOutputBytes int64
}

// WriteRecords parses, transforms and serializes one record at a time. It never
// constructs the enclosing tree or collects output across records. Working
// storage includes the current record/result and serialization intermediates,
// parser tokens and ancestor context. The compiled stylesheet, parameters and
// invocation resources also remain in memory. Callbacks may retain more data.
// Each record gets fresh execution/serialization budgets; the engine timeout
// also bounds the complete WriteRecords call. MaxOutputBytes caps total bytes,
// not peak heap usage. Blocking streams must support cancellation themselves.
// Both streams remain caller-owned. Any error may leave partial output, including
// complete earlier records; the caller decides when to commit external effects.
func (s *Stylesheet) WriteRecords(ctx context.Context, dst io.Writer, src io.Reader, options StreamOptions) (int64, error) {
	if s == nil || s.engine == nil || nilcheck.IsNil(src) || nilcheck.IsNil(dst) || options.MaxOutputBytes < 0 {
		return 0, wrap("stream XSLT", ErrInput)
	}

	ctx, cancel, err := s.engine.invocation(ctx)
	if err != nil {
		return 0, err
	}
	defer cancel()

	maximum := options.MaxOutputBytes
	if maximum == 0 {
		maximum = math.MaxInt64
	}

	writer := streamio.Writer{Context: ctx, Target: dst, Limit: maximum, LimitError: ErrLimit}
	records := options.Records
	records.Limits = s.recordLimits(records.Limits)
	first := true
	err = s.engine.parseOptions().ReadRecords(ctx, src, records, func(record *document.Document) error {
		if !first {
			if _, err := writer.WriteString(options.Separator); err != nil {
				return err
			}
		}

		first = false

		input, err := s.engine.Import(ctx, record)
		if err != nil {
			return err
		}

		return s.writeRecord(ctx, &writer, input, options)
	})

	return writer.Written, wrap("stream XSLT", err)
}

func (s *Stylesheet) writeRecord(ctx context.Context, dst io.Writer, input *Document, options StreamOptions) error {
	result, err := s.Execute(ctx, input, options.Context)
	if err != nil {
		return err
	}

	if len(result.native.Secondary) != 0 {
		return ErrUnsupported
	}

	if options.OnMessage != nil {
		for _, message := range result.messages {
			if err := options.OnMessage(message); err != nil {
				return err
			}
		}
	}

	_, err = result.WriterTo(ctx).WriteTo(dst)

	return err
}

func (s *Stylesheet) recordLimits(limits document.Limits) document.Limits {
	if limits == (document.Limits{}) {
		limits = document.DefaultLimits()
	}

	limits.MaxBytes = min(limits.MaxBytes, s.engine.limits.MaxInputBytes)
	limits.MaxNodes = min(limits.MaxNodes, s.engine.limits.MaxNodes)
	limits.MaxDepth = min(limits.MaxDepth, s.engine.limits.MaxDepth)

	return limits
}
