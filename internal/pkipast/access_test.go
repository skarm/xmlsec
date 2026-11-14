package pkipast_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/pkipast"
)

type pastValidationSession struct {
	pkipast.Access[int, string, string]
}

func TestValidateCertificateDelegation(t *testing.T) {
	archiveTime := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	validationFailure := errors.New("certificate validation failed")
	for _, tc := range []struct {
		name string
		call func(context.Context, pastValidationSession, []byte, *historicalproof.Set) (string, string, error)
		at   time.Time
		err  error
	}{
		{
			name: "candidate_paths",
			call: func(ctx context.Context, session pastValidationSession, target []byte, proofs *historicalproof.Set) (string, string, error) {
				return pkipast.Validate(ctx, session, target, proofs)
			},
		},
		{
			name: "archive_at_fixed_time",
			call: func(ctx context.Context, session pastValidationSession, target []byte, proofs *historicalproof.Set) (string, string, error) {
				return pkipast.ValidateArchive(ctx, session, target, proofs, archiveTime)
			},
			at:  archiveTime,
			err: validationFailure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			const targetDER = "\x30\x02\x01\x02"
			proofs := &historicalproof.Set{}
			const wantResult, wantReport = "certificate result", "certificate report"
			calls := 0
			session := pastValidationSession{pkipast.NewAccess(
				func(gotCtx context.Context, gotDER []byte, gotProofs *historicalproof.Set, gotAt time.Time) (string, string, error) {
					calls++
					if gotCtx != ctx || !bytes.Equal(gotDER, []byte(targetDER)) || gotProofs != proofs || !gotAt.Equal(tc.at) {
						t.Errorf("certificate callback received context=%p, DER=%x, proofs=%p, time=%v; want %p, %x, %p, %v",
							gotCtx, gotDER, gotProofs, gotAt, ctx, targetDER, proofs, tc.at)
					}
					return wantResult, wantReport, tc.err
				},
				func(context.Context, int, *historicalproof.Set) (string, string, error) {
					t.Error("certificate validation invoked the path callback")
					return "", "", nil
				},
			)}
			result, report, err := tc.call(ctx, session, []byte(targetDER), proofs)
			if result != wantResult || report != wantReport || !errors.Is(err, tc.err) {
				t.Errorf("certificate validation returned (%q, %q, %v), want (%q, %q, %v)",
					result, report, err, wantResult, wantReport, tc.err)
			}
			if calls != 1 {
				t.Errorf("certificate callback called %d times, want once", calls)
			}
		})
	}
}

func TestValidatePathDelegation(t *testing.T) {
	ctx := t.Context()
	proofs := &historicalproof.Set{}
	const path, wantResult, wantReport = 42, "path result", "path report"
	validationFailure := errors.New("path validation failed")
	calls := 0
	session := pastValidationSession{pkipast.NewAccess(
		func(context.Context, []byte, *historicalproof.Set, time.Time) (string, string, error) {
			t.Error("path validation invoked the certificate callback")
			return "", "", nil
		},
		func(gotCtx context.Context, gotPath int, gotProofs *historicalproof.Set) (string, string, error) {
			calls++
			if gotCtx != ctx || gotPath != path || gotProofs != proofs {
				t.Errorf("path callback received context=%p, path=%d, proofs=%p; want %p, %d, %p",
					gotCtx, gotPath, gotProofs, ctx, path, proofs)
			}
			return wantResult, wantReport, validationFailure
		},
	)}
	result, report, err := pkipast.ValidatePath(ctx, session, path, proofs)
	if result != wantResult || report != wantReport || !errors.Is(err, validationFailure) {
		t.Errorf("ValidatePath returned (%q, %q, %v), want (%q, %q, %v)",
			result, report, err, wantResult, wantReport, validationFailure)
	}
	if calls != 1 {
		t.Errorf("path callback called %d times, want once", calls)
	}
}
