// Package pkipast lets the historical validation workflow call the PKI past
// certificate checks without exposing them to applications.
package pkipast

import (
	"context"
	"time"

	"github.com/skarm/xmlsec/internal/historicalproof"
)

// Access holds the past-validation methods of an initialized PKI session.
type Access[Path, Result, Report any] struct {
	validate     func(context.Context, []byte, *historicalproof.Set, time.Time) (Result, Report, error)
	validatePath func(context.Context, Path, *historicalproof.Set) (Result, Report, error)
}

// NewAccess binds an initialized session's validation methods.
func NewAccess[Path, Result, Report any](
	validate func(context.Context, []byte, *historicalproof.Set, time.Time) (Result, Report, error),
	validatePath func(context.Context, Path, *historicalproof.Set) (Result, Report, error),
) Access[Path, Result, Report] {
	return Access[Path, Result, Report]{validate: validate, validatePath: validatePath}
}

// pastAccess is promoted by an embedding session but stays private to pkipast.
func (a Access[Path, Result, Report]) pastAccess() Access[Path, Result, Report] { return a }

type session[Path, Result, Report any] interface {
	pastAccess() Access[Path, Result, Report]
}

// Validate checks a certificate across the session's candidate paths.
func Validate[Path, Result, Report any](ctx context.Context, s session[Path, Result, Report], targetDER []byte, proofs *historicalproof.Set) (Result, Report, error) {
	return s.pastAccess().validate(ctx, targetDER, proofs, time.Time{})
}

// ValidateArchive checks a certificate and its evidence at a fixed past time.
func ValidateArchive[Path, Result, Report any](ctx context.Context, s session[Path, Result, Report], targetDER []byte, proofs *historicalproof.Set, at time.Time) (Result, Report, error) {
	return s.pastAccess().validate(ctx, targetDER, proofs, at)
}

// ValidatePath checks one path selected by the caller.
func ValidatePath[Path, Result, Report any](ctx context.Context, s session[Path, Result, Report], path Path, proofs *historicalproof.Set) (Result, Report, error) {
	return s.pastAccess().validatePath(ctx, path, proofs)
}
