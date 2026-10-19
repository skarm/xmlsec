package xdm

import (
	"context"
	"io"
)

// URIResolver retrieves a resource explicitly authorized by the application.
// Callers enforce cancellation and byte limits while consuming the returned stream.
type URIResolver interface {
	Resolve(context.Context, string) (io.ReadCloser, error)
}
