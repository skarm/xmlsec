package xmldsig

import (
	"context"
	"errors"
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

func parseProgramTransform(ctx context.Context, n *tree.Node, doc *document.Document) (reference.Transform, error) {
	t, err := transformxml.ParseProgram(ctx, n, doc)
	return t, transformXMLError(err)
}

func appendProgramParameters(ctx context.Context, n *tree.Node, t reference.Transform) error {
	return transformXMLError(transformxml.AppendProgram(ctx, n, t))
}

func transformXMLError(err error) error {
	if errors.Is(err, reference.ErrInput) {
		return fmt.Errorf("%w: %w", ErrStructure, err)
	}

	return processingError(err)
}

func prepareProgramReferences(ctx context.Context, p *corePlan) error {
	for _, task := range p.graph.tasks {
		if err := reference.PrepareTransforms(ctx, task.ref.transforms, p.processing); err != nil {
			return task.wrap("preflight", processingError(err))
		}
	}

	return nil
}
