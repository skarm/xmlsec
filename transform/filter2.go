// Adapted from knroy/go-xmlsec, dsig/xpath.go (selection.expanded and Filter2).
// Commit 038f602c093dcefd3c66f0022a243a9b67deb4ef.
// Copyright (c) 2026 Komol Nath Roy. MIT License.
//
// SPDX-License-Identifier: MIT
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package transform

import (
	"context"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

type filterSelection struct {
	operation string
	roots     map[document.Node]bool
}

func (f filterSelection) expanded(ctx context.Context, n document.Node) (bool, error) {
	// Namespace handles retain owner + prefix identity, so exact membership and
	// expansion through the owner use the same map as every other node kind.
	for ; n.Valid(); n = n.Parent() {
		if err := xpath.Charge(ctx, 1); err != nil {
			return false, err
		}

		if f.roots[n] {
			return true, nil
		}
	}

	return false, nil
}

func filterNodes(ctx context.Context, input []document.Node, filters []filterSelection) ([]document.Node, error) {
	var out []document.Node

	for _, n := range input {
		// Filter2 starts with the whole document; only the final intersection with
		// the original input is returned. A union cannot introduce foreign nodes.
		keep := true

		for _, f := range filters {
			selected, err := f.expanded(ctx, n)
			if err != nil {
				return nil, err
			}

			switch f.operation {
			case "intersect":
				keep = keep && selected
			case "subtract":
				keep = keep && !selected
			case "union":
				keep = keep || selected
			}
		}

		if keep {
			out = append(out, n)
		}
	}

	return out, nil
}
