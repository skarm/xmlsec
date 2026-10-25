package historical

import (
	"bytes"
	"context"
	"fmt"
	"slices"
)

func (g *graph) covered(ctx context.Context, candidate Candidate) (map[[32]byte]bool, error) {
	seen := make(map[[32]byte]bool)

	stack := slices.Clone(candidate.Covered)
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		key := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if seen[key] {
			continue
		}

		object, ok := g.objects[key]
		if !ok {
			return nil, ErrInput
		}

		seen[key] = true
		if len(seen) > g.maximum {
			return nil, ErrLimit
		}

		stack = append(stack, object.Contains...)
	}

	return seen, nil
}

// orderStamps processes protecting archives before the tokens they protect.
// Authenticated generation times break ties only between independent nodes;
// overlapping accuracy intervals cannot reverse a real containment dependency.
func orderStamps(ctx context.Context, g *graph, stamps []preparedStamp) ([]preparedStamp, error) {
	dependencies := make([][]int, len(stamps))

	indegree := make([]int, len(stamps))
	for index, stamp := range stamps {
		covered, err := g.covered(ctx, stamp.candidate)
		if err != nil {
			return nil, err
		}

		for target, other := range stamps {
			if !covered[other.assertion.TokenSHA256()] {
				continue
			}

			if index == target {
				return nil, fmt.Errorf("%w: timestamp covers itself", ErrInput)
			}

			dependencies[index] = append(dependencies[index], target)
			indegree[target]++
		}
	}

	ready := make([]int, 0, len(stamps))

	for index, count := range indegree {
		if count == 0 {
			ready = append(ready, index)
		}
	}

	ordered := make([]preparedStamp, 0, len(stamps))
	for len(ready) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		slices.SortFunc(ready, func(left, right int) int {
			a, b := stamps[left], stamps[right]
			if order := b.assertion.Info().GenTime().Compare(a.assertion.Info().GenTime()); order != 0 {
				return order
			}

			first, second := a.assertion.TokenSHA256(), b.assertion.TokenSHA256()

			return bytes.Compare(first[:], second[:])
		})
		index := ready[0]
		ready = ready[1:]

		ordered = append(ordered, stamps[index])
		for _, target := range dependencies[index] {
			indegree[target]--
			if indegree[target] == 0 {
				ready = append(ready, target)
			}
		}
	}

	if len(ordered) != len(stamps) {
		return nil, fmt.Errorf("%w: timestamp proof cycle", ErrInput)
	}

	return ordered, nil
}

func checkProtectedChronology(ctx context.Context, g *graph, stamp preparedStamp, accepted []preparedStamp) error {
	for _, covering := range accepted {
		covered, err := g.covered(ctx, covering.candidate)
		if err != nil {
			return err
		}

		if !covered[stamp.assertion.TokenSHA256()] {
			continue
		}

		accuracy := stamp.upper.Sub(stamp.assertion.Info().GenTime())
		if stamp.assertion.Info().GenTime().Add(-accuracy).After(covering.upper) {
			return fmt.Errorf("%w: archive predates protected token", ErrValidation)
		}

		if bytes.Equal(stamp.assertion.CertificateDER(), covering.assertion.CertificateDER()) && stamp.assertion.Info().Ordering() && covering.assertion.Info().Ordering() && stamp.assertion.Info().GenTime().After(covering.assertion.Info().GenTime()) {
			return fmt.Errorf("%w: same-TSA ordering", ErrValidation)
		}
	}

	return nil
}

func checkContentChronology(stamp preparedStamp, accepted []preparedStamp) error {
	for _, other := range accepted {
		if stamp.candidate.Archive || other.candidate.Archive || stamp.candidate.Content == other.candidate.Content {
			continue
		}

		content, signature := stamp, other
		if !content.candidate.Content {
			content, signature = signature, content
		}

		if bytes.Equal(content.assertion.CertificateDER(), signature.assertion.CertificateDER()) && content.assertion.Info().Ordering() && signature.assertion.Info().Ordering() {
			if content.assertion.Info().GenTime().Before(signature.assertion.Info().GenTime()) {
				continue
			}
		} else {
			accuracy := signature.upper.Sub(signature.assertion.Info().GenTime())
			if content.upper.Before(signature.assertion.Info().GenTime().Add(-accuracy)) {
				continue
			}
		}

		return fmt.Errorf("%w: content/signature timestamp ordering", ErrValidation)
	}

	return nil
}
