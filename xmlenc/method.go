package xmlenc

import (
	"context"
	"strconv"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// KeySize is optional even for fixed-size algorithms, but never changes the
// caller-selected key or parameters. The schema places it before all others.
func checkEncryptionMethod(ctx context.Context, method document.Element, algorithm string, bits int, parameters bool) error {
	if !matchesMethod(method, algorithm, false) {
		return ErrFormat
	}

	_, node := tree.Unwrap(method)
	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return ErrFormat
		}
	}

	for i, child := range method.Children() {
		if child.Name() == elementName(Namespace, "KeySize") {
			if i != 0 {
				return ErrFormat
			}

			if err := checkMethodKeySize(ctx, child, bits); err != nil {
				return err
			}
		} else if !parameters {
			return ErrFormat
		}
	}

	return ctx.Err()
}

func checkMethodKeySize(ctx context.Context, element document.Element, bits int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !exactAttributes(element) || len(element.Children()) != 0 {
		return ErrFormat
	}

	value := strings.Trim(element.Text(), " \t\r\n")

	value = strings.TrimPrefix(value, "+")
	if value == "" {
		return ErrFormat
	}

	for i := range len(value) {
		c := value[i]
		if c < '0' || c > '9' {
			return ErrFormat
		}

		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}

	if strings.TrimLeft(value, "0") != strconv.Itoa(bits) {
		return ErrFormat
	}

	return nil
}
