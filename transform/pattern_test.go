package transform_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

const (
	nameFalse       = "false"
	errCodeFORX0003 = "FORX0003"
)

func TestXPathQuantifiedAnchors(t *testing.T) {
	e := engine(t, transform.Config{})

	for _, version := range []transform.XPathVersion{transform.XPath20, transform.XPath30, transform.XPath31} {
		for expression, want := range map[string]string{
			`matches('alpha', 'alp^?ha')`:     nameTrue,
			`matches('alpha', 'alp^+ha')`:     nameFalse,
			`matches('alpha', '^{2}alpha')`:   nameTrue,
			`matches('zalpha', '^{2}alpha')`:  nameFalse,
			`matches('alpha', 'alp$?ha')`:     nameTrue,
			`matches('alpha', 'alp${2,4}ha')`: nameFalse,
			`matches('alpha', 'alpha$+')`:     nameTrue,
			`matches('alphax', 'alpha$+')`:    nameFalse,
			`replace('alpha', '^*', 'x')`:     "error",
		} {
			value, err := query(t, e, expression, version).Evaluate(t.Context(), nil, transform.XPathContext{})
			if want == "error" {
				var detail *transform.Error
				if !errors.As(err, &detail) || detail.Code != errCodeFORX0003 {
					t.Fatal(expression, value, err)
				}
			} else if err != nil || text(t, value) != want {
				t.Fatal(version, expression, value, err)
			}
		}
	}
}

// TestXPathPatternFunctions checks F&O 3.1 §5.6 pattern semantics.
func TestXPathPatternFunctions(t *testing.T) {
	e := engine(t, transform.Config{})
	for source, want := range map[string]string{
		`matches('bcdf', '^[a-z-[aeiou]]+$')`:                                                      nameTrue,
		`matches('bcaf', '^[a-z-[aeiou]]+$')`:                                                      nameFalse,
		`matches('abab', '^(ab)\1$')`:                                                              nameTrue,
		`matches('aa2', '^(a)\12$')`:                                                               nameTrue,
		`matches('Mum', '^([md])[aeiou]\1$', 'i')`:                                                 nameTrue,
		`matches('a', '\p{Lu}', 'i')`:                                                              nameFalse,
		`matches('A', '\p{Lu}', 'i')`:                                                              nameTrue,
		`matches('a', '\P{Lu}', 'i')`:                                                              nameTrue,
		`matches('b', '[\p{Lu}q]', 'i')`:                                                           nameFalse,
		`matches('Q', '[\p{Lu}q]', 'i')`:                                                           nameTrue,
		`matches('K', '[A-Z]', 'i')`:                                                               nameTrue,
		`matches('K', '[\p{IsBasicLatin}]', 'i')`:                                                  nameFalse,
		`matches('K', '\P{IsBasicLatin}', 'i')`:                                                    nameTrue,
		`matches('١٢', '^\d+$')`:                                                                   nameTrue,
		`matches('имя', '^\i\c*$')`:                                                                nameTrue,
		`matches('abc', '^\p{IsBasicLatin}+$')`:                                                    nameTrue,
		`matches('hello world', 'hello\ sworld', 'x')`:                                             nameTrue,
		`matches('helloworld', 'hello world', 'x')`:                                                nameTrue,
		`matches('a b', 'a b', 'qx')`:                                                              nameTrue,
		`matches('a.b', 'A.B', 'qi')`:                                                              nameTrue,
		`matches(codepoints-to-string(13), '.')`:                                                   nameFalse,
		`matches(codepoints-to-string(13), '.', 's')`:                                              nameTrue,
		`matches(concat('a',codepoints-to-string(10)), '^$', 'm')`:                                 nameTrue,
		`replace('abracadabra', 'a.*a', '*')`:                                                      "*",
		`replace('abracadabra', 'a.*?a', '*')`:                                                     "*c*bra",
		`replace('abracadabra', 'a(.)', 'a$1$1')`:                                                  "abbraccaddabbra",
		`replace('ab ab', '(a)(b)', '$2$1')`:                                                       "ba ba",
		`replace('aa2', '(a)\12', '$12')`:                                                          "a2",
		`replace('a.b', '.', '$1\', 'q')`:                                                          `a$1\b`,
		`replace('αβ', '(α)(β)', '$2$1')`:                                                          "βα",
		`string-join(tokenize('abracadabra', '(ab)|(a)'), '|')`:                                    "|r|c|d|r|",
		`string-join(tokenize(concat('a',codepoints-to-string(10),'ab'), '^a', 'm'), '|')`:         "|\n|b",
		`string-join(analyze-string('A1,C15', '([A-Z])([0-9]+)')/fn:match/fn:group[@nr='2'], '|')`: "1|15",
		`string-join(analyze-string('abc', '(a(b))(c)')/fn:match/fn:group[@nr='1']/fn:group, '|')`: "b",
	} {
		t.Run(source, func(t *testing.T) {
			if got := text(t, evaluate(t, e, source, transform.XPath31)); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}

	q := query(t, e, `matches($input,'^a{1001}$')`, transform.XPath20)

	result, err := q.Evaluate(context.Background(), nil, transform.XPathContext{Variables: transform.Bindings{
		{Local: "input"}: transform.Values(transform.String(strings.Repeat("a", 1001))),
	}})
	if err != nil || text(t, result) != nameTrue {
		t.Fatal("large repeat lost", result, err)
	}

	for source, code := range map[string]string{
		`matches('a', '.', 'invalid')`: "FORX0001",
		`matches('a', '[a')`:           errCodeFORX0002,
		`matches('a', '(a\1)')`:        errCodeFORX0002,
		`replace('a', 'a*', 'b')`:      errCodeFORX0003,
		`tokenize('a', 'a?')`:          errCodeFORX0003,
		`replace('a', 'a', '$')`:       "FORX0004",
	} {
		_, err := query(t, e, source, transform.XPath31).Evaluate(context.Background(), nil, transform.XPathContext{})

		var detail *transform.Error
		if !errors.As(err, &detail) || detail.Code != code {
			t.Errorf("%s: %v, want %s", source, err, code)
		}
	}
}

func TestXSLTPatternGroups(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, version := range []string{version20, version30} {
		s := stylesheet(t, e, sheet(version, `<xsl:template name="start"><xsl:analyze-string select="'A1,C15'" regex="([A-Z])([0-9]+)"><xsl:matching-substring><xsl:value-of select="concat(regex-group(2),regex-group(1))"/></xsl:matching-substring><xsl:non-matching-substring><xsl:value-of select="."/></xsl:non-matching-substring></xsl:analyze-string></xsl:template>`))

		out, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}})
		if err != nil || string(out.Primary) != "1A,15C" {
			t.Fatal(version, out, err)
		}
	}
}

func TestPatternBudgetErrors(t *testing.T) {
	e := engine(t, transform.Config{Limits: transform.Limits{MaxOperations: 400}})

	input := transform.Bindings{{Local: "input"}: transform.Values(transform.String(strings.Repeat("a", 500)))}
	for _, source := range []string{`matches($input,'^(a|aa)*b$')`, `replace($input,'(a|aa)+b','X')`, `tokenize($input,'(a|aa)+b')`, `analyze-string($input,'(a|aa)+b')`} {
		_, err := query(t, e, source, transform.XPath31).Evaluate(context.Background(), nil, transform.XPathContext{Variables: input})
		if !errors.Is(err, transform.ErrLimit) {
			t.Errorf("%s: limit cause lost: %v", source, err)
		}
	}

	s := stylesheet(t, e, sheet(version30, `<xsl:param name="input"/><xsl:template name="start"><xsl:analyze-string select="$input" regex="(a|aa)+b"><xsl:matching-substring>match</xsl:matching-substring></xsl:analyze-string></xsl:template>`))

	_, err := s.Transform(context.Background(), nil, transform.XSLTContext{Template: transform.Name{Local: nameStart}, Parameters: input})
	if !errors.Is(err, transform.ErrLimit) {
		t.Fatal("XSLT limit cause lost", err)
	}

	q := query(t, e, `matches('a','a{999999999999999999999999999999999999}')`, transform.XPath31)
	if _, err := q.Evaluate(context.Background(), nil, transform.XPathContext{}); !errors.Is(err, transform.ErrLimit) {
		t.Fatal("compile limit cause lost", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := q.Evaluate(ctx, nil, transform.XPathContext{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost", err)
	}
}
