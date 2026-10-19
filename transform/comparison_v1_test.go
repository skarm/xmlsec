//go:build interop

package transform_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform"
)

func TestCompareLibxmlXPath10(t *testing.T) {
	binary, err := exec.LookPath("xmllint")
	if err != nil {
		t.Skip("xmllint is unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	source := `<r xmlns:p="urn:p" xml:lang="en-US"><v n="2">2</v><v n="3">3</v><p:x>4</p:x></r>`
	e := engine(t, transform.Config{})

	d, err := e.Parse(ctx, []byte(source))
	if err != nil {
		t.Fatal(err)
	}

	for _, expr := range []string{`count(/r/*)`, `name(/r/v[2]/preceding-sibling::*[1])`, `count(/r/v[1]/namespace::*)`, `string(/r/v)`, `sum(/r/v/@n)`, `/r/v = false()`, `/r/missing = false()`, `/r/v != 2`, `number('+1')`, nameNumber1e2, `string(1 div 0)`, `string(-0)`, `substring('12345',1.5,2.6)`, `normalize-space(' a  b ')`, `translate('abcab','aba','XY')`, `count(/r/*[lang('en')])`} {
		t.Run(expr, func(t *testing.T) {
			q := query(t, e, expr, transform.XPath10)

			v, err := q.Evaluate(ctx, d, transform.XPathContext{})
			if err != nil {
				t.Fatal(err)
			}

			command := exec.CommandContext(ctx, binary, "--nonet", "--xpath", expr, "-")
			command.Stdin = strings.NewReader(source)

			theirs, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("xmllint: %s: %v", theirs, err)
			}

			got := text(t, v)

			want := strings.TrimRight(string(theirs), "\r\n")
			if expr == nameNumber1e2 && want == "100" {
				if got != valueNaN {
					t.Fatalf("unexpected numeric grammar: local=%q libxml=%q", got, want)
				}

				t.Log("libxml accepts exponent syntax in number(); XPath 1.0 section 4.4 requires NaN")

				return
			}

			if got != want {
				t.Fatalf("local=%q libxml=%q", got, want)
			}
		})
	}
}

func TestCompareLibxslt10(t *testing.T) {
	binary, err := exec.LookPath("xsltproc")
	if err != nil {
		t.Skip("xsltproc is unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	source := `<r><n k="a">2</n><n k="a">3</n><n k="b">bad</n></r>`
	e := engine(t, transform.Config{})

	d, err := e.Parse(ctx, []byte(source))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	input := filepath.Join(dir, "source.xml")
	if err := os.WriteFile(input, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, body := range []string{
		`<xsl:template match="/"><xsl:value-of select="number(system-property('xsl:version'))"/></xsl:template>`,
		`<xsl:template match="/"><xsl:value-of select="/r/n"/>:<xsl:value-of select="1 div 0"/>:<xsl:value-of select="number('+1')"/></xsl:template>`,
		`<xsl:key name="by-k" match="n" use="@k"/><xsl:template match="/"><xsl:value-of select="count(key('by-k','a'))"/>:<xsl:value-of select="sum(/r/n)"/></xsl:template>`,
		`<xsl:template match="/"><xsl:variable name="v"><a>2</a></xsl:variable><xsl:value-of select="concat(string($v),':',boolean($v),':',$v + 1)"/></xsl:template>`,
		`<xsl:template match="/"><xsl:for-each select="/r/n"><xsl:sort select="@k" order="descending"/><xsl:number/><xsl:text>=</xsl:text><xsl:value-of select="."/><xsl:text>;</xsl:text></xsl:for-each></xsl:template>`,
		`<xsl:template match="/"><xsl:value-of select="format-number(0.125,'0.0%')"/></xsl:template>`,
	} {
		sheetSource := []byte(xslt10(body))

		s, err := e.CompileXSLT(ctx, sheetSource, transform.XSLTOptions{})
		if err != nil {
			t.Fatal(err)
		}

		ours, err := s.Transform(ctx, d, transform.XSLTContext{})
		if err != nil {
			t.Fatal(err)
		}

		path := filepath.Join(dir, "style.xsl")
		if err := os.WriteFile(path, sheetSource, 0o600); err != nil {
			t.Fatal(err)
		}

		theirs, err := exec.CommandContext(ctx, binary, "--nonet", "--novalid", path, input).CombinedOutput()
		if err != nil {
			t.Fatalf("xsltproc: %s: %v", theirs, err)
		}

		if string(ours.Primary) != string(theirs) {
			t.Fatalf("local=%q libxslt=%q", ours.Primary, theirs)
		}
	}
}
