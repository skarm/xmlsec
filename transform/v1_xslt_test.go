package transform_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
)

func TestXSLTTemplatesVariablesAndFocus(t *testing.T) {
	tr := style(`<xsl:output method="text"/><xsl:template match="/"><xsl:variable name="suffix" select="'!'"/><xsl:for-each select="/r/item"><xsl:sort select="."/><xsl:if test="position()=last()"><xsl:call-template name="emit"><xsl:with-param name="value" select="concat(., $suffix)"/></xsl:call-template></xsl:if></xsl:for-each></xsl:template><xsl:template name="emit"><xsl:param name="value"/><xsl:value-of select="$value"/></xsl:template>`)
	p := newProcessor(t, tr)

	out, err := p.Apply(context.Background(), tr, reference.Octets([]byte(`<r><item>b</item><item>a</item></r>`)), reference.ExtensionContext{})
	if err != nil {
		t.Fatal(err)
	}

	got, _ := out.Bytes()
	if string(got) != "b!" {
		t.Fatalf("XSLT scope, sorting and focus: %q", got)
	}
}

func TestXSLTProfilePreflight(t *testing.T) {
	for _, body := range []string{
		`<xsl:include href="file:///etc/passwd"/>`,
		`<xsl:import href="https://example.invalid/style"/>`,
		`<xsl:template match="/"><xsl:value-of select="document('file:///etc/passwd')"/></xsl:template>`,
		`<xsl:template match="/"><out value="{document('https://example.invalid/')}"/></xsl:template>`,
		`<xsl:template match="/"><xsl:sequence select="1"/></xsl:template>`,
		`<xsl:template match="/" use-when="false()"/>`,
		`<xsl:template match="/"><xsl:value-of select="if (true()) then 1 else 2"/></xsl:template>`,
		`<xsl:template match="/"><xsl:value-of select="unparsed-text('file:///etc/passwd')"/></xsl:template>`,
		`<xsl:template match="/"><out xsl:version="3.0"/></xsl:template>`,
		`<xsl:template match="/"><out value="}"/></xsl:template>`,
	} {
		t.Run(body, func(t *testing.T) {
			if _, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{style(body)}}); err == nil {
				t.Fatal("unsupported stylesheet compiled")
			}
		})
	}

	tr := style(`<xsl:output method="xml" omit-xml-declaration="yes"/><xsl:template match="/"><out value="{{{concat('}', /r/value)}}}"/></xsl:template>`)
	p := newProcessor(t, tr)

	out, err := p.Apply(context.Background(), tr, reference.Octets([]byte(`<r><value>ok</value></r>`)), reference.ExtensionContext{})
	if err != nil {
		t.Fatal(err)
	}

	got, _ := out.Bytes()
	if !bytes.Contains(got, []byte(`value="{}ok}"`)) {
		t.Fatalf("AVT quote/brace handling: %q", got)
	}
}

func TestXSLTLimitsAndContext(t *testing.T) {
	ctx := context.Background()

	text := style(`<xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="/r"/></xsl:template>`)
	for _, cfg := range []transform.Config{{Limits: transform.Limits{MaxInputBytes: 5}}, {Limits: transform.Limits{MaxNodes: 1}}, {Limits: transform.Limits{MaxOutputBytes: 2}}} {
		cfg.AllowedPrograms = []reference.Transform{text}

		p, err := transform.NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}

		out, err := p.Apply(ctx, text, reference.Octets([]byte(`<r>long</r>`)), reference.ExtensionContext{})
		if !errors.Is(err, reference.ErrLimit) || out.Kind() != reference.Invalid {
			t.Fatalf("input=%d nodes=%d output=%d: %v, %v", cfg.Limits.MaxInputBytes, cfg.Limits.MaxNodes, cfg.Limits.MaxOutputBytes, out.Kind(), err)
		}
	}

	recursive := style(`<xsl:template match="/"><xsl:call-template name="loop"/></xsl:template><xsl:template name="loop"><xsl:call-template name="loop"/></xsl:template>`)

	p, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{recursive}, Limits: transform.Limits{MaxDepth: 4}})
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.Apply(ctx, recursive, reference.Octets([]byte(`<r/>`)), reference.ExtensionContext{})
	if !errors.Is(err, reference.ErrLimit) || out.Kind() != reference.Invalid {
		t.Fatalf("recursion: %v, %v", out.Kind(), err)
	}

	p = newProcessor(t, text)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err = p.Apply(cancelled, text, reference.Octets([]byte(`<r/>`)), reference.ExtensionContext{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()

	if _, err = p.Apply(expired, text, reference.Octets([]byte(`<r/>`)), reference.ExtensionContext{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}

	if err = p.Validate(nil, text); !errors.Is(err, reference.ErrInput) {
		t.Fatal(err)
	}

	if _, err = p.Apply(ctx, text, input(t, parse(t, `<r/>`)), reference.ExtensionContext{}); !errors.Is(err, reference.ErrInput) {
		t.Fatal(err)
	}
}

func TestXSLTImmutableConcurrentApproval(t *testing.T) {
	tr := style(`<xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="/r"/></xsl:template>`)
	approved := reference.CloneTransforms([]reference.Transform{tr})[0]

	p := newProcessor(t, tr)
	for i := range tr.Stylesheet {
		tr.Stylesheet[i] = 'x'
	}

	if err := p.Validate(context.Background(), approved); err != nil {
		t.Fatal(err)
	}

	changed := style(`<xsl:output method="text"/><xsl:template match="/"><xsl:text>changed</xsl:text></xsl:template>`)
	if err := p.Validate(context.Background(), changed); !errors.Is(err, reference.ErrPolicy) {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			out, err := p.Apply(context.Background(), approved, reference.Octets([]byte(`<r>yes</r>`)), reference.ExtensionContext{})

			got, _ := out.Bytes()
			if err != nil || string(got) != nameYes {
				t.Errorf("concurrent XSLT: %q, %v", got, err)
			}
		})
	}

	wg.Wait()
}

func TestXSLTExecutionTimeout(t *testing.T) {
	// Two calls per level would perform billions of template invocations. Depth is
	// bounded and no large source/output is needed: the timeout must stop the work.
	tr := style(`<xsl:output method="text"/><xsl:template match="/"><xsl:call-template name="work"><xsl:with-param name="n" select="32"/></xsl:call-template></xsl:template><xsl:template name="work"><xsl:param name="n"/><xsl:if test="$n &gt; 0"><xsl:call-template name="work"><xsl:with-param name="n" select="$n - 1"/></xsl:call-template><xsl:call-template name="work"><xsl:with-param name="n" select="$n - 1"/></xsl:call-template></xsl:if></xsl:template>`)

	p, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{tr}, Limits: transform.Limits{Timeout: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.Apply(context.Background(), tr, reference.Octets([]byte(`<r/>`)), reference.ExtensionContext{})
	if !errors.Is(err, context.DeadlineExceeded) || out.Kind() != reference.Invalid {
		t.Fatalf("unbounded execution: %v, %v", out.Kind(), err)
	}
}
