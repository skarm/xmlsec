package consumer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"testing/iotest"
	"unicode/utf16"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/resource"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestSharedResourceAdapters(t *testing.T) {
	r, err := resource.NewFSResolver(resource.FSConfig{FS: fstest.MapFS{"value.txt": &fstest.MapFile{Data: []byte("42")}}, BaseURI: "embed:/resources/"})
	if err != nil {
		t.Fatal(err)
	}
	var _ transform.Resolver = r
	var _ xmlenc.CipherResolver = r
	e := newEngine(t, transform.Config{Resolver: r})
	q, err := e.CompileXPath(t.Context(), `unparsed-text('embed:/resources/value.txt')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := q.Evaluate(t.Context(), nil, transform.XPathContext{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.Text()
	if err != nil || s != "42" {
		t.Fatal(s, err)
	}
	for _, uri := range []string{"embed:/resources/../secret", "embed:/resources/%2e%2e/secret", "embed:/other/value.txt", "embed:/resources/a%5cb"} {
		if f, err := r.Resolve(t.Context(), uri); !errors.Is(err, resource.ErrPolicy) {
			if f != nil {
				_ = f.Close()
			}
			t.Fatal(uri, err)
		}
	}
}

func TestTypedNilResourceAdapters(t *testing.T) {
	var absentFS fstest.MapFS
	if resolver, err := resource.NewFSResolver(resource.FSConfig{FS: absentFS, BaseURI: "embed:/resources/"}); resolver != nil || !errors.Is(err, resource.ErrInput) {
		t.Fatalf("nil filesystem: %v, %v", resolver, err)
	}
	if _, err := resource.NewFSResolver(resource.FSConfig{FS: fstest.MapFS{}, BaseURI: "embed:/resources/"}); err != nil {
		t.Fatalf("empty filesystem is not nil: %v", err)
	}

	var absentResolver resolverFunction
	engine := newEngine(t, transform.Config{Resolver: absentResolver})
	query, err := engine.CompileXPath(t.Context(), `doc('urn:missing')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := query.Evaluate(t.Context(), nil, transform.XPathContext{}); err == nil || value.Len() != 0 {
		t.Fatalf("nil resolver: %d items, %v", value.Len(), err)
	}

	var absentReader *strings.Reader
	if doc, err := engine.ParseReader(t.Context(), absentReader); doc != nil || !errors.Is(err, transform.ErrInput) {
		t.Fatalf("nil reader: %v, %v", doc, err)
	}
}

func TestHTTPRedirectPolicy(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "allowed.test" {
			t.Error("disallowed origin reached")
		}
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("42")), Request: req}
		if req.URL.Path == "/redirect" {
			response.StatusCode = http.StatusFound
			response.Header.Set("Location", "https://foreign.test/secret")
		}
		return response, nil
	})}
	r, err := resource.NewHTTPResolver(resource.HTTPConfig{Client: client, AllowedOrigins: []string{"https://allowed.test"}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.Resolve(t.Context(), "https://allowed.test/value")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(data) != "42" {
		t.Fatal(string(data), err)
	}
	if f, err := r.Resolve(t.Context(), "https://allowed.test/redirect"); !errors.Is(err, resource.ErrPolicy) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatal(err)
	}
}

func TestXMLResourcesStopOnParseFailureAndClose(t *testing.T) {
	for _, operation := range []string{"include", "doc", "document", "source-document", "package"} {
		t.Run(operation, func(t *testing.T) {
			closed := 0
			reader := &gatedInput{first: strings.NewReader(`<broken></different>`), rest: strings.NewReader(strings.Repeat("never read", 10000)), ready: func() bool { return false }}
			resolver := transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return &trackedInput{Reader: reader, close: func() error { closed++; return nil }}, nil
			})
			config := transform.Config{Resolver: resolver}
			if operation == "package" {
				config.PackageResolver = transform.PackageResolverFunc(func(context.Context, string, string) (transform.PackageResource, error) {
					return transform.PackageResource{Reader: &trackedInput{Reader: reader, close: func() error { closed++; return nil }}}, nil
				})
			}
			engine := newEngine(t, config)
			source := `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`
			switch operation {
			case "include":
				source += `<xsl:include href="urn:invalid"/>`
			case "package":
				source += `<xsl:use-package name="urn:invalid"/>`
			default:
				body := `<xsl:sequence select="` + operation + `('urn:invalid')"/>`
				if operation == "source-document" {
					body = `<xsl:source-document href="urn:invalid"><xsl:sequence select="."/></xsl:source-document>`
				}
				source += `<xsl:template name="start">` + body + `</xsl:template>`
			}
			source += `</xsl:stylesheet>`
			sheet, err := engine.CompileXSLT(t.Context(), []byte(source), transform.XSLTOptions{})
			if err == nil {
				_, err = sheet.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
			}
			if err == nil || reader.early || closed != 1 {
				t.Fatal(err, reader.early, closed)
			}
		})
	}
}

func TestXMLResourceCloseFailuresKeepTheirCause(t *testing.T) {
	failure := errors.New("close failed")
	const parameters = `<serialization-parameters xmlns="http://www.w3.org/2010/xslt-xquery-serialization"/>`
	const nested = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0"><xsl:template name="start">inner</xsl:template></xsl:stylesheet>`
	cases := []struct{ name, body, resource string }{
		{"static-parameters", `<xsl:output parameter-document="urn:params"/>`, parameters},
		{"runtime-parameters", `<xsl:template name="start"><xsl:result-document href="extra" parameter-document="urn:params">extra</xsl:result-document></xsl:template>`, parameters},
		{"nested-transform", `<xsl:template name="start"><xsl:sequence select="transform(map{'stylesheet-location':'urn:sheet','initial-template':QName('','start')})?output"/></xsl:template>`, nested},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return &trackedInput{Reader: strings.NewReader(tc.resource), close: func() error { return failure }}, nil
			})
			engine := newEngine(t, transform.Config{Resolver: resolver})
			sheet, err := engine.CompileXSLT(t.Context(), []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="3.0">`+tc.body+`</xsl:stylesheet>`), transform.XSLTOptions{})
			if err == nil {
				_, err = sheet.CallTemplate(t.Context(), nil, document.Name{Local: "start"}, transform.XSLTContext{})
			}
			if !errors.Is(err, failure) {
				t.Fatal(err)
			}
		})
	}
}

func TestTextResourcesWorkingStorage(t *testing.T) {
	for _, size := range []int{16 << 10, 1 << 20} {
		text := strings.Repeat("x", size)
		for _, encoding := range []string{"utf-8", "utf-16be"} {
			t.Run(fmt.Sprintf("%d/%s", size, encoding), func(t *testing.T) {
				source := []byte(text)
				if encoding == "utf-16be" {
					source = make([]byte, 2*size)
					for i := range size {
						source[2*i+1] = 'x'
					}
				}
				closed := 0
				engine := newEngine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
					return &trackedInput{Reader: bytes.NewReader(source), close: func() error { closed++; return nil }}, nil
				})})
				query, err := engine.CompileXPath(t.Context(), `unparsed-text('urn:text', '`+encoding+`')`, transform.XPathOptions{})
				if err != nil {
					t.Fatal(err)
				}
				allocated := allocatedDuring(t, func() error {
					result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
					if err != nil {
						return err
					}
					actual, err := result.Text()
					if err != nil || actual != text {
						return fmt.Errorf("text changed: %v", err)
					}
					return nil
				})
				t.Logf("%d decoded bytes: %d allocated", size, allocated)
				if allocated > uint64(3*size+128<<10) || closed != 3 {
					t.Fatalf("allocation=%d, closes=%d", allocated, closed)
				}
			})
		}
	}
}

func TestTextResourcesRejectBeforeReadingRemainder(t *testing.T) {
	for _, lines := range []bool{false, true} {
		t.Run(fmt.Sprint(lines), func(t *testing.T) {
			prefix := strings.Repeat("x", 4096)
			limits := transform.Limits{MaxOutputBytes: 64}
			expression := `unparsed-text('urn:text')`
			if lines {
				prefix = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n"
				limits = transform.Limits{MaxNodes: 8}
				expression = `unparsed-text-lines('urn:text')`
			}
			reader := &gatedInput{first: strings.NewReader(prefix), rest: strings.NewReader(strings.Repeat("not consumed", 100000)), ready: func() bool { return false }}
			closed := 0
			engine := newEngine(t, transform.Config{Limits: limits, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				return &trackedInput{Reader: reader, close: func() error { closed++; return nil }}, nil
			})})
			query, err := engine.CompileXPath(t.Context(), expression, transform.XPathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			allocated := allocatedDuring(t, func() error {
				reader.first.Reset(prefix)
				_, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
				if !errors.Is(err, transform.ErrLimit) {
					return fmt.Errorf("text limit: %w", err)
				}
				return nil
			})
			if reader.early || closed != 3 || allocated > 128<<10 {
				t.Fatal(reader.early, closed, allocated)
			}
		})
	}
}

func TestTextResourceChunksAndCompletion(t *testing.T) {
	text := strings.Repeat("x", (32<<10)-1) + "🙂\r\nя\r\nend\n"
	units := utf16.Encode([]rune(text))
	encoded := []byte{0xfe, 0xff}
	for _, unit := range units {
		encoded = append(encoded, byte(unit>>8), byte(unit))
	}
	for _, source := range [][]byte{[]byte(text), encoded} {
		engine := newEngine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(iotest.OneByteReader(bytes.NewReader(source))), nil
		})})
		query, err := engine.CompileXPath(t.Context(), `unparsed-text-lines('urn:text')`, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil || result.Len() != 3 {
			t.Fatal(result.Len(), err)
		}
		for i, want := range []string{strings.Repeat("x", (32<<10)-1) + "🙂", "я", "end"} {
			value, _ := result.At(i)
			got, err := value.Text()
			if err != nil || got != want {
				t.Fatalf("line %d changed: %v", i, err)
			}
		}
	}

	failure := errors.New("text resource close failed")
	for _, expression := range []string{`unparsed-text('urn:text')`, `unparsed-text-lines('urn:text')`, `json-doc('urn:text')`} {
		closed := 0
		engine := newEngine(t, transform.Config{Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return &trackedInput{Reader: strings.NewReader(`"ok"`), close: func() error { closed++; return failure }}, nil
		})})
		query, err := engine.CompileXPath(t.Context(), expression, transform.XPathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := query.Evaluate(t.Context(), nil, transform.XPathContext{}); !errors.Is(err, failure) || closed != 1 {
			t.Fatal(expression, err, closed)
		}
	}
}

func TestResourceAdaptersReadIncrementally(t *testing.T) {
	const size = 8 << 20
	fileResolver, err := resource.NewFSResolver(resource.FSConfig{FS: fstest.MapFS{"payload": &fstest.MapFile{Data: bytes.Repeat([]byte{'x'}, size)}}, BaseURI: "embed:/"})
	if err != nil {
		t.Fatal(err)
	}
	httpResolver, err := resource.NewHTTPResolver(resource.HTTPConfig{AllowedOrigins: []string{"https://resource.test"}, Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(&repeatedInput{remaining: size, block: []byte("x")}), Request: req}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		resolver resource.Resolver
		uri      string
	}{{fileResolver, "embed:/payload"}, {httpResolver, "https://resource.test/payload"}} {
		allocated := allocatedDuring(t, func() error {
			reader, err := tc.resolver.Resolve(t.Context(), tc.uri)
			if err != nil {
				return err
			}
			hash := sha256.New()
			var buffer [32 << 10]byte
			count, err := io.CopyBuffer(hash, reader, buffer[:])
			err = errors.Join(err, reader.Close())
			if count != size {
				return fmt.Errorf("read %d bytes: %w", count, err)
			}
			return err
		})
		if allocated > 128<<10 {
			t.Fatalf("resolver buffered %d bytes", allocated)
		}
	}
}

func TestTextAvailabilityDoesNotRetainResource(t *testing.T) {
	const size = 1 << 20
	closed := 0
	engine := newEngine(t, transform.Config{Limits: transform.Limits{MaxOutputBytes: 64}, Resolver: transform.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return &trackedInput{Reader: &repeatedInput{remaining: size, block: []byte("x")}, close: func() error { closed++; return nil }}, nil
	})})
	query, err := engine.CompileXPath(t.Context(), `unparsed-text-available('urn:text')`, transform.XPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	allocated := allocatedDuring(t, func() error {
		result, err := query.Evaluate(t.Context(), nil, transform.XPathContext{})
		if err != nil {
			return err
		}
		value, err := result.Single()
		if err != nil {
			return err
		}
		available, err := value.Boolean()
		if err != nil || !available {
			return fmt.Errorf("resource unavailable: %v", err)
		}
		return nil
	})
	if allocated > 128<<10 || closed != 3 {
		t.Fatal(allocated, closed)
	}
}

type resolverFunction func(context.Context, string) (io.ReadCloser, error)

func (f resolverFunction) Resolve(ctx context.Context, uri string) (io.ReadCloser, error) {
	return f(ctx, uri)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
