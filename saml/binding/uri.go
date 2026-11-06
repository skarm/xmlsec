package binding

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// Exact query-field name of the assertion URI binding. It is distinct from the XML ID attribute even though both use the spelling ID.
const (
	assertionIDParameter = "ID"
)

// The URI transport accepts only an assertion-namespace root; this lexical token never authenticates the returned assertion.
const (
	xmlNameAssertion = "Assertion"
)

// AssertionMediaType is the SAML assertion MIME type used by the URI binding.
const AssertionMediaType = "application/samlassertion+xml"

// AssertionURL constructs the exact ID query required by Bindings 3.7.5.1.
// The configured endpoint must have no query or fragment; wildcard IDs are invalid.
func AssertionURL(endpoint, id string, allowHTTP bool) (string, error) {
	if !profile.Endpoint(endpoint, allowHTTP) || !profile.ID(id) {
		return "", ErrBinding
	}

	u, err := url.Parse(endpoint)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", ErrBinding
	}

	u.RawQuery = url.Values{assertionIDParameter: {id}}.Encode()

	return u.String(), nil
}

// ReadAssertionID validates the URI binding's GET and single ID parameter.
// HTTP peer authentication and authorization remain the handler's responsibility.
func ReadAssertionID(r *http.Request) (string, error) {
	if r == nil || r.URL == nil || r.Method != http.MethodGet {
		return "", ErrBinding
	}

	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 1 || len(q[assertionIDParameter]) != 1 || !profile.ID(q.Get(assertionIDParameter)) {
		return "", ErrBinding
	}

	return q.Get(assertionIDParameter), nil
}

// WriteAssertion writes an application-authorized assertion with caching disabled.
// It does not authorize disclosure or authenticate the assertion's contents.
func WriteAssertion(ctx context.Context, w http.ResponseWriter, d *document.Document) error {
	const (
		maximumAssertionXMLBytes = 2 << 20
	)

	if ctx == nil || nilcheck.IsNil(w) || d == nil || d.Root().Name() != xmlutil.Name(xmlutil.Assertion, xmlNameAssertion) {
		return ErrBinding
	}

	raw, err := d.XML(ctx)
	if err != nil {
		return err
	}

	if len(raw) > maximumAssertionXMLBytes {
		return ErrBinding
	}

	w.Header().Set(lexicon.HeaderContentType, AssertionMediaType)
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	w.Header().Set(headerPragma, cachePragma)
	w.WriteHeader(http.StatusOK)

	n, err := w.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}

	return err
}

// URIClient resolves a configured authority endpoint. It never follows redirects
// or obtains authority URLs from received XML. Authentication can be supplied
// through the caller-owned HTTP client's transport, including preemptive Basic.
// Returned XML is unverified and must pass VerifyAuthorityAssertion.
type URIClient struct {
	// Client supplies the HTTP transport and timeout. Nil selects a 30-second
	// timeout. The client is copied and redirects are disabled.
	Client *http.Client
	// AllowHTTP permits explicitly configured plain HTTP endpoints. The default
	// requires HTTPS.
	AllowHTTP bool
	// MaxBytes bounds the assertion response in bytes. Zero selects 2 MiB; the
	// maximum is 16 MiB.
	MaxBytes int
}

// Resolve retrieves precisely the requested assertion or returns an HTTP error.
// Read or close failures return no document and preserve earlier error causes.
func (c URIClient) Resolve(ctx context.Context, endpoint, id string) (message *document.Document, err error) {
	const (
		defaultAssertionResponseBytes = 2 << 20
		headerAccept                  = "Accept"
		maximumAssertionResponseBytes = 16 << 20
	)

	u, err := AssertionURL(endpoint, id, c.AllowHTTP)
	if err != nil || ctx == nil {
		return nil, ErrBinding
	}

	maximum := c.MaxBytes
	if maximum == 0 {
		maximum = defaultAssertionResponseBytes
	}

	if maximum < 1 || maximum > maximumAssertionResponseBytes {
		return nil, ErrBinding
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	r.Header.Set(headerAccept, AssertionMediaType)

	response, err := soapHTTPClient(c.Client).Do(r)
	if err != nil {
		return nil, err
	}

	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			message = nil
			err = errors.Join(err, closeErr)
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: assertion HTTP status %d", ErrBinding, response.StatusCode)
	}

	media, _, err := mime.ParseMediaType(response.Header.Get(lexicon.HeaderContentType))
	if err != nil || media != AssertionMediaType && media != lexicon.MediaTypeXML && media != soapMediaType {
		return nil, ErrBinding
	}

	raw, err := io.ReadAll(&streamio.Reader{Context: ctx, Source: response.Body, Limit: int64(maximum), LimitError: ErrBinding})
	if err != nil {
		return nil, err
	}

	d, err := document.Parse(ctx, raw, xmlutil.XMLLimits(document.Limits{}, maximum))
	if err != nil {
		return nil, err
	}

	if d.Root().Name() != xmlutil.Name(xmlutil.Assertion, xmlNameAssertion) || xmlutil.Attr(d.Root(), lexicon.SAMLAttrID) != id {
		return nil, ErrBinding
	}

	return d, nil
}

const soapMediaType = lexicon.MediaTypeSOAP
