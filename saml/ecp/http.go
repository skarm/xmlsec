package ecp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/saml/binding"
)

// Canonical HTTP field spellings shared by the PAOS challenge and SP delivery writers; cache directives keep the ECP protocol responses out of intermediary storage.
const (
	headerCacheControl = "Cache-Control"
	headerPragma       = "Pragma"
)

// The ECP HTTP writer declares its serialized SOAP bytes as UTF-8; this is an output media parameter, not a parser permission.
const (
	charsetUTF8Parameter = "; charset=" + lexicon.EncodingUTF8
)

// Transport cache directive for sensitive SAML responses; shared writers must retain the same no-store/HTTP compatibility behavior.
const (
	cacheControlNoStore = "no-cache, no-store"
	cachePragma         = "no-cache"
)

// WriteChallenge returns the negotiated ECP challenge as HTTP 200 PAOS content.
// Persist the SP request state before calling this method.
func WriteChallenge(ctx context.Context, w http.ResponseWriter, r *http.Request, envelope *document.Document) error {
	if ctx == nil || nilcheck.IsNil(w) || r == nil || envelope == nil || !Negotiated(r.Header) {
		return ErrECP
	}

	raw, err := envelope.XML(ctx)
	if err != nil {
		return err
	}

	if _, err := binding.DecodeSOAP(ctx, raw, binding.SOAPOptions{Understood: knownHeaders()}); err != nil {
		return err
	}

	w.Header().Set(lexicon.HeaderContentType, MediaType+charsetUTF8Parameter)
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	w.Header().Set(headerPragma, cachePragma)
	w.WriteHeader(http.StatusOK)

	n, err := w.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}

	return err
}

// ReadResponse reads the bounded PAOS POST delivered to the SP. It returns an
// unverified SAML response; SP.ConsumePAOS supplies the full Web SSO processing.
func ReadResponse(ctx context.Context, r *http.Request, expectedMessageID string, o binding.SOAPOptions) (*document.Document, *string, error) {
	const (
		defaultSOAPBytes = 2 << 20
		maximumSOAPBytes = 16 << 20
	)

	if ctx == nil || r == nil || r.Body == nil || r.Method != http.MethodPost {
		return nil, nil, ErrECP
	}

	media, _, err := mime.ParseMediaType(r.Header.Get(lexicon.HeaderContentType))
	if err != nil || media != MediaType {
		return nil, nil, ErrECP
	}

	maximum := o.MaxBytes
	if maximum == 0 {
		maximum = defaultSOAPBytes
	}

	if maximum < 1 || maximum > maximumSOAPBytes {
		return nil, nil, ErrECP
	}

	raw, err := io.ReadAll(&streamio.Reader{Context: ctx, Source: r.Body, Limit: int64(maximum), LimitError: ErrECP})
	if err != nil {
		return nil, nil, err
	}

	return DecodeResponse(ctx, raw, expectedMessageID, o)
}

// Deliver completes the ECP hop to the SP-controlled ACS. On a destination
// mismatch it sends only the generated SOAP fault to that original ACS and
// returns the routing error. Redirects are never followed. The caller owns and
// must close any returned response body, even when a routing error is returned.
func (x *Exchange) Deliver(ctx context.Context, idpResponse []byte, client *http.Client, o binding.SOAPOptions) (*http.Response, error) {
	const (
		defaultHTTPTimeout = 30 * time.Second
		headerSOAPAction   = "SoapAction"
		samlSOAPAction     = "\"http://www.oasis-open.org/committees/security\""
	)

	envelope, routingErr := x.Finish(ctx, idpResponse, o)
	if envelope == nil {
		return nil, routingErr
	}

	raw, err := envelope.XML(ctx)
	if err != nil {
		return nil, errors.Join(routingErr, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.acs, bytes.NewReader(raw))
	if err != nil {
		return nil, errors.Join(routingErr, err)
	}

	req.Header.Set(lexicon.HeaderContentType, MediaType+charsetUTF8Parameter)
	req.Header.Set(headerSOAPAction, samlSOAPAction)
	req.Header.Set(headerCacheControl, cacheControlNoStore)
	req.Header.Set(headerPragma, cachePragma)

	c := http.Client{Timeout: defaultHTTPTimeout}
	if client != nil {
		c = *client
	}

	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	response, err := c.Do(req)
	if err != nil {
		return nil, errors.Join(routingErr, err)
	}

	return response, routingErr
}
