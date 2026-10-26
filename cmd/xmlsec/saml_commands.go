package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

func runSAML(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("saml "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "XML, POST form or raw Redirect query input")
	out := fs.String("out", "-", "XML, encoded binding or diagnostic JSON output")
	configFile := fs.String("config", "", "trusted JSON metadata.EntityDescriptor/protocol request/response options")
	keyFile := fs.String("key", "", "private key for signing; public key for redirect verification")
	certificate := fs.String("certificate", "", "certificate for XML signatures")
	method := fs.String("method", "", "signature URI; selected from signing key if omitted")
	atValue := fs.String("at", "", "explicit metadata verification/build time, RFC3339")
	kindValue := fs.String(fieldKind, nameRequest, "binding message kind: request or response")
	relayValue := fs.String("relay-state", "", "optional RelayState (absent and empty are distinct)")
	extract := fs.String("extract", "", "write authenticated Redirect XML to this local file")
	pin := fs.String("document-sha256", "", "explicit SHA-256 pin for trusted unsigned metadata bytes")
	allowHTTP := fs.Bool("allow-http", false, "explicitly permit HTTP endpoints in metadata")
	lifetime := fs.Duration("max-lifetime", 0, "maximum metadata lifetime; 0 uses library default")

	var trusted repeatedFlag
	fs.Var(&trusted, "trust-key", "explicit trusted metadata/protocol signer key; repeatable")
	flags := registerPrivateKeyFlags(fs)

	specific := ioFlagNames

	switch cmd {
	case namePostEncode:
		specific += " kind relay-state"
	case "post-decode":
		specific += " kind"
	case nameRedirectSign:
		specific += " key certificate method kind relay-state" + privateKeyFlagNames
	case nameRedirectVerify:
		specific += " key trust-key extract"
	case nameMetadataBuild:
		specific = "out config at allow-http max-lifetime key certificate method" + privateKeyFlagNames
	case "metadata-verify":
		specific += " at allow-http max-lifetime trust-key document-sha256"
	case "request-build", "response-build":
		specific = "out config key certificate method" + privateKeyFlagNames
	case "request-verify", "response-verify", nameRedirectRequestVerify:
		specific += " config trust-key"
	}

	fs = commandFlags(fs, specific, true)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	var relay *string

	fs.Visit(func(f *flag.Flag) {
		if f.Name == "relay-state" {
			relay = relayValue
		}
	})

	options := samlCommand{command: cmd, input: *input, output: *out, config: *configFile, key: *keyFile, certificate: *certificate, method: *method, at: *atValue, kind: *kindValue, relay: relay, extract: *extract, pin: *pin, allowHTTP: *allowHTTP, lifetime: *lifetime, trusted: trusted, flags: flags}

	return options.run(ctx, stdin, stdout)
}

type samlCommand struct {
	command     string
	input       string
	output      string
	config      string
	key         string
	certificate string
	method      string
	at          string
	kind        string
	extract     string
	pin         string
	relay       *string
	allowHTTP   bool
	lifetime    time.Duration
	trusted     []string
	flags       *privateKeyFlags
}

func (c samlCommand) run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	switch c.command {
	case namePostEncode, "post-decode":
		return c.post(ctx, stdin, stdout)
	case nameRedirectSign, nameRedirectVerify:
		return c.redirect(ctx, stdin, stdout)
	case nameMetadataBuild, "metadata-verify":
		return c.metadata(ctx, stdin, stdout)
	case "request-build":
		var spec protocol.AuthnRequest
		if err := readJSONFile(ctx, c.config, &spec); err != nil {
			return err
		}

		var (
			doc *document.Document
			err error
		)
		if c.key == "" {
			doc, err = protocol.BuildAuthnRequest(ctx, spec)
		} else {
			signing, e := c.signing(ctx)
			if e != nil {
				return e
			}

			doc, err = protocol.SignAuthnRequest(ctx, spec, signing)
		}

		if err != nil {
			return err
		}

		return documentOutput(ctx, c.output, stdout, doc)
	case "response-build":
		var spec protocol.Response
		if err := readJSONFile(ctx, c.config, &spec); err != nil {
			return err
		}

		signing, err := c.signing(ctx)
		if err != nil {
			return err
		}

		doc, err := protocol.SignResponse(ctx, spec, signing)
		if err != nil {
			return err
		}

		return documentOutput(ctx, c.output, stdout, doc)
	case "request-verify", nameRedirectRequestVerify:
		return c.verifyRequest(ctx, stdin, stdout)
	case "response-verify":
		return c.verifyResponse(ctx, stdin, stdout)
	}

	return usageError("unknown SAML command")
}

func (c samlCommand) signing(ctx context.Context) (protocol.SigningKey, error) {
	key, err := loadPrivateConfigured(ctx, c.key, c.flags)
	if err != nil {
		return protocol.SigningKey{}, err
	}

	method := c.method
	if method == "" {
		method = signatureMethod(key.Public())
	}

	var der []byte

	if c.certificate != "" {
		cert, err := readCertificate(ctx, c.certificate)
		if err != nil {
			return protocol.SigningKey{}, err
		}

		der = cert.Raw
	}

	policy, err := execution(ctx).signaturePolicy(false)

	return protocol.SigningKey{Key: key, CertificateDER: der, SignatureMethod: method, Policy: policy}, err
}

func (c samlCommand) keys(ctx context.Context) ([]crypto.PublicKey, error) {
	paths := append([]string(nil), c.trusted...)
	if c.command == nameRedirectVerify && c.key != "" {
		paths = append(paths, c.key)
	}

	if len(paths) == 0 || len(paths) > 64 {
		return nil, usageError("verification requires 1..64 explicit trusted keys")
	}

	keys := make([]crypto.PublicKey, 0, len(paths))
	for _, path := range paths {
		key, err := loadPublicContext(ctx, path)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func (c samlCommand) post(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	kind := binding.Request
	if c.kind == nameResponse {
		kind = binding.Response
	} else if c.kind != nameRequest {
		return usageError("-kind must be request or response")
	}

	e := execution(ctx)
	limits := binding.POSTLimits{MaxFormBytes: min(e.xml.MaxBytes, 16<<20), MaxXMLBytes: min(e.xml.MaxBytes, 8<<20), XMLLimits: e.xml}

	if c.command == namePostEncode {
		doc, err := readDocument(ctx, c.input, stdin)
		if err != nil {
			return err
		}

		return produceOutput(ctx, c.output, stdout, func(dst io.Writer) error {
			_, err := binding.WritePOST(ctx, dst, doc, kind, c.relay, limits)
			return err
		})
	}

	raw, err := readInputContext(ctx, c.input, stdin, e.xml.MaxBytes)
	if err != nil {
		return err
	}

	message, err := binding.DecodePOST(ctx, raw, kind, limits)
	if err != nil {
		return err
	}

	xml, err := message.UnverifiedDocument().XML(ctx)
	if err != nil {
		return err
	}

	relay, present := message.RelayState()

	return jsonOutput(ctx, c.output, stdout, map[string]any{fieldStatus: statusUnverified, "xml": string(xml), fieldKind: message.Parameter(), "relay_state": relay, "relay_state_present": present})
}

func (c samlCommand) redirect(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	e := execution(ctx)

	policy, err := e.signaturePolicy(false)
	if err != nil {
		return err
	}

	opt := binding.Options{Policy: policy, MaxQueryBytes: min(e.xml.MaxBytes, 4<<20), MaxMessageBytes: min(e.xml.MaxBytes, 16<<20), XMLLimits: e.xml}

	if c.command == nameRedirectSign {
		kind := binding.Request
		if c.kind == nameResponse {
			kind = binding.Response
		} else if c.kind != nameRequest {
			return usageError("-kind must be request or response")
		}

		doc, err := readDocument(ctx, c.input, stdin)
		if err != nil {
			return err
		}

		signing, err := c.signing(ctx)
		if err != nil {
			return err
		}

		opt.SignatureMethod = signing.SignatureMethod

		raw, err := binding.SignRedirect(ctx, doc, kind, c.relay, signing.Key, opt)
		if err != nil {
			return err
		}

		return writeOutputContext(ctx, c.output, stdout, []byte(raw))
	}

	raw, err := readInputContext(ctx, c.input, stdin, e.xml.MaxBytes)
	if err != nil {
		return err
	}

	keys, err := c.keys(ctx)
	if err != nil {
		return err
	}

	result, verifyErr := verifyRedirectKeys(ctx, string(raw), keys, opt)

	var detail any

	if verifyErr == nil {
		relay, present := result.RelayState()
		detail = map[string]any{fieldKind: result.Kind(), "signature_method": result.SignatureMethod(), "relay_state": relay, "relay_state_present": present, "protocol_checked": false}

		if c.extract != "" {
			if err := separateOutput(c.extract, c.output, "extract"); err != nil {
				return err
			}

			if err := documentOutput(ctx, c.extract, stdout, result.Document()); err != nil {
				return err
			}
		}
	}

	return errors.Join(verifyErr, jsonOutput(ctx, c.output, stdout, resultReport("saml redirect-verify", "explicit-public-key-pins", detail, verifyErr)))
}

func (c samlCommand) metadata(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	at, err := parseTime(c.at)
	if err != nil {
		return err
	}

	policy, err := execution(ctx).signaturePolicy(false)
	if err != nil {
		return err
	}

	opt := metadata.Options{MaxBytes: min(execution(ctx).xml.MaxBytes, 16<<20), Policy: policy, AllowHTTP: c.allowHTTP, MaxLifetime: c.lifetime}
	if c.command == nameMetadataBuild {
		return c.buildMetadata(ctx, at, opt, stdout)
	}

	raw, err := readInputContext(ctx, c.input, stdin, execution(ctx).xml.MaxBytes)
	if err != nil {
		return err
	}

	var (
		result    *metadata.Snapshot
		verifyErr error
	)

	trust := "explicit-metadata-signer-pins"

	if c.pin != "" {
		if len(c.trusted) != 0 {
			return usageError("choose -document-sha256 or -trust-key")
		}

		if fingerprint(raw) != strings.ToLower(c.pin) {
			return errors.New("metadata document SHA-256 pin mismatch")
		}

		trust = "explicit-document-sha256-pin"
		result, verifyErr = metadata.ParseTrusted(ctx, raw, at, opt)
	} else {
		keys, err := c.keys(ctx)
		if err != nil {
			return err
		}

		verifier, err := metadata.NewVerifier(metadata.Config{TrustedKeys: keys, Options: opt})
		if err != nil {
			return err
		}

		result, verifyErr = verifier.Verify(ctx, raw, at)
	}

	var detail any
	if verifyErr == nil {
		detail = metadataDescription(result, at)
	}

	return errors.Join(verifyErr, jsonOutput(ctx, c.output, stdout, resultReport("saml metadata-verify", trust, detail, verifyErr)))
}

func (c samlCommand) buildMetadata(ctx context.Context, at time.Time, opt metadata.Options, stdout io.Writer) error {
	var cfg metadata.EntityDescriptor
	if err := readJSONFile(ctx, c.config, &cfg); err != nil {
		return err
	}

	doc, err := metadata.Build(ctx, cfg, at, opt)
	if err != nil {
		return err
	}

	if c.key != "" {
		signing, err := c.signing(ctx)
		if err != nil {
			return err
		}

		doc, err = metadata.Sign(ctx, doc, signing.Key, signing.CertificateDER, signing.SignatureMethod, at, opt)
		if err != nil {
			return err
		}
	}

	return documentOutput(ctx, c.output, stdout, doc)
}

func (c samlCommand) verifyRequest(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	var opt protocol.RequestOptions
	if err := readJSONFile(ctx, c.config, &opt); err != nil {
		return err
	}

	if hasProtocolSignaturePolicy(opt.Policy) {
		return usageError("signature policy in protocol JSON must be omitted; use CLI policy flags")
	}

	policy, err := execution(ctx).signaturePolicy(false)
	if err != nil {
		return err
	}

	opt.Policy = policy

	keys, err := c.keys(ctx)
	if err != nil {
		return err
	}

	var (
		result    *protocol.VerifiedRequest
		verifyErr error
	)

	if c.command == nameRedirectRequestVerify {
		raw, err := readInputContext(ctx, c.input, stdin, execution(ctx).xml.MaxBytes)
		if err != nil {
			return err
		}

		result, verifyErr = protocol.VerifyRedirectRequest(ctx, string(raw), keys, opt, binding.Options{Policy: policy, MaxQueryBytes: min(execution(ctx).xml.MaxBytes, 4<<20), MaxMessageBytes: min(execution(ctx).xml.MaxBytes, 16<<20), XMLLimits: execution(ctx).xml})
	} else {
		doc, err := readDocument(ctx, c.input, stdin)
		if err != nil {
			return err
		}

		result, verifyErr = protocol.VerifyAuthnRequest(ctx, doc, keys, opt)
	}

	var detail any
	if verifyErr == nil {
		detail = map[string]any{
			"id":             result.ID(),
			fieldIssuer:      result.Issuer(),
			"destination":    result.Destination(),
			"acs":            result.ACS(),
			"issue_instant":  result.IssueInstant(),
			"replay_checked": false,
		}
	}

	return errors.Join(verifyErr, jsonOutput(ctx, c.output, stdout, resultReport("saml "+c.command, "explicit-protocol-key-pins-and-expectations", detail, verifyErr)))
}

func (c samlCommand) verifyResponse(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	var opt protocol.ResponseOptions
	if err := readJSONFile(ctx, c.config, &opt); err != nil {
		return err
	}

	if hasProtocolSignaturePolicy(opt.Policy) {
		return usageError("signature policy in protocol JSON must be omitted; use CLI policy flags")
	}

	policy, err := execution(ctx).signaturePolicy(false)
	if err != nil {
		return err
	}

	opt.Policy = policy

	keys, err := c.keys(ctx)
	if err != nil {
		return err
	}

	doc, err := readDocument(ctx, c.input, stdin)
	if err != nil {
		return err
	}

	result, verifyErr := protocol.VerifyResponse(ctx, doc, keys, opt)

	var detail any
	if verifyErr == nil {
		detail = map[string]any{
			"response_id":            result.ResponseID(),
			"assertion_id":           result.AssertionID(),
			fieldIssuer:              result.Issuer(),
			"audience":               result.Audience(),
			"recipient":              result.Recipient(),
			"in_response_to":         result.InResponseTo(),
			"name_id":                result.NameID(),
			"name_id_format":         result.NameIDFormat(),
			"attributes":             result.Attributes(),
			fieldExpiresAt:           result.NotOnOrAfter(),
			"authn_context":          result.AuthnContext(),
			"response_authenticated": result.ResponseAuthenticated(),
			"replay_checked":         false,
			"session_created":        false,
		}
	}

	return errors.Join(verifyErr, jsonOutput(ctx, c.output, stdout, resultReport("saml response-verify", "explicit-protocol-key-pins-and-expectations", detail, verifyErr)))
}

func signatureMethod(key crypto.PublicKey) string {
	switch key.(type) {
	case *rsa.PublicKey:
		return xmldsig.RSASHA256
	case *ecdsa.PublicKey:
		return xmldsig.ECDSASHA256
	case ed25519.PublicKey:
		return xmldsig.Ed25519
	}

	return ""
}

func verifyRedirectKeys(ctx context.Context, query string, keys []crypto.PublicKey, opt binding.Options) (*binding.RedirectResult, error) {
	var (
		result *binding.RedirectResult
		err    error
	)
	for _, key := range keys {
		result, err = binding.VerifyRedirect(ctx, query, key, opt)
		if err == nil {
			return result, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, err
}

func metadataDescription(snapshot *metadata.Snapshot, at time.Time) any {
	entities := make([]any, 0, len(snapshot.Entities()))

	for _, entity := range snapshot.Entities() {
		var roles []any

		for _, kind := range []metadata.RoleType{metadata.ServiceProvider, metadata.IdentityProvider} {
			role, err := entity.Role(kind, at)
			if err != nil {
				continue
			}

			endpoints := map[string]any{}

			for _, name := range []string{
				metadata.AssertionConsumerService,
				metadata.SingleSignOnService,
				metadata.SingleLogoutService,
				metadata.ArtifactResolutionService,
				metadata.ManageNameIDService,
			} {
				if list := role.Endpoints(name); len(list) > 0 {
					endpoints[name] = list
				}
			}

			roles = append(roles, map[string]any{
				fieldType:         role.Type(),
				fieldExpiresAt:    role.ExpiresAt(),
				"endpoints":       endpoints,
				"signing_keys":    len(role.SigningKeys()),
				"name_id_formats": role.NameIDFormats(),
			})
		}

		entities = append(entities, map[string]any{"id": entity.ID(), fieldExpiresAt: entity.ExpiresAt(), "roles": roles})
	}

	return map[string]any{"signature_authenticated": snapshot.AuthenticatedSignature(), fieldExpiresAt: snapshot.ExpiresAt(), "entities": entities}
}

func hasProtocolSignaturePolicy(p xmldsig.Policy) bool {
	return p.AllowedSignatureMethods != nil || p.AllowedDigestMethods != nil ||
		p.MinRSABits != 0 || p.MaxRSABits != 0 || p.MaxReferences != 0 || p.MaxCanonicalBytes != 0 ||
		p.MinPSSSaltBytes != 0 || p.MaxPSSSaltBytes != 0 || p.MinHMACKeyBytes != 0 || p.MaxHMACKeyBytes != 0 ||
		p.MinHMACOutputBits != 0 || p.AllowHMACTruncation
}
