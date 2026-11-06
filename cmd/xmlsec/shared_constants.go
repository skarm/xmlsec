package main

// Shared CLI policy: cliMaxBytes is an upper bound on operator-selected byte limits. Resource defaults apply to core/detached URI reads; counts and crypto bounds remain separate controls.
// Command/format tokens and report keys form the CLI vocabulary; they are kept
// separate from caller identifiers and XML element/attribute vocabularies.
const (
	// Version tag shared by CLI error/result envelopes.
	cliReportSchemaVersion = 1
	// Selectable signature-policy label, also a key in the algorithms report.
	cliPolicyModern = "modern"
	// Selectable parameterized RSA-PSS policy label, independent of command boolean flags.
	cliPolicyPSS = "pss"
	// The omitted index requests unique selection rather than an arbitrary first matching element.
	cliUnspecifiedSelectionIndex = -1
	cliMaxBytes                  = 64 << 20
	cliDefaultResourceBytes      = 8 << 20
	cliDefaultTotalResourceBytes = 32 << 20
	// Shared verification-policy and key-generation floor; each command keeps its own upper bound.
	cliMinRSABits = 2048
	// Ceiling for admitted HMAC policy and for the explicitly loaded shared-secret file.
	cliMaxHMACKeyBytes = 1 << 20
	// Maximum operator-supplied nonce bytes for both OCSP and timestamp commands.
	cliMaxNonceBytes = 128
	// Default unqualified application ID attribute for generic document commands; XML security vocabulary attributes keep their own names.
	cliDefaultIDAttribute = "ID"
	// Default hash choice; fixed algorithm parser labels remain independent of this selection.
	cliDefaultHashName = cliHashSHA256
	// Fixed SHA-256 option spelling, also used to select the default hash.
	cliHashSHA256 = "sha256"
)

const (
	nameC14N           = "c14n"
	namePKCS8          = "pkcs8"
	nameSignDetached   = "sign-detached"
	nameSignTemplate   = "sign-template"
	nameVerify         = "verify"
	nameVerifyCore     = "verify-core"
	nameVerifyDetached = "verify-detached"
)

const (
	nameSign = "sign"
)

const (
	nameDecrypt      = "decrypt"
	nameEncrypt      = "encrypt"
	nameRSA          = "rsa"
	namePlain        = "plain"
	namePKCS12       = "pkcs12"
	nameHMAC         = "hmac"
	nameInspect      = "inspect"
	statusValid      = "valid"
	statusUnverified = "unverified"
	nameDefault      = "default"
	nameHelp         = "help"

	scopeBytes      = "bytes"
	transportDirect = "direct"
	nameRequest     = "request"
	nameResponse    = "response"
	nameToken       = "token"
	nameXPath       = "xpath"
	nameXSLT        = "xslt"
	version10       = "1.0"
	version20       = "2.0"
	version30       = "3.0"
	version31       = "3.1"
	fieldStatus     = "status"
	fieldType       = "type"
	fieldKind       = "kind"
	fieldIssuer     = "issuer"
	fieldExpiresAt  = "expires_at"
)

const (
	ioFlagNames          = "in out"
	scopeElement         = "element"
	namePublic           = "public"
	namePostEncode       = "post-encode"
	nameRedirectSign     = "redirect-sign"
	nameRedirectVerify   = "redirect-verify"
	nameMetadataBuild    = "metadata-build"
	nameIssue            = "issue"
	fieldValue           = "value"
	nameTimestampRequest = "timestamp-request"
)

const nameVerifyKeyInfo = "verify-keyinfo"

const (
	jsonErrorsFlag = "--json-errors"

	nameRedirectRequestVerify = "redirect-request-verify"
)

const (
	nameEncryption = "encryption"
)
