# Standards

These primary sources define supported profiles. Listing a standard does not claim
complete conformance. [conformance.json](conformance.json) pins editions and errata
sources, selected correction identifiers and their review date. Every declared
profile has a document/role/mode matrix and a named clause/contract inventory.
Implementation and local/independent evidence gaps remain explicit.
[Normative traceability](conformance.md) explains its states and acceptance rules;
[compatibility](compatibility.md) records exclusions and oracle differences.

## XML, canonicalization and signatures

- [XML 1.0](https://www.w3.org/TR/xml/) and [Namespaces](https://www.w3.org/TR/xml-names/)
- [XML Schema datatypes](https://www.w3.org/TR/xmlschema-2/): lexical rules for supported time values
- [Canonical XML 1.0](https://www.w3.org/TR/2001/REC-xml-c14n-20010315),
  [1.1](https://www.w3.org/TR/xml-c14n11/) and [1.1 errata](https://www.w3.org/2008/05/xml-c14n11-errata)
- [Exclusive C14N](https://www.w3.org/TR/xml-exc-c14n/) and [errata](https://www.w3.org/2002/07/xml-exc-c14n-errata)
- [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) and [best practices](https://www.w3.org/TR/xmldsig-bestpractices/)
- [XPath 2.0](https://www.w3.org/TR/xpath20/),
  [XPath 3.0](https://www.w3.org/TR/xpath-30/) and
  [XPath 3.1](https://www.w3.org/TR/xpath-31/);
  [XSLT 2.0](https://www.w3.org/TR/xslt20/) and
  [XSLT 3.0](https://www.w3.org/TR/xslt-30/)
- [XPath functions and operators 3.1](https://www.w3.org/TR/xpath-functions-31/)
  and [serialization 3.1](https://www.w3.org/TR/xslt-xquery-serialization-31/)
- [XPath 1.0](https://www.w3.org/TR/1999/REC-xpath-19991116/),
  [Filter2](https://www.w3.org/TR/xmldsig-filter2/) and [XSLT 1.0](https://www.w3.org/TR/xslt-10/)
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html),
  [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045.html) and [RFC 9231](https://www.rfc-editor.org/rfc/rfc9231.html)
- [XML Base, Second Edition](https://www.w3.org/TR/2009/REC-xmlbase-20090128/):
  explicit URI resolution context; its LEIRI and complete processor obligations
  exceed the selected XMLDSig URI profile

## Trust and evidence

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html): PKIX and CRL
- [RFC 10007](https://www.rfc-editor.org/rfc/rfc10007.html), June 2026:
  selected update requiring explicit `keyUsage/cRLSign` in version 3 certificates
  of CRL issuers;
  this selection does not imply implementation of every other RFC 5280 update
- [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html): CMS
- [RFC 6211](https://www.rfc-editor.org/rfc/rfc6211.html): Algorithm Identifier Protection
- [RFC 5035](https://www.rfc-editor.org/rfc/rfc5035.html): ESSCertIDv2
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html) and [RFC 9654](https://www.rfc-editor.org/rfc/rfc9654.html): OCSP and nonce
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) and [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html): timestamps
- [ETSI EN 319 132-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf): XAdES properties
- [ETSI EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf): future historical-validation baseline; the complete process is unimplemented

## Protocols and encryption

- SAML 2.0 [Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf),
  [Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf),
  [Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
  [Metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf) and
  [metadata trust](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-os.html)
- SAML 2.0 [Conformance](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf)
  and [Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html)
- [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/): bounded GCM/CBC,
  OAEP, key wrap, ConcatKDF/ECDH and selected Element/Content replacement;
  algorithm availability and default security policy are tracked separately
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html): RSA-OAEP and PKCS#1 encodings
- [RFC 5208](https://www.rfc-editor.org/rfc/rfc5208.html),
  [RFC 5915](https://www.rfc-editor.org/rfc/rfc5915.html) and
  [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html): key and textual encodings
- [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html): PBES2, PBKDF2 and PBMAC1
- [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292.html) and
  [RFC 9879](https://www.rfc-editor.org/rfc/rfc9879.html): PKCS#12 and PBMAC1 password integrity
- [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394.html): AES Key Wrap
- [RFC 3217](https://www.rfc-editor.org/rfc/rfc3217.html): explicit legacy TripleDES Key Wrap

The library does not perform XSD validation or download schemas.

## Regression semantics checked on 21 October 2026

`fn:subsequence` uses a required single `xs:double` for a supplied length in
[F&O 2.0 Second Edition §15.1.10](https://www.w3.org/TR/2010/REC-xpath-functions-20101214/#func-subsequence)
(14 December 2010), [F&O 3.0 §14.1.9](https://www.w3.org/TR/2014/REC-xpath-functions-30-20140408/#func-subsequence)
(8 April 2014), and [F&O 3.1 §14.1.8](https://www.w3.org/TR/2017/REC-xpath-functions-31-20170321/#func-subsequence)
(21 March 2017). The 2.0 Second Edition incorporates the earlier editorial
subsequence erratum E2. The linked [3.0 errata](https://www.w3.org/XML/2014/qt-errata/xpath-functions-30-errata.html)
and [3.1 draft errata](https://www.w3.org/XML/2017/qt-errata/xpath-functions-31-errata.html)
do not change this signature. XPath 1.0 has no `fn:subsequence`; XSLT backwards
compatibility retains its first-item/number conversion rules where applicable.

Subtree import follows [Namespaces in XML 1.0 Third Edition §§6.1–6.2](https://www.w3.org/TR/2009/REC-xml-names-20091208/#scoping)
(8 December 2009): default namespace scope affects unprefixed elements but not
unprefixed attributes. The source's lexical prefixes and namespace bindings are
retained, including an absent default namespace; QName-valued XPath/XSLT content
is not rewritten. The [namespace errata](https://www.w3.org/XML/2009/xml-names-errata)
list no corrections.

Transform parameters follow [XML Signature 1.1 §4.4.3.4](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Transforms)
and its XPath/XSLT processing sections (11 April 2013), plus the linked Filter2
and Exclusive C14N specifications. The [XML Signature 1.1 errata](https://www.w3.org/2008/xmlsec/errata/xmldsig-core-11-errata.html)
do not change the parameter requirements used by these regressions. Numeric
resource accounting is an implementation policy, not a W3C memory guarantee.
