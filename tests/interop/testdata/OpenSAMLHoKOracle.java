// Thin adapter around the released OpenSAML validator, builders and signer.
// No SAML parsing, X.509 matching or signature algorithm is reimplemented here.
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;
import org.opensaml.core.Version;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.assertion.*;
import org.opensaml.saml.common.messaging.context.ChannelBindingsContext;
import org.opensaml.saml.common.profile.impl.VerifyChannelBindings;
import org.opensaml.saml.ext.saml2cb.ChannelBindings;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.impl.HolderOfKeySubjectConfirmationValidator;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.*;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.SignatureException;

public class OpenSAMLHoKOracle {
    static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    static final String NEXT = "http://schemas.xmlsoap.org/soap/actor/next";

    static X509Certificate certificate(String file) throws Exception {
        try (var input = Files.newInputStream(Path.of(file))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }

    static void signature(Signature signature, PublicKey key) throws Exception {
        if (signature == null) throw new GeneralSecurityException("missing SAML signature");
        new SAMLSignatureProfileValidator().validate(signature);
        SignatureValidator.validate(signature, new BasicCredential(key));
    }

    static Response response(String file) throws Exception {
        Document document = DetachedOracle.builder().parse(Path.of(file).toFile());
        Element root = document.getDocumentElement();
        if (SOAP.equals(root.getNamespaceURI())) {
            NodeList bodies = root.getElementsByTagNameNS(SOAP, "Body");
            if (bodies.getLength() != 1) throw new IllegalArgumentException("one SOAP body required");
            root = null;
            for (Node n = bodies.item(0).getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n instanceof Element e) {
                    if (root != null) throw new IllegalArgumentException("one SOAP payload required");
                    root = e;
                }
            }
        }
        return (Response) XMLObjectSupport.getUnmarshaller(root).unmarshall(root);
    }

    static void verify(String[] args) throws Exception {
        // verify input.xml idp-public.pem presenter-cert.pem recipient request-id
        Response response = response(args[1]);
        PublicKey key = (PublicKey) DetachedOracle.key(Path.of(args[2]), false);
        if (response.getAssertions().size() != 1) throw new IllegalArgumentException("one assertion required");
        Assertion assertion = response.getAssertions().get(0);
        try {
            signature(response.getSignature(), key);
            signature(assertion.getSignature(), key);
        } catch (SignatureException rejected) {
            System.out.println("{\"engine\":\"OpenSAML 5.2.3\",\"signatures\":false,\"confirmed\":false}");
            return;
        }
        Map<String, Object> params = new HashMap<>();
        params.put(SAML2AssertionValidationParameters.SC_HOK_PRESENTER_CERT, certificate(args[3]));
        params.put(SAML2AssertionValidationParameters.SC_RECIPIENT_REQUIRED, true);
        params.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Set.of(args[4]));
        params.put(SAML2AssertionValidationParameters.SC_IN_RESPONSE_TO_REQUIRED, true);
        params.put(SAML2AssertionValidationParameters.SC_VALID_IN_RESPONSE_TO, args[5]);
        params.put(SAML2AssertionValidationParameters.SC_NOT_BEFORE_REQUIRED, false);
        params.put(SAML2AssertionValidationParameters.SC_NOT_ON_OR_AFTER_REQUIRED, false);
        params.put(SAML2AssertionValidationParameters.SC_ADDRESS_REQUIRED, false);
        params.put(SAML2AssertionValidationParameters.SC_CHECK_ADDRESS, false);
        boolean confirmed = false;
        HolderOfKeySubjectConfirmationValidator validator = new HolderOfKeySubjectConfirmationValidator();
        for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
            if (validator.validate(confirmation, assertion, new ValidationContext(params)) == ValidationResult.VALID)
                confirmed = true;
        }
        System.out.println("{\"engine\":\"OpenSAML 5.2.3\",\"signatures\":true,\"confirmed\":" + confirmed + "}");
    }

    static Signature signing(BasicX509Credential credential) {
        Signature signature = (Signature) XMLObjectSupport.buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        return signature;
    }

    static void channels(String[] args) throws Exception {
        // channels signed-type signed-base64 received-type received-base64
        ChannelBindingsContext signed = new ChannelBindingsContext();
        ChannelBindingsContext received = new ChannelBindingsContext();
        ChannelBindingsContext verified = new ChannelBindingsContext();
        if (!args[2].isEmpty()) {
            ChannelBindings value = (ChannelBindings) XMLObjectSupport.buildXMLObject(ChannelBindings.DEFAULT_ELEMENT_NAME);
            value.setType(args[1]); value.setValue(args[2]); signed.getChannelBindings().add(value);
        }
        if (!args[4].isEmpty()) {
            ChannelBindings value = (ChannelBindings) XMLObjectSupport.buildXMLObject(ChannelBindings.DEFAULT_ELEMENT_NAME);
            value.setType(args[3]); value.setValue(args[4]); received.getChannelBindings().add(value);
        }
        VerifyChannelBindings action = new VerifyChannelBindings();
        action.setChannelBindingsLookupStrategy1(context -> signed);
        action.setChannelBindingsLookupStrategy2(context -> received);
        action.setChannelBindingsCreationStrategy(context -> verified);
        action.initialize();
        action.execute(new ProfileRequestContext());
        System.out.println("{\"matched\":" + !verified.getChannelBindings().isEmpty() + "}");
    }

    static void issue(String[] args) throws Exception {
        // issue private.pem idp-cert.pem presenter-cert.pem output.xml issuer audience recipient request-id instant [alternative-cert.pem]
        Instant at = Instant.parse(args[9]);
        BasicX509Credential credential = new BasicX509Credential(certificate(args[2]),
            (PrivateKey) DetachedOracle.key(Path.of(args[1]), true));
        Response response = (Response) XMLObjectSupport.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
        response.setID("_opensaml_response_" + UUID.randomUUID()); response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(at); response.setDestination(args[7]); response.setInResponseTo(args[8]);
        Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(args[5]); response.setIssuer(issuer);
        Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
        StatusCode code = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
        code.setValue(StatusCode.SUCCESS); status.setStatusCode(code); response.setStatus(status);
        Assertion assertion = (Assertion) XMLObjectSupport.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID("_opensaml_assertion_" + UUID.randomUUID()); assertion.setVersion(SAMLVersion.VERSION_20); assertion.setIssueInstant(at);
        Issuer assertionIssuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
        assertionIssuer.setValue(args[5]); assertion.setIssuer(assertionIssuer);
        Subject subject = (Subject) XMLObjectSupport.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);
        NameID name = (NameID) XMLObjectSupport.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
        name.setFormat(NameID.UNSPECIFIED); name.setValue("alice"); subject.setNameID(name);
        SubjectConfirmation confirmation = (SubjectConfirmation) XMLObjectSupport.buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        confirmation.setMethod(SubjectConfirmation.METHOD_HOLDER_OF_KEY);
        KeyInfoConfirmationDataType data = (KeyInfoConfirmationDataType) XMLObjectSupport
            .getBuilder(KeyInfoConfirmationDataType.TYPE_NAME)
            .buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME, KeyInfoConfirmationDataType.TYPE_NAME);
        data.setRecipient(args[7]); data.setInResponseTo(args[8]);
        if (args.length > 10) {
            KeyInfo alternative = (KeyInfo) XMLObjectSupport.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            KeyInfoSupport.addCertificate(alternative, certificate(args[10])); data.getKeyInfos().add(alternative);
        }
        KeyInfo info = (KeyInfo) XMLObjectSupport.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
        KeyInfoSupport.addCertificate(info, certificate(args[3])); data.getKeyInfos().add(info);
        confirmation.setSubjectConfirmationData(data); subject.getSubjectConfirmations().add(confirmation);
        assertion.setSubject(subject);
        Conditions conditions = (Conditions) XMLObjectSupport.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(at); conditions.setNotOnOrAfter(at.plusSeconds(300));
        AudienceRestriction restriction = (AudienceRestriction) XMLObjectSupport.buildXMLObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        Audience audience = (Audience) XMLObjectSupport.buildXMLObject(Audience.DEFAULT_ELEMENT_NAME);
        audience.setURI(args[6]); restriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(restriction); assertion.setConditions(conditions);
        AuthnStatement statement = (AuthnStatement) XMLObjectSupport.buildXMLObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
        statement.setAuthnInstant(at);
        AuthnContext authn = (AuthnContext) XMLObjectSupport.buildXMLObject(AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef classRef = (AuthnContextClassRef) XMLObjectSupport.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        classRef.setURI("urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"); authn.setAuthnContextClassRef(classRef);
        statement.setAuthnContext(authn); assertion.getAuthnStatements().add(statement);
        response.getAssertions().add(assertion);
        Signature inner = signing(credential), outer = signing(credential);
        assertion.setSignature(inner); response.setSignature(outer);
        Document document = DetachedOracle.builder().newDocument();
        Element envelope = document.createElementNS(SOAP, "soap:Envelope");
        envelope.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:soap", SOAP); document.appendChild(envelope);
        Element header = document.createElementNS(SOAP, "soap:Header"); envelope.appendChild(header);
        var routing = (org.opensaml.saml.saml2.ecp.Response) XMLObjectSupport.buildXMLObject(org.opensaml.saml.saml2.ecp.Response.DEFAULT_ELEMENT_NAME);
        routing.setAssertionConsumerServiceURL(args[7]); routing.setSOAP11Actor(NEXT); routing.setSOAP11MustUnderstand(true);
        XMLObjectSupport.getMarshaller(routing).marshall(routing, header);
        var hint = (org.opensaml.saml.saml2.ecp.SubjectConfirmation) XMLObjectSupport.buildXMLObject(org.opensaml.saml.saml2.ecp.SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        hint.setMethod(SubjectConfirmation.METHOD_HOLDER_OF_KEY);
        hint.setSubjectConfirmationData(XMLObjectSupport.cloneXMLObject(data));
        hint.setSOAP11Actor(NEXT); hint.setSOAP11MustUnderstand(true);
        XMLObjectSupport.getMarshaller(hint).marshall(hint, header);
        Element body = document.createElementNS(SOAP, "soap:Body"); envelope.appendChild(body);
        XMLObjectSupport.getMarshaller(response).marshall(response, body);
        Signer.signObject(inner); Signer.signObject(outer);
        TransformerFactory transformers = TransformerFactory.newInstance();
        transformers.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, ""); transformers.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer serializer = transformers.newTransformer(); serializer.setOutputProperty(OutputKeys.INDENT, "no");
        serializer.transform(new DOMSource(document), new StreamResult(Path.of(args[4]).toFile()));
        System.out.println("OpenSAML 5.2.3 HoK response produced");
    }

    public static void main(String[] args) throws Exception {
        if (!"5.2.3".equals(Version.getVersion())) throw new IllegalStateException("OpenSAML 5.2.3 required");
        InitializationService.initialize();
        if (args[0].equals("verify")) verify(args);
        else if (args[0].equals("issue")) issue(args);
        else if (args[0].equals("channels")) channels(args);
        else throw new IllegalArgumentException("mode");
    }
}
