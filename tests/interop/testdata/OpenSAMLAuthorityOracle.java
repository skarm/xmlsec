// Independent OpenSAML 5.2.3 builders, schema validator and signature engine.
// No SAML parser, XML canonicalizer or cryptographic implementation is supplied here.
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import javax.xml.namespace.QName;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.TransformerFactory;
import org.opensaml.core.Version;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.*;
import org.opensaml.saml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.*;

public class OpenSAMLAuthorityOracle {
    static final String NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    static XMLObject object(QName name) { return XMLObjectSupport.buildXMLObject(name); }
    static Issuer issuer(String name) { Issuer i=(Issuer)object(Issuer.DEFAULT_ELEMENT_NAME);i.setValue(name);return i; }
    static Subject subject() {
        Subject s=(Subject)object(Subject.DEFAULT_ELEMENT_NAME);
        NameID n=(NameID)object(NameID.DEFAULT_ELEMENT_NAME);n.setValue("alice");s.setNameID(n);return s;
    }
    static Subject copySubject(Subject original) {
        Subject s=(Subject)object(Subject.DEFAULT_ELEMENT_NAME);NameID old=original.getNameID();
        NameID n=(NameID)object(NameID.DEFAULT_ELEMENT_NAME);n.setValue(old.getValue());n.setFormat(old.getFormat());n.setNameQualifier(old.getNameQualifier());n.setSPNameQualifier(old.getSPNameQualifier());n.setSPProvidedID(old.getSPProvidedID());s.setNameID(n);return s;
    }
    static BasicX509Credential credential(String key,String cert) throws Exception {
        return new BasicX509Credential(OpenSAMLHoKOracle.certificate(cert),(PrivateKey)DetachedOracle.key(Path.of(key),true));
    }
    static void sign(SignableSAMLObject value,BasicX509Credential key) throws Exception {
        value.setSignature(OpenSAMLHoKOracle.signing(key));XMLObjectSupport.marshall(value);Signer.signObject(value.getSignature());
    }
    static void write(XMLObject object,String file) throws Exception {
        Element root=XMLObjectSupport.marshall(object);
        new SAMLSchemaBuilder(SAMLSchemaBuilder.SAML1Version.SAML_11).getSAMLSchema().newValidator().validate(new DOMSource(root));
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(root),new StreamResult(Path.of(file).toFile()));
    }
    static XMLObject read(String file) throws Exception {
        Document d=DetachedOracle.builder().parse(Path.of(file).toFile());
        new SAMLSchemaBuilder(SAMLSchemaBuilder.SAML1Version.SAML_11).getSAMLSchema().newValidator().validate(new DOMSource(d));
        return XMLObjectSupport.getUnmarshaller(d.getDocumentElement()).unmarshall(d.getDocumentElement());
    }
    static void verify(XMLObject value,PublicKey key) throws Exception {
        if (value instanceof SignableSAMLObject s) OpenSAMLHoKOracle.signature(s.getSignature(),key);
        if (value instanceof Response response) for (Assertion a:response.getAssertions()) verify(a,key);
    }
    static void query(String[] a) throws Exception {
        // query kind key cert out requester endpoint instant
        RequestAbstractType q=(RequestAbstractType)object(new QName(NS,a[1],"samlp"));
        q.setID("_oracle_query_"+java.util.UUID.randomUUID());q.setVersion(SAMLVersion.VERSION_20);q.setIssuer(issuer(a[5]));q.setDestination(a[6]);q.setIssueInstant(Instant.parse(a[7]));
        if(q instanceof SubjectQuery s)s.setSubject(subject());
        if(q instanceof AuthnQuery s){s.setSessionIndex("past-session");RequestedAuthnContext c=(RequestedAuthnContext)object(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);AuthnContextClassRef r=(AuthnContextClassRef)object(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);r.setURI("urn:example:strong");c.getAuthnContextClassRefs().add(r);s.setRequestedAuthnContext(c);}
        if(q instanceof AttributeQuery s){Attribute v=(Attribute)object(Attribute.DEFAULT_ELEMENT_NAME);v.setName("role");s.getAttributes().add(v);}
        if(q instanceof AuthzDecisionQuery s){s.setResource("urn:example:resource");Action v=(Action)object(Action.DEFAULT_ELEMENT_NAME);v.setNamespace("urn:example:actions");v.setValue("read");s.getActions().add(v);}
        if(q instanceof AssertionIDRequest s){AssertionIDRef ref=(AssertionIDRef)object(AssertionIDRef.DEFAULT_ELEMENT_NAME);ref.setValue("_held");s.getAssertionIDRefs().add(ref);}
        if(q instanceof NameIDMappingRequest s){NameID n=(NameID)object(NameID.DEFAULT_ELEMENT_NAME);n.setValue("alice");s.setNameID(n);NameIDPolicy p=(NameIDPolicy)object(NameIDPolicy.DEFAULT_ELEMENT_NAME);p.setFormat(NameID.PERSISTENT);p.setSPNameQualifier("https://target.test/entity");p.setAllowCreate(true);s.setNameIDPolicy(p);}
        sign(q,credential(a[2],a[3]));write(q,a[4]);
    }
    static Status status(String code){Status s=(Status)object(Status.DEFAULT_ELEMENT_NAME);StatusCode c=(StatusCode)object(StatusCode.DEFAULT_ELEMENT_NAME);c.setValue(code);s.setStatusCode(c);return s;}
    static void response(String[] a) throws Exception {
        // response query key cert out authority instant
        RequestAbstractType request=(RequestAbstractType)read(a[1]);Instant at=Instant.parse(a[6]);BasicX509Credential key=credential(a[2],a[3]);
        if(request instanceof NameIDMappingRequest mapping){
            NameIDMappingResponse r=(NameIDMappingResponse)object(NameIDMappingResponse.DEFAULT_ELEMENT_NAME);r.setID("_oracle_mapping");r.setVersion(SAMLVersion.VERSION_20);r.setIssueInstant(at);r.setIssuer(issuer(a[5]));r.setInResponseTo(request.getID());r.setStatus(status(StatusCode.SUCCESS));
            NameID n=(NameID)object(NameID.DEFAULT_ELEMENT_NAME);n.setValue("mapped-alice");n.setFormat(mapping.getNameIDPolicy().getFormat());n.setSPNameQualifier(mapping.getNameIDPolicy().getSPNameQualifier());r.setNameID(n);sign(r,key);write(r,a[4]);return;
        }
        Response r=(Response)object(Response.DEFAULT_ELEMENT_NAME);r.setID("_oracle_response");r.setVersion(SAMLVersion.VERSION_20);r.setIssueInstant(at);r.setIssuer(issuer(a[5]));r.setInResponseTo(request.getID());r.setStatus(status(StatusCode.SUCCESS));
        for(int index=0;index<2;index++){
            Assertion assertion=(Assertion)object(Assertion.DEFAULT_ELEMENT_NAME);assertion.setID(request instanceof AssertionIDRequest?"_held":"_oracle_assertion_"+index);assertion.setVersion(SAMLVersion.VERSION_20);assertion.setIssueInstant(at);assertion.setIssuer(issuer(a[5]));
            assertion.setSubject(request instanceof SubjectQuery q?copySubject(q.getSubject()):subject());
            if(request instanceof AuthnQuery q){AuthnStatement s=(AuthnStatement)object(AuthnStatement.DEFAULT_ELEMENT_NAME);s.setAuthnInstant(at.minusSeconds(3600));s.setSessionIndex(q.getSessionIndex());AuthnContext c=(AuthnContext)object(AuthnContext.DEFAULT_ELEMENT_NAME);AuthnContextClassRef ref=(AuthnContextClassRef)object(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);ref.setURI("urn:example:strong");c.setAuthnContextClassRef(ref);s.setAuthnContext(c);assertion.getAuthnStatements().add(s);}
            else if(request instanceof AuthzDecisionQuery q){AuthzDecisionStatement s=(AuthzDecisionStatement)object(AuthzDecisionStatement.DEFAULT_ELEMENT_NAME);s.setDecision(DecisionTypeEnumeration.PERMIT);s.setResource(q.getResource());for(Action action:q.getActions())s.getActions().add((Action)XMLObjectSupport.cloneXMLObject(action));assertion.getAuthzDecisionStatements().add(s);}
            else {AttributeStatement s=(AttributeStatement)object(AttributeStatement.DEFAULT_ELEMENT_NAME);Attribute v=(Attribute)object(Attribute.DEFAULT_ELEMENT_NAME);v.setName("role");XSString value=new XSStringBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,XSString.TYPE_NAME);value.setValue("reader");v.getAttributeValues().add(value);s.getAttributes().add(v);assertion.getAttributeStatements().add(s);}
            assertion.setSignature(OpenSAMLHoKOracle.signing(key));r.getAssertions().add(assertion);if(request instanceof AssertionIDRequest)break;
        }
        r.setSignature(OpenSAMLHoKOracle.signing(key));XMLObjectSupport.marshall(r);for(Assertion assertion:r.getAssertions())Signer.signObject(assertion.getSignature());Signer.signObject(r.getSignature());write(r,a[4]);
    }
    public static void main(String[] a) throws Exception {
        InitializationService.initialize();if(!"5.2.3".equals(Version.getVersion()))throw new IllegalStateException("OpenSAML 5.2.3 required");
        switch(a[0]){case "query":query(a);break;case "response":response(a);break;case "schema":read(a[1]);System.out.println("schema valid");break;case "verify":verify(read(a[1]),(PublicKey)DetachedOracle.key(Path.of(a[2]),false));System.out.println("verified");break;default:throw new IllegalArgumentException("mode");}
    }
}
