// Whole-SOAP proof producer using the independent JDK JSR 105 implementation.
// It declares the standard enveloped transform; it does not implement the
// nonstandard CS01 self-exclusion interpretation.
import java.nio.file.*;
import java.security.cert.*;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;

public class ECPProofOracle {
    static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    static final String WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

    public static void main(String[] args) throws Exception {
        // private.pem certificate.pem input.xml output.xml C14N signature-method
        Document document = DetachedOracle.builder().parse(Path.of(args[2]).toFile());
        Element root = document.getDocumentElement();
        if (!SOAP.equals(root.getNamespaceURI()) || !"Envelope".equals(root.getLocalName()))
            throw new IllegalArgumentException("SOAP Envelope required");
        Element header = null;
        for (Node n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && SOAP.equals(e.getNamespaceURI()) && "Header".equals(e.getLocalName()))
                header = e;
        }
        if (header == null) {
            header = document.createElementNS(SOAP, "soap:Header");
            header.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:soap", SOAP);
            root.insertBefore(header, root.getFirstChild());
        }
        if (document.getElementsByTagNameNS(WSSE, "Security").getLength() != 0)
            throw new IllegalArgumentException("existing proof header");
        Element security = document.createElementNS(WSSE, "wsse:Security");
        security.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:wsse", WSSE);
        security.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:soap", SOAP);
        security.setAttributeNS(SOAP, "soap:actor", "http://schemas.xmlsoap.org/soap/actor/next");
        security.setAttributeNS(SOAP, "soap:mustUnderstand", "1");
        header.appendChild(security);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        Reference reference = factory.newReference("",
            factory.newDigestMethod(DigestMethod.SHA256, null),
            List.of(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
        SignedInfo info = factory.newSignedInfo(
            factory.newCanonicalizationMethod(args[4], (C14NMethodParameterSpec) null),
            factory.newSignatureMethod(args[5], null), List.of(reference));
        X509Certificate certificate;
        try (var input = Files.newInputStream(Path.of(args[1]))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        var keyInfo = factory.getKeyInfoFactory().newKeyInfo(
            List.of(factory.getKeyInfoFactory().newX509Data(List.of(certificate))));
        DOMSignContext context = new DOMSignContext(DetachedOracle.key(Path.of(args[0]), true), security);
        context.setDefaultNamespacePrefix("proofds");
        context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
        context.setURIDereferencer(CoreOracle.resolver(factory));
        factory.newXMLSignature(info, keyInfo).sign(context);
        TransformerFactory transformers = TransformerFactory.newInstance();
        transformers.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformers.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer serializer = transformers.newTransformer();
        serializer.setOutputProperty(OutputKeys.INDENT, "no");
        serializer.transform(new DOMSource(document), new StreamResult(Path.of(args[3]).toFile()));
        System.out.println("JDK whole-SOAP proof signed");
    }
}
