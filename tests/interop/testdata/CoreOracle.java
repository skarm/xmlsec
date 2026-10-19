// Independent SAME-DOCUMENT XMLDSig oracle, public JSR 105 API only.
// Reuses the hardened XML parser/PEM loader from DetachedOracle. It never falls
// back to external URI fetching; this helper is TEST tooling, not library code.
import java.nio.file.*;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.crypto.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;

public class CoreOracle {
    static final String DS=XMLSignature.XMLNS;
    static final String EXC="http://www.w3.org/2001/10/xml-exc-c14n#";
    static final String C11="http://www.w3.org/2006/12/xml-c14n11";
    static final String SHA256="http://www.w3.org/2001/04/xmlenc#sha256";
    static final Set<String> ID_ELEMENTS=Set.of("Signature","SignedInfo","SignatureValue","Reference","KeyInfo","Object","Manifest","SignatureProperties","SignatureProperty");
    static void ids(Element e) {
        if(e.hasAttribute("ID"))e.setIdAttribute("ID",true);
        if(DS.equals(e.getNamespaceURI())&&ID_ELEMENTS.contains(e.getLocalName())&&e.hasAttribute("Id"))e.setIdAttribute("Id",true);
        for(Node n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element)ids((Element)n);
    }
    static URIDereferencer resolver(XMLSignatureFactory f) {
        return (r,c)->{
            String uri=r.getURI();
            if(uri==null||(!uri.isEmpty()&&!uri.startsWith("#")))throw new URIReferenceException("external URI forbidden");
            return f.getURIDereferencer().dereference(r,c);
        };
    }
    static Element item(Document d,String id,String text) {
        Element e=d.createElement("item");e.setAttribute("ID",id);e.appendChild(d.createTextNode(text));
        e.appendChild(d.createComment("comment"));return e;
    }
    static Reference ref(XMLSignatureFactory f,String uri,List<String> algorithms,boolean bad) throws Exception{
        List<Transform> ts=new ArrayList<>();
        for(String a:algorithms)ts.add(f.newTransform(a,(TransformParameterSpec)null));
        DigestMethod dm=f.newDigestMethod(SHA256,null);
        return bad?f.newReference(uri,dm,ts,null,null,new byte[32]):f.newReference(uri,dm,ts,null,null);
    }
    public static void main(String[] args) throws Exception {
        XMLSignatureFactory f=XMLSignatureFactory.getInstance("DOM");
        String mode=args[0];
        if(mode.equals("verify")){
            // verify public.pem input.xml signature-index
            Document d=DetachedOracle.builder().parse(Path.of(args[2]).toFile());ids(d.getDocumentElement());
            NodeList signatures=d.getElementsByTagNameNS(DS,"Signature");int index=Integer.parseInt(args[3]);
            if(index<0||index>=signatures.getLength())throw new IllegalArgumentException("index");
            DOMValidateContext ctx=new DOMValidateContext(DetachedOracle.key(Path.of(args[1]),false),signatures.item(index));
            ctx.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);ctx.setURIDereferencer(resolver(f));
            XMLSignature s=f.unmarshalXMLSignature(ctx);
            boolean sv=s.getSignatureValue().validate(ctx);
            List<Boolean> refs=new ArrayList<>();for(Reference r:s.getSignedInfo().getReferences())refs.add(r.validate(ctx));
            System.out.println("{\"signature_value\":"+sv+",\"references\":"+refs+",\"core\":"+s.validate(ctx)+"}");return;
        }
        // sign[-bad-second] private.pem output.xml CM SIGMETHOD form
        boolean bad=mode.equals("sign-bad-second");
        if(!mode.equals("sign")&&!bad)throw new IllegalArgumentException("mode");
        String cm=args[3],method=args[4],form=args[5];
        Document d=DetachedOracle.builder().newDocument();
        Element root=null;
        if(!form.equals("enveloping")){
            root=d.createElement("root");root.setAttribute("ID","root");root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,"xmlns:z","urn:unused");d.appendChild(root);
            root.appendChild(item(d,"data","one"));root.appendChild(item(d,"other","two"));ids(root);
        }
        int count=form.equals("multi")?2:1;
        for(int index=0;index<count;index++){
            List<Reference> refs=new ArrayList<>();List<XMLObject> objects=new ArrayList<>();
            if(form.equals("enveloping")){
                Element payload=d.createElementNS("urn:payload","p:item");payload.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,"xmlns:p","urn:payload");payload.appendChild(d.createTextNode("one"));payload.appendChild(d.createComment("comment"));
                objects.add(f.newXMLObject(List.of(new DOMStructure(payload)),"data","text/xml",null));
                objects.add(f.newXMLObject(List.of(new DOMStructure(d.createTextNode("aGVsbG8="))),"bin",null,null));
                refs.add(ref(f,"#data",List.of(cm),false));refs.add(ref(f,"#bin",List.of(Transform.BASE64),bad));refs.add(ref(f,"#data",List.of(EXC),false));
            }else if(form.equals("whole")){
                refs.add(ref(f,"",List.of(Transform.ENVELOPED,cm),false));refs.add(ref(f,"#root",List.of(Transform.ENVELOPED,EXC),bad));
            }else if(form.equals("xpointer")){
                refs.add(ref(f,"#xpointer(id('data'))",List.of(EXC+"WithComments"),false));refs.add(ref(f,"#data",List.of(EXC+"WithComments"),bad));
            }else if(form.equals("sibling")||form.equals("multi")){
                refs.add(ref(f,"#data",List.of(cm),false));refs.add(ref(f,"#other",List.of(C11),bad));
            }else throw new IllegalArgumentException("form");
            SignedInfo si=f.newSignedInfo(f.newCanonicalizationMethod(cm,(C14NMethodParameterSpec)null),f.newSignatureMethod(method,null),refs);
            DOMSignContext ctx=new DOMSignContext(DetachedOracle.key(Path.of(args[1]),true),root==null?d:root);
            ctx.setDefaultNamespacePrefix("ds");ctx.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);ctx.setURIDereferencer(resolver(f));
            f.newXMLSignature(si,null,objects,"s"+index,null).sign(ctx);
        }
        TransformerFactory tf=TransformerFactory.newInstance();tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");
        Transformer t=tf.newTransformer();t.setOutputProperty(OutputKeys.INDENT,"no");t.transform(new DOMSource(d),new StreamResult(Path.of(args[2]).toFile()));
        System.out.println("signed");
    }
}
