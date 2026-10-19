// Independent public JSR 105 Manifest graph test oracle. It is deliberately
// restricted to generated local fixtures and one allowlisted external resource.
import java.io.*;
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

public class ManifestOracle {
 static final String DS=XMLSignature.XMLNS;
 static final String EXC="http://www.w3.org/2001/10/xml-exc-c14n#";
 static final String SHA256="http://www.w3.org/2001/04/xmlenc#sha256";
 static URIDereferencer resolver(XMLSignatureFactory f, Path attachment) {
  return (r,c)->{
   String uri=r.getURI();
   if("urn:attachment".equals(uri)) {
    try{return new OctetStreamData(new ByteArrayInputStream(Files.readAllBytes(attachment)),uri,null);}
    catch(IOException e){throw new URIReferenceException(e);}
   }
   if(uri!=null&&(uri.isEmpty()||uri.startsWith("#")))return f.getURIDereferencer().dereference(r,c);
   throw new URIReferenceException("not allowlisted");
  };
 }
 static Reference ref(XMLSignatureFactory f,String uri,String type,boolean bad)throws Exception {
  List<Transform> ts=uri.startsWith("#")?List.of(f.newTransform(EXC,(TransformParameterSpec)null)):List.of();
  DigestMethod dm=f.newDigestMethod(SHA256,null);
  return bad?f.newReference(uri,dm,ts,type,null,new byte[32]):f.newReference(uri,dm,ts,type,null);
 }
 public static void main(String[] args)throws Exception {
  // mode key.pem xml attachment.bin [signature-method]
  String mode=args[0];XMLSignatureFactory f=XMLSignatureFactory.getInstance("DOM");Path attachment=Path.of(args[3]);
  if(mode.equals("verify")) {
   Document d=DetachedOracle.builder().parse(Path.of(args[2]).toFile());CoreOracle.ids(d.getDocumentElement());
   NodeList sigs=d.getElementsByTagNameNS(DS,"Signature");if(sigs.getLength()!=1)throw new IllegalArgumentException("signature count");
   DOMValidateContext c=new DOMValidateContext(DetachedOracle.key(Path.of(args[1]),false),sigs.item(0));
   c.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);c.setProperty("org.jcp.xml.dsig.validateManifests",Boolean.TRUE);c.setURIDereferencer(resolver(f,attachment));
   XMLSignature s=f.unmarshalXMLSignature(c);boolean sv=s.getSignatureValue().validate(c);List<Boolean> direct=new ArrayList<>();for(Reference r:s.getSignedInfo().getReferences())direct.add(r.validate(c));
   List<String> manifests=new ArrayList<>();
   for(XMLObject o:s.getObjects())for(XMLStructure x:o.getContent())if(x instanceof Manifest m){List<Boolean> values=new ArrayList<>();for(Reference r:m.getReferences())values.add(r.validate(c));manifests.add("{\"id\":\""+m.getId()+"\",\"references\":"+values+"}");}
   System.out.println("{\"signature_value\":"+sv+",\"references\":"+direct+",\"manifests\":["+String.join(",",manifests)+"],\"valid\":"+s.validate(c)+"}");return;
  }
  if(!mode.equals("sign")&&!mode.equals("sign-bad"))throw new IllegalArgumentException("mode");
  boolean bad=mode.equals("sign-bad");Document d=DetachedOracle.builder().newDocument();
  Manifest top=f.newManifest(List.of(ref(f,"#leaf",DS+"Manifest",false),ref(f,"#leaf",null,false)),"top");
  Manifest leaf=f.newManifest(List.of(ref(f,"#a",null,false),ref(f,"#b",null,bad),ref(f,"urn:attachment",null,false)),"leaf");
  List<XMLObject> objects=List.of(f.newXMLObject(List.of(top),null,null,null),f.newXMLObject(List.of(leaf),null,null,null),f.newXMLObject(List.of(new DOMStructure(d.createTextNode("payload"))),"a",null,null),f.newXMLObject(List.of(new DOMStructure(d.createTextNode("second"))),"b",null,null));
  SignedInfo si=f.newSignedInfo(f.newCanonicalizationMethod(EXC,(C14NMethodParameterSpec)null),f.newSignatureMethod(args[4],null),List.of(ref(f,"#top",DS+"Manifest",false)));
  DOMSignContext c=new DOMSignContext(DetachedOracle.key(Path.of(args[1]),true),d);c.setDefaultNamespacePrefix("ds");c.setURIDereferencer(resolver(f,attachment));c.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);
  f.newXMLSignature(si,null,objects,"sig",null).sign(c);
  TransformerFactory tf=TransformerFactory.newInstance();tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");Transformer t=tf.newTransformer();t.setOutputProperty(OutputKeys.INDENT,"no");t.transform(new DOMSource(d),new StreamResult(Path.of(args[2]).toFile()));
 }
}
