// Independent public JSR 105 Manifest graph test oracle. It is deliberately
// restricted to generated local fixtures and one allowlisted external resource.
import java.io.*;
import java.nio.file.*;
import java.security.Key;
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
 static URIDereferencer externalResolver(XMLSignatureFactory f,Path manifest,Path payload) {
  return (r,c)->{
   Path path="urn:manifest".equals(r.getURI())?manifest:"urn:attachment".equals(r.getURI())?payload:null;
   if(path!=null){try{return new OctetStreamData(new ByteArrayInputStream(Files.readAllBytes(path)),r.getURI(),null);}catch(IOException e){throw new URIReferenceException(e);}}
   if(r.getURI()!=null&&(r.getURI().isEmpty()||r.getURI().startsWith("#")))return f.getURIDereferencer().dereference(r,c);
   throw new URIReferenceException("external Manifest URI not allowlisted");
  };
 }
 static void save(Node node,Path path)throws Exception {
  TransformerFactory tf=TransformerFactory.newInstance();tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");
  Transformer t=tf.newTransformer();t.setOutputProperty(OutputKeys.INDENT,"no");t.transform(new DOMSource(node),new StreamResult(path.toFile()));
 }
 static void signExternal(XMLSignatureFactory f,String[] args)throws Exception {
  Path manifest=Path.of(args[3]),payload=Path.of(args[4]);Key key=DetachedOracle.key(Path.of(args[1]),true);
  // Let JSR 105 compute the nested Manifest reference, then retain its XML as
  // a standalone resource. No Go hash/transform implementation participates.
  Document holder=DetachedOracle.builder().newDocument();
  Manifest m=f.newManifest(List.of(ref(f,"urn:attachment",null,false)),"remote");
  SignedInfo inner=f.newSignedInfo(f.newCanonicalizationMethod(EXC,(C14NMethodParameterSpec)null),f.newSignatureMethod(args[5],null),List.of(ref(f,"#remote",DS+"Manifest",false)));
  DOMSignContext first=new DOMSignContext(key,holder);first.setDefaultNamespacePrefix("ds");first.setURIDereferencer(externalResolver(f,manifest,payload));first.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);
  f.newXMLSignature(inner,null,List.of(f.newXMLObject(List.of(m),null,null,null)),null,null).sign(first);
  Node source=holder.getElementsByTagNameNS(DS,"Manifest").item(0);Document standalone=DetachedOracle.builder().newDocument();
  Element root=(Element)standalone.importNode(source,true);root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,"xmlns:ds",DS);standalone.appendChild(root);save(standalone,manifest);
  Document d=DetachedOracle.builder().newDocument();
  Reference edge=f.newReference("urn:manifest",f.newDigestMethod(SHA256,null),List.of(f.newTransform(EXC,(TransformParameterSpec)null)),DS+"Manifest",null);
  SignedInfo si=f.newSignedInfo(f.newCanonicalizationMethod(EXC,(C14NMethodParameterSpec)null),f.newSignatureMethod(args[5],null),List.of(edge));
  DOMSignContext c=new DOMSignContext(key,d);c.setDefaultNamespacePrefix("ds");c.setURIDereferencer(externalResolver(f,manifest,payload));c.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);
  f.newXMLSignature(si,null).sign(c);save(d,Path.of(args[2]));
 }
 static void verifyExternal(XMLSignatureFactory f,String[] args)throws Exception {
  Path manifest=Path.of(args[3]),payload=Path.of(args[4]);Key key=DetachedOracle.key(Path.of(args[1]),false);
  Document d=DetachedOracle.builder().parse(Path.of(args[2]).toFile());CoreOracle.ids(d.getDocumentElement());
  DOMValidateContext c=new DOMValidateContext(key,d.getElementsByTagNameNS(DS,"Signature").item(0));c.setURIDereferencer(externalResolver(f,manifest,payload));c.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);
  XMLSignature s=f.unmarshalXMLSignature(c);boolean sv=s.getSignatureValue().validate(c);List<Boolean> direct=new ArrayList<>();for(Reference r:s.getSignedInfo().getReferences())direct.add(r.validate(c));
  // JSR 105 does not automatically traverse arbitrary external Manifest XML.
  // Wrap the original node solely for public-API unmarshalling and validate
  // its original Reference values without signing/recomputing them.
  Document source=DetachedOracle.builder().parse(manifest.toFile());
  String shell="<ds:Signature xmlns:ds='"+DS+"'><ds:SignedInfo><ds:CanonicalizationMethod Algorithm='"+EXC+"'/><ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/><ds:Reference URI=''><ds:DigestMethod Algorithm='"+SHA256+"'/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue><ds:Object/></ds:Signature>";
  Document wrapper=DetachedOracle.builder().parse(new ByteArrayInputStream(shell.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  wrapper.getElementsByTagNameNS(DS,"Object").item(0).appendChild(wrapper.importNode(source.getDocumentElement(),true));CoreOracle.ids(wrapper.getDocumentElement());
  DOMValidateContext nested=new DOMValidateContext(key,wrapper.getDocumentElement());nested.setURIDereferencer(externalResolver(f,manifest,payload));nested.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.TRUE);
  XMLSignature loaded=f.unmarshalXMLSignature(nested);List<Boolean> values=new ArrayList<>();
  for(XMLStructure x:loaded.getObjects().get(0).getContent())if(x instanceof Manifest m)for(Reference r:m.getReferences())values.add(r.validate(nested));
  boolean valid=s.validate(c)&&!values.isEmpty()&&!values.contains(Boolean.FALSE);
  System.out.println("{\"signature_value\":"+sv+",\"references\":"+direct+",\"external_references\":"+values+",\"valid\":"+valid+"}");
 }
 public static void main(String[] args)throws Exception {
  // mode key.pem xml attachment.bin [signature-method]
  String mode=args[0];XMLSignatureFactory f=XMLSignatureFactory.getInstance("DOM");Path attachment=Path.of(args[3]);
  if(mode.equals("sign-external")){signExternal(f,args);return;}
  if(mode.equals("verify-external")){verifyExternal(f,args);return;}
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
