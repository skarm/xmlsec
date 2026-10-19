// Test-only independent JSR105 oracle. XSLT requires secureValidation=false;
// only the fixed local test programs are executed. NEVER deploy this helper.
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
public class TransformOracle {
 static final String DS=XMLSignature.XMLNS, F2="http://www.w3.org/2002/06/xmldsig-filter2", EXC="http://www.w3.org/2001/10/xml-exc-c14n#", XSL="http://www.w3.org/1999/XSL/Transform";
 static final Map<String,String> NS=Map.of("ds",DS,"xf",F2);
 static String stylesheet(){return "<xsl:stylesheet xmlns:xsl=\""+XSL+"\" xmlns:ds=\""+DS+"\" xmlns:xf=\""+F2+"\" version=\"1.0\"><xsl:output method=\"text\"/><xsl:template match=\"/\"><xsl:value-of select=\"//fixed\"/></xsl:template></xsl:stylesheet>";}
 static List<Transform> transforms(XMLSignatureFactory f,String kind)throws Exception{
  List<Transform> result=new ArrayList<>();
  if(kind.startsWith("xpath")){
   String x="not(ancestor-or-self::volatile)";
   if(kind.equals("xpath-context"))x+=" and position()=1 and last()=1";
   if(kind.equals("xpath-here"))x+=" and count(here()/ancestor::ds:Signature)=1";
   result.add(f.newTransform(Transform.XPATH,new XPathFilterParameterSpec(x,NS)));
  }else if(kind.startsWith("filter")){
   List<XPathType> xs=new ArrayList<>();
   if(kind.equals("filter-sequence"))xs.add(new XPathType("//payload",XPathType.Filter.INTERSECT,NS));
   xs.add(new XPathType(kind.equals("filter-here")?"here()/ancestor::ds:Signature/preceding-sibling::payload/volatile":"//volatile",XPathType.Filter.SUBTRACT,NS));
   if(kind.equals("filter-sequence"))xs.add(new XPathType("//volatile/keep",XPathType.Filter.UNION,NS));
   result.add(f.newTransform(Transform.XPATH2,new XPathFilter2ParameterSpec(xs)));
  }else if(kind.equals("xslt-text")){
   Document style=DetachedOracle.builder().parse(new java.io.ByteArrayInputStream(stylesheet().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
   result.add(f.newTransform(Transform.XSLT,new XSLTTransformParameterSpec(new DOMStructure(style.getDocumentElement()))));
  }else throw new IllegalArgumentException("case");
  if(!kind.startsWith("xslt"))result.add(f.newTransform(EXC,(TransformParameterSpec)null));
  return result;
 }
 public static void main(String[] args)throws Exception{
  String mode=args[0],kind=args[3];Path key=Path.of(args[1]),path=Path.of(args[2]);XMLSignatureFactory f=XMLSignatureFactory.getInstance("DOM");
  if(mode.equals("verify")){
   Document d=DetachedOracle.builder().parse(path.toFile());CoreOracle.ids(d.getDocumentElement());
   DOMValidateContext c=new DOMValidateContext(DetachedOracle.key(key,false),d.getElementsByTagNameNS(DS,"Signature").item(0));
   c.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.FALSE);c.setURIDereferencer(CoreOracle.resolver(f));
   XMLSignature s=f.unmarshalXMLSignature(c);boolean sv=s.getSignatureValue().validate(c);List<Boolean> refs=new ArrayList<>();for(Reference r:s.getSignedInfo().getReferences())refs.add(r.validate(c));
   System.out.println("{\"signature_value\":"+sv+",\"references\":"+refs+",\"valid\":"+s.validate(c)+"}");return;
  }
  if(!mode.equals("sign")&&!mode.equals("sign-bad"))throw new IllegalArgumentException("mode");
  String source="<r xmlns:ds=\""+DS+"\" xmlns:xf=\""+F2+"\"><payload ID=\"payload\"><fixed>SIGNED-VALUE</fixed><volatile>old-value<keep>KEEP</keep></volatile></payload></r>";
  Document d=DetachedOracle.builder().parse(new java.io.ByteArrayInputStream(source.getBytes(java.nio.charset.StandardCharsets.UTF_8)));CoreOracle.ids(d.getDocumentElement());
  DigestMethod dm=f.newDigestMethod(DigestMethod.SHA256,null);List<Reference> refs=new ArrayList<>();
  refs.add(f.newReference("#payload",dm,transforms(f,kind),null,null));
  refs.add(mode.equals("sign-bad")?f.newReference("#payload",dm,transforms(f,kind),null,null,new byte[32]):f.newReference("#payload",dm,transforms(f,kind),null,null));
  SignedInfo si=f.newSignedInfo(f.newCanonicalizationMethod(EXC,(C14NMethodParameterSpec)null),f.newSignatureMethod(SignatureMethod.RSA_SHA256,null),refs);
  DOMSignContext c=new DOMSignContext(DetachedOracle.key(key,true),d.getDocumentElement());c.setDefaultNamespacePrefix("ds");c.putNamespacePrefix(F2,"xf");c.setProperty("org.jcp.xml.dsig.secureValidation",Boolean.FALSE);c.setURIDereferencer(CoreOracle.resolver(f));
  f.newXMLSignature(si,null).sign(c);
  TransformerFactory tf=TransformerFactory.newInstance();tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");Transformer t=tf.newTransformer();t.setOutputProperty(OutputKeys.INDENT,"no");t.transform(new DOMSource(d),new StreamResult(path.toFile()));System.out.println("signed");
 }
}
