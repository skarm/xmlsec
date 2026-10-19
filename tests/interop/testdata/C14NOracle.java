/* Independent TEST oracle using the XMLDSig implementation bundled with the
 * JDK (Apache-derived). Not an application API or a Go dependency.
 * Protocol: tab-separated base64(XML), algorithm URI, base64(selection),
 * base64(prefix list). Selection: '-' / 'SUBTREE:<xpath>' / '<xpath node-set>'. */
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.*;
import javax.xml.xpath.*;
import org.w3c.dom.*;
import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;

public class C14NOracle {
    public static void main(String[] args) throws Exception {
        Init.init();
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setCoalescing(true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (String line; (line = input.readLine()) != null;) {
            try {
                String[] parts = line.split("\t", -1);
                if (parts.length != 4) throw new IllegalArgumentException("invalid test request");
                byte[] xml = Base64.getDecoder().decode(parts[0]);
                String selection = decode(parts[2]);
                String prefixes = decode(parts[3]);
                Document d = f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
                Canonicalizer c = Canonicalizer.getInstance(parts[1]);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                if (selection.equals("-")) {
                    if (prefixes.isEmpty()) c.canonicalizeSubtree(d, out);
                    else c.canonicalizeSubtree(d, prefixes, out);
                } else {
                    XPath xp = XPathFactory.newInstance().newXPath();
                    if (selection.startsWith("SUBTREE:")) {
                        Node n = (Node) xp.evaluate(selection.substring(8), d, XPathConstants.NODE);
                        if (n == null) throw new IllegalArgumentException("missing subtree");
                        if (prefixes.isEmpty()) c.canonicalizeSubtree(n, out);
                        else c.canonicalizeSubtree(n, prefixes, out);
                    } else {
                        NodeList list = (NodeList) xp.evaluate(selection, d, XPathConstants.NODESET);
                        Set<Node> set = new HashSet<>();
                        for (int i = 0; i < list.getLength(); i++) set.add(list.item(i));
                        if (prefixes.isEmpty()) c.canonicalizeXPathNodeSet(set, out);
                        else c.canonicalizeXPathNodeSet(set, prefixes, out);
                    }
                }
                System.out.println("OK\t" + Base64.getEncoder().encodeToString(out.toByteArray()));
            } catch (Exception e) {
                System.out.println("ERR\t" + Base64.getEncoder().encodeToString(e.toString().getBytes(StandardCharsets.UTF_8)));
            }
            System.out.flush();
        }
    }
    static String decode(String s) { return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8); }
}
