// Independent JDK XMLDSig implementation of the statically observed Android
// DSXmlService signature profile.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.*;

public class InvoiceSigner {
    static final String DS = XMLSignature.XMLNS;
    static final String XPATH = "not(self::*[name()='TaxInvoice'] | ancestor-or-self::*[name()='ExchangedDocument'] | ancestor-or-self::ds:Signature)";
    static byte[] read(BufferedReader in) throws Exception {
        return Base64.getDecoder().decode(in.readLine());
    }
    public static void main(String[] args) {
        try { run(); }
        catch (Exception e) {
            // Parser/signing exceptions can quote document contents. Never log them.
            System.err.println("XML signature could not be completed ("+e.getClass().getSimpleName()+")");
            System.exit(2);
        }
    }
    static void run() throws Exception {
        var in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        var cert = (X509Certificate)CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(read(in)));
        byte[] keyBytes = read(in), xml = read(in);
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        var builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
        var document = builder.parse(new ByteArrayInputStream(xml));
        if (keyBytes.length == 0) {
            var signature = document.getElementsByTagNameNS(DS,"Signature").item(0);
            var context = new DOMValidateContext(cert.getPublicKey(), signature);
            context.setProperty("org.jcp.xml.dsig.secureValidation", false);
            boolean valid = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context).validate(context);
            System.out.println(valid ? "VALID" : "INVALID");
            return;
        }
        var key = KeyFactory.getInstance(cert.getPublicKey().getAlgorithm())
            .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        if (!key.getAlgorithm().equalsIgnoreCase("RSA"))
            throw new UnsupportedOperationException("Unimplemented non-RSA original profile");
        boolean sha256 = cert.getSigAlgName().toLowerCase(Locale.ROOT).startsWith("sha256withrsa")
            || cert.getSigAlgOID().equals("1.2.840.113549.1.1.11");
        var ds = XMLSignatureFactory.getInstance("DOM");
        var transforms = List.of(
            ds.newTransform(CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec)null),
            ds.newTransform(Transform.XPATH, new XPathFilterParameterSpec(XPATH, Map.of("ds", DS))));
        var reference = ds.newReference("",ds.newDigestMethod(sha256 ? DigestMethod.SHA256 : DigestMethod.SHA1,null),transforms,null,null);
        var info = ds.newSignedInfo(ds.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
            (C14NMethodParameterSpec)null),ds.newSignatureMethod(sha256 ? SignatureMethod.RSA_SHA256 : SignatureMethod.RSA_SHA1,null),List.of(reference));
        var keys = ds.getKeyInfoFactory();
        var signature = ds.newXMLSignature(info,keys.newKeyInfo(List.of(keys.newX509Data(List.of(cert)))));
        var context = new DOMSignContext(key, document.getElementsByTagName("TaxInvoice").item(0),
            document.getElementsByTagName("TaxInvoiceDocument").item(0));
        context.setDefaultNamespacePrefix("ds");
        context.setProperty("org.jcp.xml.dsig.secureValidation", false);
        signature.sign(context);
        var tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        var output = new ByteArrayOutputStream();
        tf.newTransformer().transform(new DOMSource(document),new StreamResult(output));
        System.out.println(Base64.getEncoder().encodeToString(output.toByteArray()));
        Arrays.fill(keyBytes,(byte)0);
    }
}
