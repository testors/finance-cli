// Standard JDK cross-decryption of synthetic development inputs only.
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

class ExchangeKeyVector {
    public static void main(String[] args) throws Exception {
        var lines = new String(System.in.readAllBytes(), java.nio.charset.StandardCharsets.US_ASCII).split("\n");
        var base64 = Base64.getDecoder();
        var privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(base64.decode(lines[0])));
        var certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(base64.decode(lines[1])));
        var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        var plain = cipher.doFinal(base64.decode(lines[2]));
        cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
        System.out.println(Base64.getEncoder().encodeToString(plain));
        System.out.println(Base64.getEncoder().encodeToString(cipher.doFinal(plain)));
    }
}
