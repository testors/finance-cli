import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HexFormat;

/** Development-only parsing/encoding/digest comparison, with no trust checks. */
class SignerCertificateVector {
    public static void main(String[] args) throws Exception {
        var factory = CertificateFactory.getInstance("X.509");
        for (String line : new String(System.in.readAllBytes(), java.nio.charset.StandardCharsets.US_ASCII).split("\\n")) {
            if (line.isEmpty()) continue;
            var stream = new ByteArrayInputStream(Base64.getDecoder().decode(line));
            var cert = factory.generateCertificate(stream);
            byte[] der = cert.getEncoded();
            System.out.println(Base64.getEncoder().encodeToString(der) + ":"
                + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der)) + ":"
                + stream.available());
        }
    }
}
