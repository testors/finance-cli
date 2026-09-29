// Independent Bouncy Castle verifier.
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CmsReference {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        var bare = SignedData.getInstance(ASN1Primitive.fromByteArray(Files.readAllBytes(Path.of(args[0]))));
        var message = new CMSSignedData(new ContentInfo(CMSObjectIdentifiers.signedData, bare));
        if (((byte[]) message.getSignedContent().getContent()).length != 0)
            throw new AssertionError("Expected empty content");
        for (SignerInformation signer : message.getSignerInfos().getSigners()) {
            X509CertificateHolder certificate = (X509CertificateHolder)
                message.getCertificates().getMatches(signer.getSID()).iterator().next();
            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate)))
                throw new AssertionError("Signature verification failed");
        }
        System.out.println("Bouncy Castle: bare SignedData parsed, empty content and RSA signature verified");
    }
}
