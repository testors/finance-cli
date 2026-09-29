// Independent standard-JDK oracle over synthetic DER names. No Android/SDK.
import javax.security.auth.x500.X500Principal;
import java.util.HexFormat;

class PrincipalVectors {
    public static void main(String[] args) {
        for (String hex : args) {
            System.out.println(new X500Principal(HexFormat.of().parseHex(hex))
                .getName(X500Principal.CANONICAL));
        }
    }
}
