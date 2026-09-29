// Independent JDK-library comparison using synthetic public seeds only.
// Does not load Android classes, Giro/CodeGuard libraries, files or sockets.
import java.util.HexFormat;
import java.util.Random;

class RandomVectors {
    public static void main(String[] args) {
        for (String arg : args) {
            Random random = new Random();
            random.setSeed(Long.parseLong(arg));
            byte[] key = new byte[16];
            random.nextBytes(key);
            System.out.println(HexFormat.of().formatHex(key));
        }
    }
}
