import java.io.*;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Development-only modified UTF vectors; no Android or native library. */
class JniStringValueVectors {
    static byte[] encoded(String text) throws Exception {
        var bytes = new ByteArrayOutputStream();
        new DataOutputStream(bytes).writeUTF(text);
        return bytes.toByteArray();
    }
    static String units(String text) {
        var result = new StringBuilder();
        for (char c : text.toCharArray()) result.append(String.format("%04x", (int)c));
        return result.toString();
    }
    public static void main(String[] args) throws Exception {
        char[][] samples = {{}, {'A',0,'B'}, {0x7f,0x80,0x7ff,0x800,0xffff},
            {0xd800}, {0xdc00}, {0xd83d,0xde00}, {0xd800,'A',0xdc00}, {0xd55c,0xae00}};
        for (char[] chars : samples) {
            String input = new String(chars);
            byte[] wire = encoded(input);
            String output = new DataInputStream(new ByteArrayInputStream(wire)).readUTF();
            if (!input.equals(output)) throw new AssertionError("modified UTF roundtrip");
            System.out.println(units(output) + ":" + HexFormat.of().formatHex(wire, 2, wire.length));
        }
        var digest = MessageDigest.getInstance("SHA-256");
        for (int i=0; i<65536; i++) digest.update(encoded(String.valueOf((char)i)));
        System.out.println("all-units:" + HexFormat.of().formatHex(digest.digest()));
    }
}
