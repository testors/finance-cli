// Independent STANDARD JDK vectors over synthetic inputs. No Android/SDK code.
import java.net.HttpCookie;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.stream.Collectors;

class HttpValueVectors {
    public static void main(String[] args) {
        Locale.setDefault(Locale.US);
        for (int i=1; i<args.length; i++) {
            if (args[0].equals("double")) {
                System.out.println(Double.toString(Double.parseDouble(args[i])));
            } else if (args[0].equals("bits")) {
                System.out.println(Long.toUnsignedString(Double.doubleToRawLongBits(Double.parseDouble(args[i]))));
            } else {
                String header = new String(Base64.getDecoder().decode(args[i]), StandardCharsets.UTF_8);
                String value = HttpCookie.parse(header).stream().map(HttpCookie::toString).collect(Collectors.joining("\n"));
                System.out.println(Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)));
            }
        }
    }
}
