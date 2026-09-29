// JDK reference for URL encoding.
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

class JavaFormReference {
    public static void main(String[] args) {
        String[] values = {"+/8=", "A+B/C==", " ~*_-.한글\n", "", "😀", "\ud800"};
        for (String value : values) {
            System.out.println(URLEncoder.encode(value.replace("+", "%2B"), StandardCharsets.UTF_8));
        }
    }
}
