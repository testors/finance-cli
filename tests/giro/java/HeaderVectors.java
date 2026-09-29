import java.nio.charset.StandardCharsets;
import java.util.*;

// Synthetic JDK container/comparator cross-check, not Android/app execution.
public class HeaderVectors {
    static String decode(String s) {
        return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
    }
    static String encode(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
    public static void main(String[] args) {
        Map<String,List<String>> map = new TreeMap<>(Comparator.nullsFirst(String.CASE_INSENSITIVE_ORDER));
        for (String arg : args) {
            String[] pair = arg.split("\\.", -1);
            String key = decode(pair[0]), value = decode(pair[1]);
            List<String> values = new ArrayList<>(map.getOrDefault(key, List.of()));
            values.add(value);
            map.put(key, List.copyOf(values));
        }
        map.put(null, List.of("HTTP/1.1 200 synthetic"));
        for (var entry : map.entrySet()) {
            System.out.println(encode(entry.getKey() == null ? "<status>" : entry.getKey())
                + ":" + encode(String.join("\0",entry.getValue())));
        }
    }
}
