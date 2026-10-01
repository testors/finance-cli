// Standard JDK value comparison only. No Android or service SDK execution.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

class LocalErrorValueVectors {
    public static void main(String[] args) throws Exception {
        HashMap<String, String> fields = new HashMap<>();
        for (String key : new String[]{"CODE_APP_INFO", "CODE_GUARD_OS_RESULT",
                "CODE_RESPONSE", "CG_VALIDTO", "CG_SIGNATURE"}) fields.put(key, null);
        System.out.println(String.join(",", fields.keySet()));
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        String line;
        while ((line = reader.readLine()) != null) {
            int split = line.indexOf(' ');
            long now = Long.parseLong(line.substring(0, split));
            String units = line.substring(split+1);
            StringBuilder input = new StringBuilder();
            for (int i = 0; i < units.length(); i += 4)
                input.append((char)Integer.parseInt(units.substring(i, i+4), 16));
            String detail = input.toString();
            for (int i = 0; i < 2; i++) {
                if (detail.length() > 200)
                    detail = detail.substring(0, 100) + "--" + detail.substring(detail.length()-100);
            }
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < detail.length(); i++) output.append(String.format("%04x", (int)detail.charAt(i)));
            System.out.println(Long.toString(now + 1800000L) + ":" + output);
        }
    }
}
