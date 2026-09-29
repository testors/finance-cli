// Synthetic standard JDK arithmetic.
class RclVectors {
    public static void main(String[] args) {
        System.out.println(((Number) Long.valueOf(4294967307L)).intValue());
        System.out.println((int) Double.parseDouble("4294967307"));
        System.out.println(((Number) Long.valueOf(Long.MAX_VALUE)).intValue());
        System.out.println(((Number) Double.valueOf(11.75)).intValue());
        System.out.println(((Number) Double.valueOf(-11.75)).intValue());
        System.out.println((int) Double.parseDouble("NaN"));
        System.out.println((int) Double.parseDouble("Infinity"));
        System.out.println((int) Double.parseDouble("-Infinity"));
        System.out.println((int) Double.parseDouble(" 0x1.8p3f "));
        System.out.println("true".equalsIgnoreCase("TrUe"));
        System.out.println("true".equalsIgnoreCase(" true "));
        System.out.println(!"false".equalsIgnoreCase("fal\u017fe"));
    }
}
