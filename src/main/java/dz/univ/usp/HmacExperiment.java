package dz.univ.usp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

public final class HmacExperiment {

    public static void main(String[] args) throws Exception {
        HexFormat hex = HexFormat.of();
        byte[] data = Files.readAllBytes(Path.of("data/grades.json"));
        String text = new String(data, StandardCharsets.UTF_8);
        if (!text.contains("15.5"))
            throw new IllegalStateException("grades.json must contain 15.5 (restore the original file)");

        byte[] key = HmacService.generateKey();
        System.out.println("Key: random, " + key.length + " bytes (a real key is never printed)");

        // Experiment 1: calculate the HMAC
        byte[] tag = HmacService.create(data, key);
        System.out.println("\n1. HMAC of grades.json : " + hex.formatHex(tag));
        System.out.println("   tag length          : " + tag.length + " bytes");

        // Experiment 2: verify the original file
        System.out.println("\n2. Original file      -> " + HmacService.verify(data, tag, key) + "   (expected true)");

        // Experiments 3 and 4: modify the file, then verify
        byte[] modified = text.replace("15.5", "19.0").getBytes(StandardCharsets.UTF_8);
        System.out.println("\n3. File modified: grade 15.5 -> 19.0");
        System.out.println("4. Modified file      -> " + HmacService.verify(modified, tag, key) + "  (expected false)");

        // Experiment 5: modify the tag (flip one bit)
        byte[] badTag = tag.clone();
        badTag[0] ^= 1;
        System.out.println("\n5. Tag modified (1 bit flipped): " + hex.formatHex(badTag));
        System.out.println("   Modified tag       -> " + HmacService.verify(data, badTag, key) + "  (expected false)");

        // Experiment 6: incorrect key
        byte[] wrongKey = HmacService.generateKey();
        System.out.println("\n6. Wrong key          -> " + HmacService.verify(data, tag, wrongKey) + "  (expected false)");

        // Experiment 7: truncated tag
        byte[] shortTag = Arrays.copyOf(tag, 16);
        System.out.println("\n7. Truncated tag (16 of 32 bytes) -> " + HmacService.verify(data, shortTag, key) + "  (expected false)");
    }
}