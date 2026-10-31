package dz.univ.usp;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class FileIntegrity {
    private FileIntegrity() {}

    public static String sha256Hex(Path file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(md.digest(Files.readAllBytes(file)));
    }

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "data/grades.json");
        String digest = sha256Hex(file);
        System.out.println("SHA-256: " + digest);
        Files.writeString(Path.of(file + ".sha256"),
                digest + "  " + file.getFileName() + "\n");
    }
}