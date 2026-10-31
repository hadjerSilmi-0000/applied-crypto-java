package dz.univ.usp;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/** Stored format: $pbkdf2-sha256$i=<iterations>$<salt b64>$<hash b64> */
public final class Pbkdf2PasswordService implements PasswordService {

    private static final String PREFIX = "pbkdf2-sha256";
    private static final int ITERATIONS = 600_000;
    private static final int MAX_ITERATIONS = 10_000_000; // reject absurd values (DoS)
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;

    private final SecureRandom random = new SecureRandom();

    private record Parsed(int iterations, byte[] salt, byte[] hash) {}

    @Override
    public String hash(String password) {
        if (password == null) throw new IllegalArgumentException("password must not be null");
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS, HASH_BYTES);
        Base64.Encoder enc = Base64.getEncoder().withoutPadding();
        return "$" + PREFIX + "$i=" + ITERATIONS + "$"
                + enc.encodeToString(salt) + "$" + enc.encodeToString(hash);
    }

    @Override
    public boolean verify(String password, String storedHash) {
        if (password == null || storedHash == null) return false;
        Parsed p = parse(storedHash);
        if (p == null) return false;
        byte[] actual = derive(password, p.salt(), p.iterations(), p.hash().length);
        return MessageDigest.isEqual(actual, p.hash());
    }

    @Override
    public boolean needsRehash(String storedHash) {
        Parsed p = (storedHash == null) ? null : parse(storedHash);
        return p == null
                || p.iterations() < ITERATIONS
                || p.salt().length < SALT_BYTES
                || p.hash().length < HASH_BYTES;
    }

    private static byte[] derive(String password, byte[] salt, int iterations, int bytes) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, bytes * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Returns null for any malformed input. */
    private static Parsed parse(String s) {
        try {
            String[] parts = s.split("\\$", -1);
            if (parts.length != 5 || !parts[0].isEmpty() || !parts[1].equals(PREFIX)
                    || !parts[2].startsWith("i=")) return null;
            int iterations = Integer.parseInt(parts[2].substring(2));
            if (iterations <= 0 || iterations > MAX_ITERATIONS) return null;
            byte[] salt = Base64.getDecoder().decode(parts[3]);
            byte[] hash = Base64.getDecoder().decode(parts[4]);
            if (salt.length < 8 || hash.length < 16) return null;
            return new Parsed(iterations, salt, hash);
        } catch (IllegalArgumentException e) { // NumberFormatException and bad Base64
            return null;
        }
    }
}