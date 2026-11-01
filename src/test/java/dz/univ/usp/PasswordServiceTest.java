package dz.univ.usp;

import org.junit.jupiter.api.Test;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class PasswordServiceTest {

    private final PasswordService svc = new Pbkdf2PasswordService();

    /** Builds a valid hash with a weaker (older) iteration count, like one stored years ago. */
    private static String legacyHash(String password, int iterations) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        byte[] h = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        Base64.Encoder e = Base64.getEncoder().withoutPadding();
        return "$pbkdf2-sha256$i=" + iterations + "$" + e.encodeToString(salt) + "$" + e.encodeToString(h);
    }

    // Experiments 1 and 2: same password hashed twice, the hashes differ
    @Test void samePasswordGivesDifferentHashes() {
        String h1 = svc.hash("S3cret!pass");
        String h2 = svc.hash("S3cret!pass");
        assertNotEquals(h1, h2);
    }

    @Test void hashHasExpectedFormatAndHidesPassword() {
        String h = svc.hash("my-password");
        assertTrue(h.startsWith("$pbkdf2-sha256$i=600000$"));
        assertEquals(5, h.split("\\$").length);
        assertFalse(h.contains("my-password"));
    }

    // Experiment 3: correct password
    @Test void correctPasswordVerifiesAgainstBothHashes() {
        String h1 = svc.hash("correct horse");
        String h2 = svc.hash("correct horse");
        assertTrue(svc.verify("correct horse", h1));
        assertTrue(svc.verify("correct horse", h2));
    }

    // Experiment 4: wrong password
    @Test void wrongPasswordIsRejected() {
        String h = svc.hash("correct horse");
        assertFalse(svc.verify("wrong horse", h));
        assertFalse(svc.verify("correct horse ", h));   // trailing space
        assertFalse(svc.verify("", h));
        assertFalse(svc.verify(null, h));
    }

    // Experiment 5: malformed hashes are rejected without exceptions
    @Test void malformedHashesAreRejectedSafely() {
        String valid = svc.hash("pw");
        String[] p = valid.split("\\$");   // "", prefix, i=..., salt, hash
        String[] bad = {
                null, "", "garbage", "$$$$", "a$b$c$d",
                "$pbkdf2-sha256$i=abc$" + p[3] + "$" + p[4],          // cost is not a number
                "$pbkdf2-sha256$i=0$" + p[3] + "$" + p[4],            // cost is zero
                "$pbkdf2-sha256$i=-5$" + p[3] + "$" + p[4],           // negative cost
                "$pbkdf2-sha256$i=2000000000$" + p[3] + "$" + p[4],   // absurd cost (DoS)
                "$pbkdf2-sha256$i=600000$!!!$!!!",                    // invalid Base64
                "$pbkdf2-sha256$i=600000$AAAA$" + p[4],               // salt too short
                "$md5$i=600000$" + p[3] + "$" + p[4],                 // wrong algorithm
                valid.substring(0, valid.length() - 10)               // truncated
        };
        for (String b : bad) {
            assertDoesNotThrow(() -> svc.verify("pw", b));
            assertFalse(svc.verify("pw", b), "should reject: " + b);
        }
    }

    @Test void nullPasswordCannotBeHashed() {
        assertThrows(IllegalArgumentException.class, () -> svc.hash(null));
    }

    // Experiment 6: needsRehash
    @Test void currentHashDoesNotNeedRehash() {
        assertFalse(svc.needsRehash(svc.hash("pw")));
    }

    @Test void outdatedHashNeedsRehashButStillVerifies() throws Exception {
        String old = legacyHash("pw", 100_000);
        assertTrue(svc.needsRehash(old));
        assertTrue(svc.verify("pw", old));   // old hashes keep working with their own cost
    }

    @Test void malformedHashNeedsRehash() {
        assertTrue(svc.needsRehash("garbage"));
        assertTrue(svc.needsRehash(null));
    }
}