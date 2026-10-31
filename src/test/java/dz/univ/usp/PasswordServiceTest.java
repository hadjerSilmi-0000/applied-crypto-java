package dz.univ.usp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PasswordServiceTest {

    private final PasswordService svc = new Pbkdf2PasswordService();
    private static final String PW = "Correct-Horse-Battery-9";

    @Test
    void samePasswordTwiceProducesDifferentHashes() {            // experiments 1 + 2
        String h1 = svc.hash(PW), h2 = svc.hash(PW);
        System.out.println("hash1 = " + h1);
        System.out.println("hash2 = " + h2);
        assertNotEquals(h1, h2);
    }

    @Test
    void correctPasswordVerifies() {                              // experiment 3
        assertTrue(svc.verify(PW, svc.hash(PW)));
    }

    @Test
    void wrongPasswordRejected() {                                // experiment 4
        assertFalse(svc.verify("wrong-password", svc.hash(PW)));
    }

    @ParameterizedTest                                            // experiment 5
    @ValueSource(strings = {
            "", "garbage", "$md5$i=1$AAAA$BBBB",
            "$pbkdf2-sha256$i=abc$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
            "$pbkdf2-sha256$i=600000$!!!$???",
            "$pbkdf2-sha256$i=600000$AAAA"
    })
    void malformedHashRejectedSafely(String bad) {
        assertDoesNotThrow(() -> assertFalse(svc.verify(PW, bad)));
    }

    @Test
    void nullInputsRejectedSafely() {
        assertFalse(svc.verify(null, svc.hash(PW)));
        assertFalse(svc.verify(PW, null));
        assertThrows(IllegalArgumentException.class, () -> svc.hash(null));
    }

    @Test
    void needsRehashBehaviour() {                                 // experiment 6
        assertFalse(svc.needsRehash(svc.hash(PW)));               // current parameters
        Base64.Encoder enc = Base64.getEncoder().withoutPadding();
        String outdated = "$pbkdf2-sha256$i=1000$"
                + enc.encodeToString(new byte[16]) + "$" + enc.encodeToString(new byte[32]);
        assertTrue(svc.needsRehash(outdated));                    // weaker iteration count
        assertTrue(svc.needsRehash("garbage"));                   // malformed
        assertTrue(svc.needsRehash(null));
    }

    @Test
    void storedHashDoesNotContainPassword() {
        assertFalse(svc.hash(PW).contains(PW));
    }
}