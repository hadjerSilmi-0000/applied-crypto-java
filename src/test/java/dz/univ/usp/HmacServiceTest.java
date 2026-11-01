package dz.univ.usp;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class HmacServiceTest {

    private static final byte[] DATA =
            "{\"studentId\":\"S2026001\",\"grade\":15.5}".getBytes(StandardCharsets.UTF_8);

    // ---------- success cases ----------

    @Test void generatedKeyIsRandom256Bit() {
        byte[] k1 = HmacService.generateKey();
        byte[] k2 = HmacService.generateKey();
        assertEquals(32, k1.length);
        assertFalse(Arrays.equals(k1, k2));
    }

    @Test void tagHasHmacSha256Length() {
        assertEquals(32, HmacService.create(DATA, HmacService.generateKey()).length);
    }

    @Test void sameDataAndKeyGiveSameTag() {
        byte[] key = HmacService.generateKey();
        assertArrayEquals(HmacService.create(DATA, key), HmacService.create(DATA, key));
    }

    @Test void originalDataVerifies() {
        byte[] key = HmacService.generateKey();
        assertTrue(HmacService.verify(DATA, HmacService.create(DATA, key), key));
    }

    @Test void emptyDataCanBeAuthenticated() {
        byte[] key = HmacService.generateKey();
        assertTrue(HmacService.verify(new byte[0], HmacService.create(new byte[0], key), key));
    }

    @Test void matchesRfc4231TestVector() {   // official HMAC-SHA256 test case 2
        byte[] key = "Jefe".getBytes(StandardCharsets.UTF_8);
        byte[] data = "what do ya want for nothing?".getBytes(StandardCharsets.UTF_8);
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                HexFormat.of().formatHex(HmacService.create(data, key)));
    }

    // ---------- rejection cases ----------

    @Test void modifiedDataIsRejected() {
        byte[] key = HmacService.generateKey();
        byte[] tag = HmacService.create(DATA, key);
        byte[] modified = new String(DATA, StandardCharsets.UTF_8)
                .replace("15.5", "19.0").getBytes(StandardCharsets.UTF_8);
        assertFalse(HmacService.verify(modified, tag, key));
    }

    @Test void everySingleByteChangeInDataIsRejected() {
        byte[] key = HmacService.generateKey();
        byte[] tag = HmacService.create(DATA, key);
        for (int i = 0; i < DATA.length; i++) {
            byte[] copy = DATA.clone();
            copy[i] ^= 1;
            assertFalse(HmacService.verify(copy, tag, key), "byte " + i);
        }
    }

    @Test void modifiedTagIsRejected() {
        byte[] key = HmacService.generateKey();
        byte[] tag = HmacService.create(DATA, key);
        for (int i = 0; i < tag.length; i++) {
            byte[] bad = tag.clone();
            bad[i] ^= 1;
            assertFalse(HmacService.verify(DATA, bad, key), "tag byte " + i);
        }
    }

    @Test void incorrectKeyIsRejected() {
        byte[] tag = HmacService.create(DATA, HmacService.generateKey());
        assertFalse(HmacService.verify(DATA, tag, HmacService.generateKey()));
    }

    @Test void truncatedTagIsRejected() {
        byte[] key = HmacService.generateKey();
        byte[] tag = HmacService.create(DATA, key);
        for (int len : new int[]{0, 1, 16, 31}) {
            assertFalse(HmacService.verify(DATA, Arrays.copyOf(tag, len), key), "length " + len);
        }
    }

    @Test void extendedTagIsRejected() {
        byte[] key = HmacService.generateKey();
        byte[] tag = HmacService.create(DATA, key);
        assertFalse(HmacService.verify(DATA, Arrays.copyOf(tag, 33), key));
    }

    @Test void nullAndEmptyInputsAreRejectedSafely() {
        byte[] key = HmacService.generateKey();
        byte[] tag = HmacService.create(DATA, key);
        assertFalse(HmacService.verify(null, tag, key));
        assertFalse(HmacService.verify(DATA, null, key));
        assertFalse(HmacService.verify(DATA, tag, null));
        assertFalse(HmacService.verify(DATA, tag, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> HmacService.create(null, key));
        assertThrows(IllegalArgumentException.class, () -> HmacService.create(DATA, null));
        assertThrows(IllegalArgumentException.class, () -> HmacService.create(DATA, new byte[0]));
    }
}