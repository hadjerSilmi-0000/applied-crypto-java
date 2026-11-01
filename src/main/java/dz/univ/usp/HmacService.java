package dz.univ.usp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

public final class HmacService {

 private static final String ALGORITHM = "HmacSHA256";
 private static final int KEY_BYTES = 32;   // 256-bit random key
 private static final int TAG_BYTES = 32;   // HMAC-SHA256 output size
 private static final SecureRandom RANDOM = new SecureRandom();

 private HmacService() {}

 /** Generates a fresh random 256-bit key (never hardcode keys). */
 public static byte[] generateKey() {
  byte[] key = new byte[KEY_BYTES];
  RANDOM.nextBytes(key);
  return key;
 }

 /** Computes HMAC-SHA256(key, data). */
 public static byte[] create(byte[] data, byte[] key) {
  if (data == null || key == null || key.length == 0)
   throw new IllegalArgumentException("data and key must not be null or empty");
  try {
   Mac mac = Mac.getInstance(ALGORITHM);
   mac.init(new SecretKeySpec(key, ALGORITHM));
   return mac.doFinal(data);
  } catch (GeneralSecurityException e) {
   throw new IllegalStateException("HmacSHA256 unavailable", e);
  }
 }

 /** Returns true only if tag is the correct HMAC of data under key. */
 public static boolean verify(byte[] data, byte[] tag, byte[] key) {
  if (data == null || tag == null || key == null || key.length == 0) return false;
  if (tag.length != TAG_BYTES) return false;             // truncated or padded tag
  byte[] expected = create(data, key);
  return MessageDigest.isEqual(expected, tag);           // constant-time compare
 }
}