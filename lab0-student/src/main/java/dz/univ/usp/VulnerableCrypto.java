package dz.univ.usp;
import javax.crypto.Cipher; import javax.crypto.spec.SecretKeySpec; import java.nio.charset.StandardCharsets; import java.security.MessageDigest; import java.util.Base64; import java.util.Random;
public final class VulnerableCrypto {
 private static final String KEY="university-secret-key";
 private VulnerableCrypto() {}
 public static String hashPassword(String p)throws Exception{return Base64.getEncoder().encodeToString(MessageDigest.getInstance("MD5").digest(p.getBytes(StandardCharsets.UTF_8)));}
 public static String generateToken(){return Integer.toString(100000+new Random().nextInt(900000));}
 public static String encrypt(String p)throws Exception{Cipher c=Cipher.getInstance("AES/ECB/PKCS5Padding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8),"AES"));return Base64.getEncoder().encodeToString(c.doFinal(p.getBytes(StandardCharsets.UTF_8)));}
 public static String createMac(String d)throws Exception{return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(d.getBytes(StandardCharsets.UTF_8)));}
}