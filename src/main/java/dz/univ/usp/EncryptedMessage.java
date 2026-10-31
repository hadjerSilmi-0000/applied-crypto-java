package dz.univ.usp;
public record EncryptedMessage(int version,byte[] iv,byte[] ciphertext,byte[] aad) {}