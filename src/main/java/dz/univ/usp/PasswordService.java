package dz.univ.usp;
public interface PasswordService { String hash(String password); boolean verify(String password,String storedHash); boolean needsRehash(String storedHash); }