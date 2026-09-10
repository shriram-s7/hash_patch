import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        byte[] plaintext = "CBOM_TEST".getBytes();

        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        KeyPair rsaKeys = rsaGenerator.generateKeyPair();

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic());
        byte[] rsaEncrypted = rsa.doFinal(plaintext);

        KeyGenerator aesGenerator = KeyGenerator.getInstance("AES");
        aesGenerator.init(128);
        SecretKey aesKey = aesGenerator.generateKey();

        byte[] aesIv = new byte[12];
        new SecureRandom().nextBytes(aesIv);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, aesIv));
        byte[] aesEncrypted = aes.doFinal(rsaEncrypted);

        KeyGenerator chaChaGenerator = KeyGenerator.getInstance("ChaCha20");
        SecretKey chaChaKey = chaChaGenerator.generateKey();

        byte[] chaChaNonce = new byte[12];
        new SecureRandom().nextBytes(chaChaNonce);

        Cipher chaCha = Cipher.getInstance("ChaCha20-Poly1305");
        chaCha.init(Cipher.ENCRYPT_MODE, chaChaKey, new IvParameterSpec(chaChaNonce));
        byte[] finalEncrypted = chaCha.doFinal(aesEncrypted);

        internalEncrypt(plaintext);

        System.out.println(Base64.getEncoder().encodeToString(finalEncrypted));
    }

    private static byte[] internalEncrypt(byte[] input) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("Blowfish");
        generator.init(128);
        SecretKey key = generator.generateKey();

        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        byte[] iv = new byte[8];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(input);
    }
}
