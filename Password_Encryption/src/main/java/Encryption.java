import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class Encryption {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SALT = "84B03D034B409D4E";

    public static String encode(String secret, char[] cipherKey) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(cipherKey, SALT.getBytes(StandardCharsets.UTF_8), 65536, 128);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);

        byte[] iv = new byte[cipher.getBlockSize()];

        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);
        byte[] encryptedVal = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));
        byte[] encodedVal = new Base64().encode(encryptedVal);

        return new String(encodedVal, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {

        String encryptedVal;
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        char passwordArray[] = console.readPassword("Please Enter a password you want to use for the encryption: ");
        encryptedVal = encode(args[0], passwordArray);
        Files.write(Paths.get("./encrypted_password.txt"), encryptedVal.getBytes());
        Arrays.fill(passwordArray, (char)0);
    }
}