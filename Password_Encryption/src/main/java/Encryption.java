import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

public class Encryption {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    public static String encode(String secret,
                                String cipherKey)
            throws Exception {

        SecretKey key = new SecretKeySpec(cipherKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        byte[] iv = new byte[cipher.getBlockSize()];

        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
        byte[] encryptedVal = cipher.doFinal(secret.getBytes("UTF-8"));
        byte[] encodedVal = new Base64().encode(encryptedVal);

        return new String(encodedVal, "UTF-8");
    }

    public static void main (String[] args) throws Exception{
        String encryptedVal;
        encryptedVal = encode(args[0], args[1]);
        Files.write(Paths.get("../secret_key.txt"), encryptedVal.getBytes());
    }
}
