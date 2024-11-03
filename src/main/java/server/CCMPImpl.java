package server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class CCMPImpl {

    private final Logger logger = LogManager.getLogger(CCMPImpl.class.getName());

    // ova vo dr klasa
    public static byte[] generateMIC4Way(byte[] kck, byte[] message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(kck, "RAW");

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(keySpec);

        byte[] mic = mac.doFinal(message);

        byte[] micResult = new byte[8];
        System.arraycopy(mic, 0, micResult, 0, 8);
        return micResult;
    }


    static byte[] generateMIC(Frame frame,byte[] key,byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //aes-cbc
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        return encryptCipher.doFinal(frame.get("payload"));
    }

    static ClearTextFrame decrypt(EncryptedFrame frame,byte[] key,byte[] iv) throws Exception{

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher decryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = decryptCipher.doFinal(frame.get("payload"));

        String decryptedText = new String(decryptedBytes);
        System.out.println("Decrypted Text: " + decryptedText);

        ClearTextFrame resp = new ClearTextFrame();
        resp.set("payload",decryptedText.getBytes(StandardCharsets.UTF_8));
        return resp;
    }

    static EncryptedFrame encrypt(ClearTextFrame frame,byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);


        Cipher encryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = encryptCipher.doFinal(frame.get("payload"));

        EncryptedFrame encryptedFrame = new EncryptedFrame();
        encryptedFrame.set("payload",encryptedBytes);

        return encryptedFrame;
    }

    static byte[] computeKey(String password, byte[] salt,int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt,4096,keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded(); //pmk
    }
    static byte[] generateNonce(){
        SecureRandom sr = new SecureRandom();
        byte[] nonce = new byte[32];
        sr.nextBytes(nonce);
        return nonce;
    }

    static boolean validate(String mic1,String mic2){
        return mic1.equals(mic2);
    }


}
