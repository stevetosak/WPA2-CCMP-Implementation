package server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.ByteUtil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class CCMPImpl {

    private final Logger logger = LogManager.getLogger(CCMPImpl.class.getName());

    // ova vo dr klasa
    public static byte[] generateHandshakeMic(byte[] kck, byte[] message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(kck, "RAW");

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(keySpec);

        byte[] mic = mac.doFinal(message);

        byte[] micResult = new byte[8];
        System.arraycopy(mic, 0, micResult, 0, 8);
        return micResult;
    }


    public static byte[] generateMIC(byte[] msg,byte[] key,byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //aes-cbc
        System.arraycopy(new byte[]{0x03,0x03,0x03},0,iv,13,3);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        return encryptCipher.doFinal(msg);
    }

    public static byte[] decrypt(byte[] msg,byte[] key,byte[] iv) throws Exception{

        System.arraycopy(new byte[]{0x00,0x00,0x00},0,iv,13,3);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher decryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = decryptCipher.doFinal(msg);


        return decryptedBytes;
    }

    public static byte[] encrypt(byte[]msg,byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.arraycopy(new byte[]{0x00,0x00,0x00},0,iv,13,3);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher encryptCipher = Cipher.getInstance("AES/CTR/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = encryptCipher.doFinal(msg);

//        EncryptedFrame encryptedFrame = new EncryptedFrame();
//        encryptedFrame.set("payload",encryptedBytes);

        return encryptedBytes;
    }

    public static byte[] computeKey(String password, byte[] salt,int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt,4096,keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded(); //pmk
    }
    public static byte[] generateNonce(){
        SecureRandom sr = new SecureRandom();
        byte[] nonce = new byte[32];
        sr.nextBytes(nonce);
        return nonce;
    }

    public static boolean validate(String mic1,String mic2){
        return mic1.equals(mic2);
    }


}
