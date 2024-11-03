package util;

public class ByteUtil {

    public static void incrementBytes(byte[] pn) {
        for (int i = pn.length - 1; i >= 0; i--) {
            pn[i]++;
            if (pn[i] != 0) {
                break;
            }
        }
    }

    public static String convertBytesToHex(byte[] bytes){
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }

}
