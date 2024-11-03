package server;

import util.ByteUtil;

public class HandshakeUtil {
    static PTKWrapper derivePTK(byte[] pmk,byte[] ANonce,byte[] SNonce,String CLIENT_MAC_ADDRESS,String AP_MAC_ADDRESS) throws Exception {
        String pmkHex = ByteUtil.convertBytesToHex(pmk);
        String saltHex = ByteUtil.convertBytesToHex(ANonce) +
                ByteUtil.convertBytesToHex(SNonce) +
                CLIENT_MAC_ADDRESS + AP_MAC_ADDRESS;

        return new PTKWrapper(CCMPImpl.computeKey(pmkHex, saltHex.getBytes(), 384));
    }
}
