package server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.ByteUtil;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class WPA2Controller {
    // cekor 1: sa konektirat so password, ako e uspesno sa generirat PMK(Pairwise master key)
    //

    private static final Logger logger = LogManager.getLogger(WPA2Controller.class.getName());

    private final String ssid = "TP-Link2024";
    private final String password = "jonus123";
    private byte[] ANonce;
    public String MAC_ADDRESS = "5A7FAB12D49E";
    byte[] packetNumber = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private String CLIENT_MAC_ADDRESS = "3A9B5E1D4C3A";
    private byte[] SNonce;
    private PTKWrapper PTK;


    byte[] connect(String password, String ssid, String clientMacAddress) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (!password.equals(this.password) || !ssid.equals(this.ssid)) {
            System.out.println("Invalid credentials");
            throw new IllegalArgumentException("Invalid credentials");
        }

        this.ANonce = CCMPImpl.generateNonce();
        this.CLIENT_MAC_ADDRESS = clientMacAddress;

        logger.info("Credentials are correct, commencing handshake");

        logger.info("First step of handshake: generate ANonce and send it to the client.");

        return this.ANonce; // prva poraka vo 4 way handshake
    }


    byte[] handshake(ClearTextFrame frame) throws Exception {
        this.SNonce = frame.get("nonce");

        byte[] PMK = CCMPImpl.computeKey(password, ssid.getBytes(), 256);
        this.PTK = HandshakeUtil.derivePTK(PMK,ANonce,SNonce,CLIENT_MAC_ADDRESS,MAC_ADDRESS);


        byte[] iv = getNewIV();

        String msg4way = ByteUtil.convertBytesToHex(SNonce) + ByteUtil.convertBytesToHex(ANonce)
                + CLIENT_MAC_ADDRESS + MAC_ADDRESS;

        byte[] MIC = CCMPImpl.generateMIC4Way(this.PTK.KCK, msg4way.getBytes());


        boolean status = CCMPImpl.validate(ByteUtil.convertBytesToHex(frame.get("mic")), ByteUtil.convertBytesToHex(MIC));

        logger.info("Third Step of Handshake[0] AP (Access Point): Calculate PMK");
        logger.info("Third Step of Handshake[1] AP (Access Point): Derive PTK from PMK");
        logger.info("Third Step of Handshake[2] AP (Access Point): Generate MIC using the PTK");
        logger.info("Third Step of Handshake[3] AP (Access Point): Compare the Received MIC with the Generated MIC to Ensure Data Integrity");
        logger.info("Third Step of Handshake[4] AP (Access Point): Send the MIC to server.Client for final Verification");

        if (status) {
            return MIC;
        } else {
            throw new Exception("ERROR: MIC DOES NOT MATCH");
        }
    }

    byte[] getNewIV(){
        ByteUtil.incrementBytes(packetNumber);
        byte[] iv = new byte[16];
        System.arraycopy(packetNumber, 0, iv, 0, 6);
        System.arraycopy(SNonce, 0, iv, 6, 10);

        return iv;
    }


    EncryptedFrame recieve(EncryptedFrame frame) throws Exception {
        //proverki tuka ako e s ok

        ByteUtil.incrementBytes(packetNumber);
        byte[] iv = new byte[16];
        System.arraycopy(packetNumber, 0, iv, 0, 6);
        System.arraycopy(SNonce, 0, iv, 6, 10);

        byte[] MIC = CCMPImpl.generateMIC(frame, PTK.TK, iv);

        byte[] msgMIC = frame.get("mic");


        boolean match = CCMPImpl.validate(ByteUtil.convertBytesToHex(MIC), ByteUtil.convertBytesToHex(msgMIC));

        if (match) {
            ClearTextFrame ctf = CCMPImpl.decrypt(frame, PTK.TK, iv);
            String decryptedMessage = new String(ctf.get("payload"));

            logger.info("CONTROLLER: Decrypted message: {}", decryptedMessage);

            String apRespMsg = "server.Client Mac Address: "  + CLIENT_MAC_ADDRESS + " Packet Number: " + ByteUtil.convertBytesToHex(packetNumber);
            ClearTextFrame fr = new ClearTextFrame();
            fr.set("payload",apRespMsg.getBytes());

            iv = getNewIV();

            EncryptedFrame resp = CCMPImpl.encrypt(fr,PTK.TK,iv);
            byte[] respMIC = CCMPImpl.generateMIC(resp, PTK.TK, iv);

            resp.set("mic",respMIC);

            return resp;

        } else {
            throw new SecurityException("ERROR: MIC DOES NOT MATCH");
        }
    }


}
