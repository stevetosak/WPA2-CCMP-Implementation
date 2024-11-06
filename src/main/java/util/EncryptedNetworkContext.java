package util;

import org.apache.logging.log4j.Logger;
import server.CCMPImpl;
import server.DataPacket;
import server.PTKWrapper;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class EncryptedNetworkContext {

    List<String> receivedPackets = new ArrayList<>();

    PTKWrapper PTK;
    String CLIENT_MAC_ADDRESS;
    String AP_MAC_ADDRESS;
    byte[] packetNumber;

    Logger logger;


    public EncryptedNetworkContext(PTKWrapper PTK, String CLIENT_MAC_ADDRESS, String AP_MAC_ADDRESS,byte[] packetNumber,Logger logger) {
        this.PTK = PTK;
        this.CLIENT_MAC_ADDRESS = CLIENT_MAC_ADDRESS;
        this.AP_MAC_ADDRESS = AP_MAC_ADDRESS;
        this.packetNumber = packetNumber;
        this.logger = logger;
    }

    public void EncryptAndSendMessage(PrintWriter out, byte[] iv, byte[] packetNumber, String message) throws Exception{
        DataPacket respDataPacket = new DataPacket();

        byte[] respMIC = CCMPImpl.generateMIC(message.getBytes(),PTK.TK,iv);
        byte[] encryptedMsg = CCMPImpl.encrypt(message.getBytes(),PTK.TK,iv);

        byte [] encryptedMIC = CCMPImpl.encrypt(respMIC,PTK.TK,iv);

        String b64msg = Base64.getEncoder().encodeToString(encryptedMsg);
        String b64mic = Base64.getEncoder().encodeToString(encryptedMIC);

        respDataPacket.add(Base64.getEncoder().encodeToString(encryptedMsg));
        respDataPacket.add(ByteUtil.convertBytesToHex(packetNumber));
        respDataPacket.add(Base64.getEncoder().encodeToString(encryptedMIC));

        out.println(respDataPacket.getData());
    }

    public String receiveAndDecryptMessage(BufferedReader in, byte[] iv) throws Exception{
        String response = in.readLine();

        logger.warn("Received encrypted message: " + response);

        if(response == null || response.equals("terminate")){
            return null;
        }
        String[] respDataParts = DataPacket.parse(response);
        byte[] decodedMsg = Base64.getDecoder().decode(respDataParts[0]);
        byte[] decryptedMsg = CCMPImpl.decrypt(decodedMsg,PTK.TK,iv);
        byte[] respMIC = CCMPImpl.generateMIC(decryptedMsg,PTK.TK,iv);

        byte[] decodedMsgMIC = Base64.getDecoder().decode(respDataParts[respDataParts.length-1]);
        byte[] decryptedMIC = CCMPImpl.decrypt(decodedMsgMIC,PTK.TK,iv);

        logger.info("Decoding...");
        logger.info("Decrypting...");


        String packetNumber = respDataParts[1];

        if(!receivedPackets.contains(packetNumber)){
            receivedPackets.add(packetNumber);
        } else {
            throw new SecurityException("Possible replay attack. Packet number: " + packetNumber + "was previously encountered");
        }

        if(!CCMPImpl.validate(Base64.getEncoder().encodeToString(decryptedMIC), Base64.getEncoder().encodeToString(respMIC))){
            System.out.println("MIC: NOT VALID: " + Base64.getEncoder().encodeToString(respMIC) + " " + Base64.getEncoder().encodeToString(decryptedMIC));
        }

        logger.info("Message decrypted successfully! Receiving...");


        return new String(decryptedMsg, StandardCharsets.UTF_8);
    }

}
