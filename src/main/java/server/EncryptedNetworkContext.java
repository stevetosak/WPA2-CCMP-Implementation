package server;

import org.apache.logging.log4j.Logger;
import util.ByteUtil;

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

    byte[] QoS = new byte[]{0x1};

    Logger logger;


    public EncryptedNetworkContext(PTKWrapper PTK, String CLIENT_MAC_ADDRESS, String AP_MAC_ADDRESS,byte[] packetNumber,Logger logger) {
        this.PTK = PTK;
        this.CLIENT_MAC_ADDRESS = CLIENT_MAC_ADDRESS;
        this.AP_MAC_ADDRESS = AP_MAC_ADDRESS;
        this.packetNumber = packetNumber;
        this.logger = logger;
    }

    public void encryptAndSendMessage(PrintWriter out, byte[] nonce, byte[] packetNumber, String message) throws Exception{
        System.arraycopy(QoS,0,nonce,12,1);

        byte[] respMIC = CCMPImpl.generateMIC(message.getBytes(),PTK.TK,nonce);

        DataPacket respDataPacket = new DataPacket();

        byte[] encryptedMsg = CCMPImpl.encrypt(message.getBytes(),PTK.TK,nonce);

        byte [] encryptedMIC = CCMPImpl.encrypt(respMIC,PTK.TK,nonce);

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

        System.arraycopy(QoS,0,iv,12,1);

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

        String b64mic1 = Base64.getEncoder().encodeToString(decryptedMIC);
        String b64mic2 = Base64.getEncoder().encodeToString(respMIC);

        if(!CCMPImpl.validate(b64mic1,b64mic2)){
            throw new SecurityException("MIC DO NOT MATCH: mic1: " + b64mic1 + " mic2: " + b64mic2);
        }

        logger.info("Success! MIC MATCH: mic1: " + b64mic1 + " mic2: " + b64mic2);

        logger.info("Message decrypted successfully! Receiving...");


        return new String(decryptedMsg, StandardCharsets.UTF_8);
    }

}
