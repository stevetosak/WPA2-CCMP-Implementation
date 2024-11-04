package util;

import server.CCMPImpl;
import server.DataPacket;
import server.PTKWrapper;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptedNetworkContext {

    PTKWrapper PTK;
    String CLIENT_MAC_ADDRESS;
    String AP_MAC_ADDRESS;
    byte[] packetNumber;
    public EncryptedNetworkContext(PTKWrapper PTK, String CLIENT_MAC_ADDRESS, String AP_MAC_ADDRESS,byte[] packetNumber) {
        this.PTK = PTK;
        this.CLIENT_MAC_ADDRESS = CLIENT_MAC_ADDRESS;
        this.AP_MAC_ADDRESS = AP_MAC_ADDRESS;
        this.packetNumber = packetNumber;
    }

    public void EncryptAndSendMessage(PrintWriter out, byte[] iv, byte[] packetNumber,String message) throws Exception{
        DataPacket respDataPacket = new DataPacket();

        byte[] respMIC = CCMPImpl.generateMIC(message.getBytes(),PTK.TK,iv);
        byte[] encryptedMsg = CCMPImpl.encrypt(message.getBytes(),PTK.TK,iv);

        respDataPacket.add(Base64.getEncoder().encodeToString(respMIC));
        respDataPacket.add(Base64.getEncoder().encodeToString(encryptedMsg));

        out.println(respDataPacket.getData());
    }

    public String receiveAndDecryptMessage(BufferedReader in, byte[] iv) throws Exception{
        String response = in.readLine();
        if(response == null || response.equals("terminate")){
            return null;
        }
        String[] respDataParts = DataPacket.parse(response);
        byte[] decodedMsg = Base64.getDecoder().decode(respDataParts[1]);
        byte[] decryptedMsg = CCMPImpl.decrypt(decodedMsg,PTK.TK,iv);
        byte[] respMIC = CCMPImpl.generateMIC(decryptedMsg,PTK.TK,iv);
        if(!CCMPImpl.validate(respDataParts[0], Base64.getEncoder().encodeToString(respMIC))){
            System.out.println("MIC: NOT VALID: " + Base64.getEncoder().encodeToString(respMIC) + " " + respDataParts[0]);
        }

        String decryptedText = new String(decryptedMsg, StandardCharsets.UTF_8);

        return decryptedText;
    }

}
