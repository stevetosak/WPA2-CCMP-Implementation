package server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Connection {
    Client client;
    WPA2Controller wpa2Controller;
    private final Logger logger = LogManager.getLogger(Connection.class.getName());

    public Connection(Client client, WPA2Controller wpa2Controller) {
        this.client = client;
        this.wpa2Controller = wpa2Controller;
    }


    void init(){
//        try {
//            for(int i = 0; i < 10; i++){
//                logger.info("*".repeat(i + 1));
//            }
//            logger.info("========== CONNECTION ESTABLISHED ==========");
//            logger.info("*");
//            logger.info("All messages sent and received through this channel are encrypted");
//            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
//
//            while (true){
//                server.BitwiseUtil.increment(client.packetNumber);
//                byte[] iv = new byte[16];
//                System.arraycopy(client.packetNumber,0,iv,0,6);
//                System.arraycopy(client.getSNonce(),0,iv,6,10);
//
//                System.out.println("Enter message: ");
//                String inputMsg = br.readLine();
//
//                if(inputMsg.equals("exit")) return;
//
//                server.ClearTextFrame msgFrame = new server.ClearTextFrame();
//                msgFrame.set("payload",inputMsg.getBytes(StandardCharsets.UTF_8));
//
//                server.EncryptedFrame encryptedFrame = server.CCMPImpl.encrypt(msgFrame,client.getPTK().TK,iv);
//                byte [] MIC = server.CCMPImpl.generateMIC(encryptedFrame,client.getPTK().TK,iv);
//
//                encryptedFrame.set("mic",MIC);
//
//                server.EncryptedFrame resp = wpa2Controller.recieve(encryptedFrame);
//                byte[] respMIC = resp.get("mic");
//
//                iv = client.getNewIV();
//
//                MIC = server.CCMPImpl.generateMIC(resp,client.getPTK().TK,iv);
//
//                if(server.CCMPImpl.validate(server.ByteToHexConverter.convert(MIC),server.ByteToHexConverter.convert(respMIC))){
//                    server.ClearTextFrame decrypted = server.CCMPImpl.decrypt(resp,client.getPTK().TK,iv);
//                    String decryptedMessage = new String(decrypted.get("payload"));
//                    logger.info("Decrypted Message Received from AP [CLIENT]: {}", decryptedMessage);
//
//                } else {
//                    logger.error("RESPONSE MIC DOES NOT MATCH!");
//                }
//
//            }
//
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

}
