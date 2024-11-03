package server;

import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.ByteUtil;

@Getter @Setter
public class Client{
    private String MAC_ADDRESS;
    private byte[] ANonce;
    private byte[] SNonce;
    private PTKWrapper PTK;
    private String AP_MAC_ADDRESS;
    byte[] packetNumber;

    private Logger logger = LogManager.getLogger(Client.class.getName());

    public Client(String macAddress){
        this.MAC_ADDRESS = macAddress;
        this.SNonce = CCMPImpl.generateNonce();
        this.packetNumber = new byte[]{0x00,0x00,0x00,0x00,0x00,0x00};
    }

    byte[] getNewIV(){
        ByteUtil.incrementBytes(packetNumber);
        byte[] iv = new byte[16];
        System.arraycopy(packetNumber, 0, iv, 0, 6);
        System.arraycopy(SNonce, 0, iv, 6, 10);

        return iv;
    }

   boolean establishConnection(String passw,String routerSSID,WPA2Controller wpa2Controller) throws Exception {

        //1
        byte[] ANonce = wpa2Controller.connect(passw,routerSSID,MAC_ADDRESS);

        //2
        this.ANonce = ANonce;
        this.AP_MAC_ADDRESS = wpa2Controller.MAC_ADDRESS;

        byte[] PMK = CCMPImpl.computeKey("jonus123","TP-Link2024".getBytes(),256);
        logger.info("Second Step of Handshake[0] CLIENT: Calculate PMK");
        logger.info("Second Step of Handshake[1] CLIENT: Derive PTK from PMK");
        logger.info("Second Step of Handshake[2] CLIENT: Generate MIC using the PTK");
        logger.info("Second Step of Handshake[3] CLIENT: Send MIC and SNonce to AP");


        this.PTK = HandshakeUtil.derivePTK(PMK,ANonce,SNonce,MAC_ADDRESS,AP_MAC_ADDRESS);
        String micGenMsg = ByteUtil.convertBytesToHex(SNonce)
                + ByteUtil.convertBytesToHex(ANonce)
                + MAC_ADDRESS + wpa2Controller.MAC_ADDRESS;


        byte[] clientMIC = CCMPImpl.generateMIC4Way(PTK.KCK,micGenMsg.getBytes());

        ByteUtil.incrementBytes(packetNumber);

        ClearTextFrame frame = new ClearTextFrame();

        frame.set("mic",clientMIC);
        frame.set("nonce", SNonce);

        //3
        byte[] ApMIC = wpa2Controller.handshake(frame);

        logger.info("Fourth Step of Handshake[0] AP (Access Point): Validate received MIC and establish connection");
        //4
       return CCMPImpl.validate(ByteUtil.convertBytesToHex(clientMIC), ByteUtil.convertBytesToHex(ApMIC));


   }

}
