import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import server.*;
import util.ByteUtil;
import server.EncryptedNetworkContext;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.security.SecureRandom;
import java.util.Base64;

public class SocketClient {

    public static String getMacAddress() {
        try {
            InetAddress ip = InetAddress.getLocalHost();
            NetworkInterface network = NetworkInterface.getByInetAddress(ip);

            byte[] macAddressBytes = network.getHardwareAddress();

            if (macAddressBytes != null) {
                System.out.println(ByteUtil.convertBytesToHex(macAddressBytes));
                return ByteUtil.convertBytesToHex(macAddressBytes);
            } else {
                System.out.println("MAC address not found.");
            }
        } catch (UnknownHostException | SocketException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void main(String[] args) {


        String MAC_ADDRESS;
        byte[] ANonce;
        byte[] SNonce;
        PTKWrapper PTK;
        String AP_MAC_ADDRESS = "5A7FAB12D49E";
        byte[] packetNumber = new byte[]{0x00,0x00,0x00,0x00,0x00,0x00};

        Logger logger = LogManager.getLogger(SocketClient.class.getName());
        String routerSSID = "TP-Link2024";
        String hostname = "localhost";
        int port = 5355;


        try (Socket socket = new Socket(hostname, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Enter password: ");
            String password = consoleReader.readLine();


            DataPacket f1data = new DataPacket();

            MAC_ADDRESS = getMacAddress();

            f1data.add(MAC_ADDRESS);
            f1data.add(routerSSID);
            f1data.add(password); // password

            // mu pustat poraka za konekcija

            out.println(f1data.getData());
            // ako e ok trebit da dobiet response ANonce

            logger.info("First Step of Handshake: CLIENT: Connect with login information");


            String f1response = in.readLine();

            if(f1response == null || f1response.equals("terminate")){
                logger.error("Incorrect password, closing connection");
                socket.close();
                System.exit(0);
            }


            ANonce = Base64.getDecoder().decode(DataPacket.parse(f1response)[0]);
            SNonce = CCMPImpl.generateNonce();


            // vtora faza generiraj pmk i ptk, pa generiraj mac

            byte[] PMK = CCMPImpl.computeKey(password,routerSSID.getBytes(),256);

            System.out.println(Base64.getEncoder().encodeToString(PMK) + " ->>PMKKK");

            logger.info("Second Step of Handshake[0] CLIENT: Calculate PMK");
            logger.info("Second Step of Handshake[1] CLIENT: Derive PTK from PMK");
            logger.info("Second Step of Handshake[2] CLIENT: Generate MIC using the PTK");
            logger.info("Second Step of Handshake[3] CLIENT: Send MIC and SNonce to AP");

            PTK = HandshakeUtil.derivePTK(PMK,ANonce,SNonce,MAC_ADDRESS,AP_MAC_ADDRESS);

            // mac

            String micGenMsg = Base64.getEncoder().encodeToString(SNonce) + Base64.getEncoder().encodeToString(ANonce)
                    + MAC_ADDRESS + AP_MAC_ADDRESS;

            byte[] clientMIC = CCMPImpl.generateHandshakeMic(PTK.KCK,micGenMsg.getBytes());

            ByteUtil.incrementBytes(packetNumber);

            DataPacket f2data = new DataPacket();
            f2data.add(Base64.getEncoder().encodeToString(clientMIC));
            f2data.add(Base64.getEncoder().encodeToString(SNonce));

            System.out.println("SNONCE CLIENT: " + Base64.getEncoder().encodeToString(SNonce));


            out.println(f2data.getData());

            String f3response = in.readLine();

            logger.info("Third Step of Handshake[0] CLIENT: Compare generated MIC with received MIC");


            String APMIC = DataPacket.parse(f3response)[0];

            boolean match = CCMPImpl.validate(Base64.getEncoder().encodeToString(clientMIC),APMIC);

            if(!match){
                logger.info("CLIENT AND AP MIC DO NOT MATCH");
                System.out.println("err");
                return;
            }


            String connResponse = in.readLine();

            if (connResponse.equals("terminate")) {
                System.out.println("Can't connect");
                return;
            }

            logger.info("Connected to the server.");

            String input;

            EncryptedNetworkContext encryptedNetworkContext = new EncryptedNetworkContext(PTK,MAC_ADDRESS,AP_MAC_ADDRESS,packetNumber,logger);

            SecureRandom r = new SecureRandom();

            while (!socket.isClosed()) {
                input = consoleReader.readLine();
                //input = messages[r.nextInt(messages.length)];
                if (input == null || input.isEmpty()) {
                    System.out.println("empty input, try again");
                    continue;
                }

                ByteUtil.incrementBytes(packetNumber);

                byte[] nonce = new byte[16];
                System.arraycopy(packetNumber, 0, nonce, 0, 6);
                System.arraycopy(MAC_ADDRESS.getBytes(),0,nonce,6,6);

                encryptedNetworkContext.encryptAndSendMessage(out,nonce,packetNumber,input);

                String receivedMessage = encryptedNetworkContext.receiveAndDecryptMessage(in,nonce);
                System.out.println("Server: " + receivedMessage);

                if (receivedMessage == null || receivedMessage.equals("terminate")){
                    return;
                }

                //Thread.sleep(1000);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



}
