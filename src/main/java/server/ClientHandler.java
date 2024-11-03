package server;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.ByteUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

@Slf4j
public class ClientHandler extends Thread {

    Socket socket;
    Logger logger;
    static String CLIENT_MAC_ADDRESS = "3A9B5E1D4C3A";
    static String routerSSID = "TP-Link2024";

    public ClientHandler(Socket socket, Logger logger) {
        this.socket = socket;
        this.logger = logger;
    }

//    public static void main(String[] args) throws Exception {
//
//        Logger logger = LogManager.getLogger(server.ClientHandler.class.getName());
//
//        // 4 WAY HANDSHAKE
//        server.WPA2Controller wpa2Controller = new server.WPA2Controller();
//        server.Client client = new server.Client(CLIENT_MAC_ADDRESS);
//
//        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
//
//        System.out.println("Password:");
//        String passw = reader.readLine();
//
//
//        server.Connection connection = client.establishConnection(passw, routerSSID, wpa2Controller);
//
//        if (connection != null) {
//            connection.init();
//        } else {
//            logger.error("server.Connection failed");
//        }
//
//    }

    void terminate(PrintWriter out) throws IOException {
        out.println("terminate");
        socket.close();
        logger.warn("Connection with: " + socket.getRemoteSocketAddress() + " closed");
    }


    @SneakyThrows
    @Override
    public void run() {

        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            Logger logger = LogManager.getLogger(ClientHandler.class.getName());

            String clientMacAddress = in.readLine();

            logger.warn("{} wants to connect", clientMacAddress);

            // 4 WAY HANDSHAKE
            WPA2Controller wpa2Controller = new WPA2Controller();
            Client client = new Client(clientMacAddress);
            //


            //out.println("Password:");
            String passw = null;
            try {
                passw = in.readLine();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            boolean connection = false;

            try {
               connection = client.establishConnection(passw, routerSSID, wpa2Controller);
            } catch (Exception e) {
                logger.error("Server Connection failed");
                terminate(out);
            }

            if (!connection) {
                terminate(out);
                return;
            }


            for (int i = 0; i < 10; i++) {
                logger.info("*".repeat(i + 1));
            }
            logger.info("New client connected");
            logger.info("========== CONNECTION ESTABLISHED ==========");
            logger.info("*");
            logger.info("All messages sent and received through this channel are encrypted");

            out.println("Connected");

            while (true) {
                ByteUtil.incrementBytes(client.packetNumber);
                byte[] iv = new byte[16];
                System.arraycopy(client.packetNumber, 0, iv, 0, 6);
                System.arraycopy(client.getSNonce(), 0, iv, 6, 10);
                String inputMsg = in.readLine();

                if (inputMsg.equals("exit" ) || inputMsg.equals("terminate")){
                    terminate(out);
                    return;
                }

                logger.info("Encrypting message: {}", inputMsg);

                ClearTextFrame msgFrame = new ClearTextFrame();
                msgFrame.set("payload", inputMsg.getBytes(StandardCharsets.UTF_8));

                EncryptedFrame encryptedFrame = CCMPImpl.encrypt(msgFrame, client.getPTK().TK, iv);
                byte[] MIC = CCMPImpl.generateMIC(encryptedFrame, client.getPTK().TK, iv);

                encryptedFrame.set("mic", MIC);

                EncryptedFrame resp = wpa2Controller.recieve(encryptedFrame);
                byte[] respMIC = resp.get("mic");

                iv = client.getNewIV();

                MIC = CCMPImpl.generateMIC(resp, client.getPTK().TK, iv);

                if (CCMPImpl.validate(ByteUtil.convertBytesToHex(MIC), ByteUtil.convertBytesToHex(respMIC))) {
                    ClearTextFrame decrypted = CCMPImpl.decrypt(resp, client.getPTK().TK, iv);
                    String decryptedMessage = new String(decrypted.get("payload"));
                    logger.info("Decrypted Message Received from AP [CLIENT]: {}", decryptedMessage);
                    out.println("Decrypted Message Received from AP [CLIENT]:" + decryptedMessage);

                } else {
                    logger.error("RESPONSE MIC DOES NOT MATCH!");
                }

            }


        } catch (Exception e) {

        }

    }
}