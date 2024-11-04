package server;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import util.ByteUtil;
import util.EncryptedNetworkContext;

import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
public class ClientHandler extends Thread {

    Socket socket;
    Logger logger;
    String CLIENT_MAC_ADDRESS = "3A9B5E1D4C3A";
    static String routerSSID = "TP-Link2024";
    public String MAC_ADDRESS = "5A7FAB12D49E";

    private final String ssid = "TP-Link2024";
    private final String password = "jonus123";
    private byte[] ANonce;


    byte[] packetNumber = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] SNonce;
    private PTKWrapper PTK;

    public ClientHandler(Socket socket, Logger logger) {
        this.socket = socket;
        this.logger = logger;
    }

    void terminate(PrintWriter out) throws IOException {
        //out.println("terminate");
        socket.close();
        logger.warn("Connection with: " + socket.getRemoteSocketAddress() + " closed");
    }

    byte[] connect(String password, String ssid, String clientMacAddress) throws NoSuchAlgorithmException, InvalidKeySpecException {


        return this.ANonce; // prva poraka vo 4 way handshake
    }


    @SneakyThrows
    @Override
    public void run() {

        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            Logger logger = LogManager.getLogger(ClientHandler.class.getName());
            String connData = null;
            try {
                connData = in.readLine();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }


            String[] dataParts = DataPacket.parse(connData);
            System.out.println(Arrays.toString(dataParts) + " PARTS");
            logger.warn("{} wants to connect", dataParts[0]);

            try {
                if (!this.password.equals(dataParts[2]) || !routerSSID.equals(dataParts[1])) {
                    System.out.println("Invalid credentials");
                    throw new IllegalArgumentException("Invalid credentials");
                }

                this.ANonce = CCMPImpl.generateNonce();
                CLIENT_MAC_ADDRESS = dataParts[0];

                DataPacket f1 = new DataPacket();
                String b64encodedANonce = Base64.getEncoder().encodeToString(ANonce);

                System.out.println("ANONCEEEEEE AP: " + ByteUtil.convertBytesToHex(ANonce));
                f1.add(b64encodedANonce);

                out.println(f1.getData());

                ///do tuka prva faza

                logger.info("Credentials are correct, commencing handshake");

                logger.info("First step of handshake: generate ANonce and send it to the client.");

                // vtora faza generiraj svoj mic, pmk, ptk i proveri dali sa sovpagjat tvojot mic so client mic

                String f2resp = in.readLine();

                System.out.println("f2 resp: " + f2resp);

                String[] f2dataParts = DataPacket.parse(f2resp);

                String clientMIC = f2dataParts[0];
                this.SNonce = Base64.getDecoder().decode(f2dataParts[1]);

                System.out.println("SNONCE " + Base64.getEncoder().encodeToString(this.SNonce));

                byte[] PMK = CCMPImpl.computeKey(password,routerSSID.getBytes(),256);

                System.out.println(Base64.getEncoder().encodeToString(PMK) + " ->>PMKKK");

                this.PTK = HandshakeUtil.derivePTK(PMK,ANonce,SNonce,CLIENT_MAC_ADDRESS,MAC_ADDRESS);

                String micGenMsg = Base64.getEncoder().encodeToString(SNonce) + Base64.getEncoder().encodeToString(ANonce)
                        + CLIENT_MAC_ADDRESS + MAC_ADDRESS;

                byte[] APMIC = CCMPImpl.generateHandshakeMic(PTK.KCK,micGenMsg.getBytes());

                System.out.println(Base64.getEncoder().encodeToString(APMIC));
                System.out.println(clientMIC);

                boolean match = CCMPImpl.validate(Base64.getEncoder().encodeToString(APMIC),clientMIC);

                if(!match){
                    logger.error("CLIENT AND AP MIC DO NOT MATCH");
                    terminate(out);
                    return;
                }


                ByteUtil.incrementBytes(packetNumber);

                DataPacket f3data = new DataPacket();

                f3data.add(Base64.getEncoder().encodeToString(APMIC));

                out.println(f3data.getData());
                // posledna faza

            } catch (Exception e) {
                logger.error("Server Connection failed");
                terminate(out);
            }

            for (int i = 0; i < 10; i++) {
                logger.info("*".repeat(i + 1));
            }
            logger.info("New client connected");
            logger.info("========== CONNECTION ESTABLISHED ==========");
            logger.info("*");
            logger.info("All messages sent and received through this channel are encrypted");

            out.println("Connected");

            EncryptedNetworkContext encryptedNetworkContext = new EncryptedNetworkContext(PTK,CLIENT_MAC_ADDRESS,MAC_ADDRESS,packetNumber);

            while (true) {
                ByteUtil.incrementBytes(packetNumber);

                byte[] iv = new byte[16];
                System.arraycopy(packetNumber, 0, iv, 0, 6);
                System.arraycopy(SNonce, 0, iv, 6, 10);


               String receivedMessage = encryptedNetworkContext.receiveAndDecryptMessage(in,iv);


                if (receivedMessage.equals("exit") || receivedMessage.equals("terminate")) {
                    terminate(out);
                    return;
                }
                System.out.println("Client: " + receivedMessage);

                String responseMsg = "Successfully Received Message from Address: "
                        + CLIENT_MAC_ADDRESS + " Packet Number: " + ByteUtil.convertBytesToHex(packetNumber);

                encryptedNetworkContext.EncryptAndSendMessage(out,iv,packetNumber,responseMsg);

            }


        } catch (Exception e) {
        }

    }

}