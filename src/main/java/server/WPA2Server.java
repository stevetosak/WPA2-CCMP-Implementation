package server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class WPA2Server {
    private static final int PORT = 5355;

    public static void main(String[] args) {
        Logger logger = LogManager.getLogger(WPA2Server.class.getName());

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            logger.info("Server is listening on port " + PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(socket, logger);
                clientHandler.start();
            }
        } catch (IOException e) {
            logger.error("Server error: {}", e.getMessage());
        }
    }
}
