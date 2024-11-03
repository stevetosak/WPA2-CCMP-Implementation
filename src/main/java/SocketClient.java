import util.ByteUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;

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
        String hostname = "localhost";
        int port = 5355;


        try (Socket socket = new Socket(hostname, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

            out.println(getMacAddress());

            System.out.print("Enter password: ");
            String userInput = consoleReader.readLine();
            out.println(userInput);
            String connResponse = in.readLine();

            if (connResponse.equals("terminate")) {
                System.out.println("Can't connect");
                return;
            }

            System.out.println("Connected to the server.");

            while (true) {
                userInput = consoleReader.readLine();
                if (userInput == null || userInput.isEmpty()) {
                    System.out.println("empty input, try again");
                }


                out.println(userInput);
                String response = in.readLine();
                if (response.equals("terminate")) return;
                System.out.println("Server response: " + response);

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
