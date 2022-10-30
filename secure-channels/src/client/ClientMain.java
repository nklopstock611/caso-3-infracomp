package client;

import java.io.IOException;
import java.net.Socket;

public class ClientMain {

    private static int PUERTO = 4030;
    private static String SERVIDOR = "localhost";
    private static Integer idThread = 0;

    public static void main(String[] args) {
        Socket socket = null;
        
        System.out.println("Cliente...");

        try {
            socket = new Socket(SERVIDOR, PUERTO);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        ClientThread client = new ClientThread(socket);
        idThread++;
        client.start();
    }
}
