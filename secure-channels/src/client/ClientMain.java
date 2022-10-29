package client;

import java.io.IOException;
import java.net.Socket;

public class ClientMain {

    private static int PUERTO = 4030;
    private static String SERVIDOR = "localhost";

    public static void main(String[] args) {
        Socket socket = null;
        
        System.out.println("Cliente...");

        try {
            socket = new Socket(SERVIDOR, PUERTO);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        // Crea un flujo para leer lo que escribe el cliente por el teclado
        ClientThread client = new ClientThread(socket);
        client.start();
    }
}
