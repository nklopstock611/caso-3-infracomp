package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Stream;

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
