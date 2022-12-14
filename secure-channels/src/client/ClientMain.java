package client;

import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;

public class ClientMain {

    private static int PUERTO = 4030;
    private static String SERVIDOR = "localhost";

    private static Integer N;
    private static Integer idThread = 0;

    public static void main(String[] args) {
        Socket socket = null;
        
        System.out.println("Client...");

        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the number of clients: ");
        N = sc.nextInt();
        sc.close();

        for (int i = 0; i < N; i++) {
            try {
                socket = new Socket(SERVIDOR, PUERTO);
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(-1);
            }
            ClientThread client = new ClientThread(socket, idThread);
            idThread++;
            client.start();
        }
    }
}
