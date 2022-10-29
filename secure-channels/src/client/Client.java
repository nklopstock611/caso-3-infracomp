package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Client {

    private static int PUERTO = 4030;
    private static String SERVIDOR = "localhost";

    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        // Lee del teclado
        System.out.println("Escriba el mensaje para enviar: ");
        String fromUser = stdIn.readLine();

        // Envía el mensaje al servidor
        pOut.println(fromUser);

        String fromSever = "";

        // Lee la respuesta del servidor
        // Si lo que llega del servidor no es null observe la asignación luego la condición
        if ((fromSever = pIn.readLine()) != null) {
            System.out.println("Servidor: " + fromSever);
        }
    }

    public static void main(String[] args) {
        Socket socket = null;
        PrintWriter escritor = null;
        BufferedReader lector = null;
        
        System.out.println("Cliente...");

        try {
            socket = new Socket(SERVIDOR, PUERTO);
            escritor = new PrintWriter(socket.getOutputStream(), true);
            lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        // Crea un flujo para leer lo que escribe el cliente por el teclado
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        // Se ejecuta el protocolo en el lado cliente
        try {
            procesar(stdIn, lector, escritor);
            // Se cierran los flujos y el socket
    
            stdIn.close();
            escritor.close();
            lector.close();
            socket.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
