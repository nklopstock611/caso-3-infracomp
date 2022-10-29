package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.stream.Stream;

public class Client {

    private static BigInteger p;
	private static BigInteger g;
	private Integer pInt;
	private Integer gInt;
	private BigInteger y;
	private BigInteger z;

    private static int PUERTO = 4030;
    private static String SERVIDOR = "localhost";

    public BigInteger diffieHellmanY(BigInteger xRand) {
		// cálculo de y
		Integer xInt = xRand.intValue();
		int yInt = (int) Math.pow(this.gInt, xInt) % this.pInt;
		this.y = BigInteger.valueOf(yInt);
		return this.y;
	}

    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        // Lee del teclado
        System.out.println("Escriba el mensaje para enviar: ");
        String fromUser = stdIn.readLine();

        // sends to server
        pOut.println(fromUser);

        String fromSever = "";

        // reads the answer from the server
        // g:
        if ((fromSever = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            g = new BigInteger(fromSever);
            System.out.println("g: " + g);
        }
        // p:
        if ((fromSever = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            p = new BigInteger(fromSever);
            System.out.println("p: " + p);
        }
        // g2x: ¿?¿?¿?¿?
        // if ((fromSever = pIn.readLine()) != null) {
        //     System.out.println("Servidor: " + fromSever);
        // }
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
