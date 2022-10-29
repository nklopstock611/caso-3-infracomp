package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

public class ClientThread extends Thread {
    
    private Socket socket = null;

    private static BigInteger p;
	private static BigInteger g;
    private BigInteger x = getRandomBigInteger();
	private static BigInteger y;
	private static BigInteger z;

    public ClientThread(Socket pSocket) {
        this.socket = pSocket;
    }

    private BigInteger getRandomBigInteger() {
        SecureRandom r = new SecureRandom();
        int x = Math.abs(r.nextInt());
        
        Long longx = Long.valueOf(x);
        BigInteger bix = BigInteger.valueOf(longx);
        return bix;
    }

    public void diffieHellmanY(BigInteger xRand) {
        y = g.modPow(xRand, p);
	}

    private void diffieHellmanZ(BigInteger yNew, BigInteger xRand) {
        z = g.modPow(yNew, p);
	}

    public static void process(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        // reads the keyboard
        System.out.println("Escriba el mensaje para enviar: ");
        String fromUser = stdIn.readLine();
        pOut.println(fromUser);
        
        String fromSever = "";
        
        // reads the answer from the server

        // gets g:
        if ((fromSever = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            g = new BigInteger(fromSever);
            System.out.println("g: " + g);
        }
        // gets p:
        if ((fromSever = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            p = new BigInteger(fromSever);
            System.out.println("p: " + p);
        }
        // gets g2x: ¿?¿?¿?¿?
         if ((fromSever = pIn.readLine()) != null) {
             System.out.println("G^x: " + fromSever);
         }
    }

    public void run() {
        PrintWriter writer = null;
        BufferedReader reader = null;
        try {
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        try {
            process(stdIn, reader, writer);

            stdIn.close();
            writer.close();
            reader.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
