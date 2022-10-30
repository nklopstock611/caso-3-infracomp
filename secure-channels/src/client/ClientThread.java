package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;

import server.SecurityFunctions;

public class ClientThread extends Thread {
    
    private Socket socket = null;

    private static BigInteger p;
	private static BigInteger g;
    private BigInteger x;
	private static BigInteger yInter;
    private static BigInteger yExter;
	private static BigInteger z;

    private static String serverFirm = "";

    public ClientThread(Socket pSocket) {
        this.socket = pSocket;
        this.x = getRandomBigInteger();
    }

    private BigInteger getRandomBigInteger() {
        SecureRandom r = new SecureRandom();
        int x = Math.abs(r.nextInt());
        
        Long longx = Long.valueOf(x);
        BigInteger bix = BigInteger.valueOf(longx);
        return bix;
    }

    public void diffieHellmanY(BigInteger xRand) {
        yInter = g.modPow(xRand, p);
	}

    private void diffieHellmanZ(BigInteger yNew, BigInteger xRand) {
        z = yNew.modPow(xRand, p);
	}

    /**
     * Function copied from ServerThread.
     * Transforms String into byte[].
     * 
     * @param ss
     * @return
     */
    public byte[] str2byte(String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length() / 2];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
		}
		return ret;
	}

    public void process(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        SecurityFunctions f = new SecurityFunctions();
        String dlg = "public key-client: ";
        PublicKey publicKey = f.read_kplus("lib/datos_asim_srv.pub", dlg);
                
        // 1. client sends "SECURE INIT"
        System.out.println("Escriba el mensaje para enviar: ");
        String fromUser = stdIn.readLine();
        pOut.println(fromUser);
        
        String fromServer = "";
        
        // 3. gets g, p, y and the signature from server

        // gets g:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            g = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer + ",";
            System.out.println("g: " + g);
        }

        // gets p:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            p = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer + ",";
            System.out.println("p: " + p);
        }

        // gets g2x aka yExter:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            yExter = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer;
            System.out.println("yExter: " + yExter);
        }

        // gets signature (authentication)
        if ((fromServer = pIn.readLine()) != null) {
            // System.out.println("Servidor: " + fromServer);
            String state = "ERROR";
            byte[] byte_authentication = str2byte(fromServer);
        // 4. verifies if the string "g,p,g2x" is the signature
            try {
                Boolean authentication = f.checkSignature(publicKey, byte_authentication, serverFirm);
                if (authentication) {
                    state = "OK";
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        // 5. sends "OK" or "ERROR"
            pOut.println(state);
        }

        diffieHellmanY(this.x);
        System.out.println("yInter: " + yInter);
        // 6. sends yInter
        pOut.println(yInter.toString());
        System.out.println("yInter sent...");

        // 7. generate z, symmetric key for encrypt, HMAC symmetric key
        //    and iv1
        diffieHellmanZ(yExter, this.x);
        System.out.println("z: " + z);

        // 8. send message with the generated keys and iv1

        // 10. get "OK" or "ERROR"

        // 11. gets decrypted message

        // 12. verifies the decrypted message

        // 13. sends "OK" or "ERROR"

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

            System.out.println("closing everything...");

            stdIn.close();
            writer.close();
            reader.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
