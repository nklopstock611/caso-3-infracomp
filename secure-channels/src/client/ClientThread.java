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
     * function copied from ServerThread.
     * transforms String into byte[].
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

    public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}

    public void process(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        SecurityFunctions f = new SecurityFunctions();
        String dlg = "public key - client: ";
        PublicKey publicKey = f.read_kplus("lib/datos_asim_srv.pub", dlg);
                
        // 1. client sends "SECURE INIT"
        System.out.println("Escriba el mensaje para enviar: ");
        String fromUser = stdIn.readLine();
        pOut.println(fromUser);
        
        String fromServer = "";
        
        // 2. gets g, p and y from server

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

        // gets firm (authentication)
        if ((fromServer = pIn.readLine()) != null) {
            // System.out.println("Servidor: " + fromServer);
            String state = "ERROR";
            byte[] byte_authentication = str2byte(fromServer);
            try { // checks if the string "g,p,g2x" is the signature
                if (f.checkSignature(publicKey, byte_authentication, serverFirm)) {
                    state = "OK";
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println(state);
            pOut.println(state);
        }

        diffieHellmanY(this.x);
        System.out.println("yInter: " + yInter);
        pOut.println(yInter.toString());
        System.out.println("yInter sent...");

        diffieHellmanZ(yExter, this.x);
        System.out.println("z: " + z);

        // generate symmetric key for to encrypt
        // generate HMAC symmetric key

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
