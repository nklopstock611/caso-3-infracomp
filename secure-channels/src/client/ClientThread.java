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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import server.SecurityFunctions;

public class ClientThread extends Thread {
    
    private Socket socket = null;
    private Integer id;
    private String ccs;

    private static BigInteger p;
	private static BigInteger g;
    private BigInteger x;
	private static BigInteger yInter;
    private static BigInteger yExter;
	private static BigInteger z;

    private static String serverFirm = "";
    private static SecretKey K_AB1 = null;
    private static SecretKey K_AB2 = null;
    private static IvParameterSpec iv1 = null;

    private static byte[] decryptedMessage = null;
    private static byte[] newHmacMessage = null;
    private static IvParameterSpec iv2 = null;

    public ClientThread(Socket pSocket, Integer pId) {
        this.id = pId;
        ccs = new String("concurrent server " + this.id + ": ");
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

    public byte[] str2byte(String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length() / 2];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
		}
		return ret;
	}

    public String byte2str(byte[] b)
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char )b[i]) & 0x00ff);
			ret += (g.length() == 1 ? "0" : "") + g;
		}
		return ret;
	}

    private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}

    public void process(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        SecurityFunctions f = new SecurityFunctions();
        PublicKey publicKey = f.read_kplus("lib/datos_asim_srv.pub", ccs);
                
        // 1. client sends "SECURE INIT"
        System.out.println("Type SECURE INIT: ");
        String fromUser = stdIn.readLine();
        pOut.println(fromUser);
        
        String fromServer = "";
        
        // 3. gets g, p, y and the signature from server

        // gets g:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            g = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer + ",";
            //System.out.println("g: " + g);
        }

        // gets p:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            p = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer + ",";
            //System.out.println("p: " + p);
        }

        // gets g2x aka yExter:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println("Servidor: " + fromSever);
            yExter = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer;
            //System.out.println("yExter: " + yExter);
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
            // 5. sends "OK" or "ERROR"
                        pOut.println(state);
                    }
                    else {
            // 5. sends "OK" or "ERROR"
                        pOut.println(state);
                        return; // works as a STOP! for the thread
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
        }

        diffieHellmanY(this.x);

        // 6. sends yInter
        pOut.println(yInter.toString());

        // 7. generates z, symmetric key for encrypt, HMAC symmetric key
        //    and iv1
        diffieHellmanZ(yExter, this.x);

        byte[] iv1bytes = null;
        try {
            K_AB1 = f.csk1(z.toString());
            K_AB2 = f.csk2(z.toString());
            iv1bytes = generateIvBytes();
            iv1 = new IvParameterSpec(iv1bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        
        // 8. sends encrypted message, hmac and iv1
        Integer messageInt = 99;
        String str_messageInt = String.valueOf(messageInt);
        byte[] messageBytes = (str_messageInt).getBytes();

        try {
            byte[] encryptedMessage = f.senc(messageBytes, K_AB1, iv1, "encryption-client");
            System.out.println("b2s: " + byte2str(encryptedMessage));
            pOut.println(byte2str(encryptedMessage));

            byte[] hmacMessage = f.hmac(messageBytes, K_AB2);
            pOut.println(byte2str(hmacMessage));

            pOut.println(byte2str(iv1bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 10. get "OK" or "ERROR"
        if ((fromServer = pIn.readLine()) != null) {
            if (fromServer.equals("OK")) {
                System.out.println(ccs + "Message recieved.");
            } else {
                System.out.println(ccs + "Nothing recieved.");
                return; // works as a STOP! for the thread
            }
        }

        // 11. gets encrypted response message, hmac and iv2
        byte[] newMessageBytes = null;
        if ((fromServer = pIn.readLine()) != null) {
            newMessageBytes = str2byte(fromServer);
        }

        if ((fromServer = pIn.readLine()) != null) {
            byte[] newHmacMessageBytes = str2byte(fromServer);
            try {
                newHmacMessage = f.hmac(newHmacMessageBytes, K_AB2);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if ((fromServer = pIn.readLine()) != null) {
            byte[] iv2bytes = str2byte(fromServer);
            try {
                iv2 = new IvParameterSpec(iv2bytes);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // decrypts the response from the server
        try {
            decryptedMessage = f.sdec(newMessageBytes, K_AB1, iv2);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 12. verifies the decrypted message
        // must dcheck hmac before anything else!

        String decryptedMessageStr = new String(decryptedMessage, StandardCharsets.UTF_8);
        messageInt = messageInt + 1;
        String messagePlusOne = messageInt.toString();
        System.out.println("decrypted: " + decryptedMessageStr);
        System.out.println("plus one: " + messagePlusOne);
        String state = "ERROR";
        if (decryptedMessageStr.equals(messagePlusOne)) {
            System.out.println("Success!");
            state = "OK";
        // 13. sends "OK" or "ERROR"
            pOut.println(state);
        }
        else {
            System.out.println("Failure...");
            pOut.println(state);
            return; // works as a STOP! for the thread
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
