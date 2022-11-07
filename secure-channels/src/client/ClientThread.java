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
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import server.SecurityFunctions;

public class ClientThread extends Thread {
    
    private Socket socket = null;
    private Integer id;
    private String ccs;

    private PrintWriter writer = null;
    private BufferedReader reader = null;
    private BufferedReader stdIn = null;

    private BigInteger p;
	private BigInteger g;
    private BigInteger x;
	private BigInteger yInter;
    private BigInteger yExter;
	private BigInteger z;

    private String serverFirm = "";
    private SecretKey K_AB1 = null;
    private SecretKey K_AB2 = null;
    private IvParameterSpec iv1 = null;

    private static byte[] decryptedMessage = null;
    private static IvParameterSpec iv2 = null;

    public ClientThread(Socket pSocket, Integer pId) {
        id = pId;
        ccs = new String("concurrent client " + id + ": ");
        this.socket = pSocket;
        this.x = getRandomBigInteger();
        try {
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        stdIn = new BufferedReader(new InputStreamReader(System.in));
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
        //System.out.println(ccs + "Type SECURE INIT: ");
        //String fromUser = stdIn.readLine();
        pOut.println("SECURE INIT");
        
        String fromServer = "";
        
        // 3. gets g, p, y and the signature from server

        // gets g:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println(ccs + "Servidor: " + fromSever);
            g = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer + ",";
            //System.out.println(ccs + "g: " + g);
        }

        // gets p:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println(ccs + "Servidor: " + fromSever);
            p = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer + ",";
            //System.out.println(ccs + "p: " + p);
        }

        // gets g2x aka yExter:
        if ((fromServer = pIn.readLine()) != null) {
            //System.out.println(ccs + "Servidor: " + fromSever);
            yExter = new BigInteger(fromServer);
            serverFirm = serverFirm + fromServer;
            //System.out.println(ccs + "yExter: " + yExter);
        }

        // gets signature (authentication)
        if ((fromServer = pIn.readLine()) != null) {
            // System.out.println(ccs + "Servidor: " + fromServer);
            String state = "ERROR";
            byte[] byte_authentication = str2byte(fromServer);
        // 4. verifies if the string "g,p,g2x" is the signature
            try {
                Boolean authentication = f.checkSignature(publicKey, byte_authentication, serverFirm);
                if (authentication) {
                    state = "OK";
        // 5. sends "OK" or "ERROR"
                    System.out.println(ccs + " ==========> Test 1. passed (correct signature)");
                    pOut.println(state);
                }
                else {
        // 5. sends "OK" or "ERROR"
                    System.out.println(ccs + " ==========> Test 1. failed (not the right signature)");
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
        Random rand = new Random();
        Integer messageInt = rand.nextInt((Integer.MAX_VALUE - 1) + 1);
        String str_messageInt = String.valueOf(messageInt);
        byte[] messageBytes = (str_messageInt).getBytes();

        try {
            byte[] encryptedMessage = f.senc(messageBytes, K_AB1, iv1, "encryption-client");
            //System.out.println(ccs + "b2s: " + byte2str(encryptedMessage));
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
                //System.out.println(ccs + "Message recieved.");
                System.out.println(ccs + " ==========> Test 2. passed (String OK recieved)");
            } else {
                //System.out.println(ccs + "Nothing recieved.");
                System.out.println(ccs + " ==========> Test 2. failed (String ERROR recieved)");
                return; // works as a STOP! for the thread
            }
        }

        // 11. gets encrypted response message, hmac and iv2
        byte[] newMessageBytes = null;
        if ((fromServer = pIn.readLine()) != null) {
            newMessageBytes = str2byte(fromServer);
        }

        byte[] newHmacMessageBytes = null;
        if ((fromServer = pIn.readLine()) != null) {
            newHmacMessageBytes = str2byte(fromServer);
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

        // validates hmac
        try {
            Boolean validHMAC = f.checkInt(decryptedMessage, K_AB2, newHmacMessageBytes);
            //System.out.println(ccs + "Integrity check: " + validHMAC);
            if (validHMAC == false) {
                System.out.println(ccs + " ==========> Test 3. failed (integrity failed)");
                pOut.println("ERROR");
                return;
            }
        } catch (Exception e1) {
            e1.printStackTrace();
        }

        // 12. verifies the decrypted message
        String decryptedMessageStr = new String(decryptedMessage, StandardCharsets.UTF_8);
        messageInt = messageInt + 1;
        String messagePlusOne = messageInt.toString();
        System.out.println(ccs + "original: " + str_messageInt);
        System.out.println(ccs + "decrypted: " + decryptedMessageStr);
        System.out.println(ccs + "plus one: " + messagePlusOne);
        String state = "ERROR";
        if (decryptedMessageStr.equals(messagePlusOne)) {
            //System.out.println(ccs + "Success!");
            System.out.println(ccs + " ==========> Test 4. success!");
            state = "OK";
        // 13. sends "OK" or "ERROR"
            pOut.println(state);
        }
        else {
            //System.out.println(ccs + "Failure...");
            System.out.println(ccs + " ==========> Test 4. failure...");
            pOut.println("ERROR");
            return; // works as a STOP! for the thread
        }        
    }

    public void run() {
        try {
            process(stdIn, reader, writer);

            System.out.println(ccs + "closing everything...");

            stdIn.close();
            writer.close();
            reader.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
