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

    private static SecretKey K_AB1_2 = null;
    private static SecretKey K_AB2_2 = null;
    private static byte[] decryptedMessage = null;
    private static byte[] newHmacMessage = null;
    private static byte[] iv2 = null;

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

    private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}

    public void process(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        SecurityFunctions f = new SecurityFunctions();
        String dlg = "client side: ";
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
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        // 5. sends "OK" or "ERROR"
            pOut.println(state);

        }

        diffieHellmanY(this.x);

        // 6. sends yInter
        pOut.println(yInter.toString());

        // 7. generates z, symmetric key for encrypt, HMAC symmetric key
        //    and iv1
        diffieHellmanZ(yExter, this.x);

        try {
            K_AB1 = f.csk1(z.toString());
            K_AB2 = f.csk2(z.toString());
            byte[] iv1bytes = generateIvBytes();
            iv1 = new IvParameterSpec(iv1bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        
        // 8. sends encrypted message, hmac and iv1
        String message = "99";
        byte[] messageBytes = str2byte(message);

        try {
            byte[] encryptedMessage = f.senc(messageBytes, K_AB1, iv1, "encryption-client");
            System.out.println("b2s: " + byte2str(encryptedMessage));
            pOut.println(byte2str(encryptedMessage));

            byte[] hmacMessage = f.hmac(messageBytes, K_AB2);
            pOut.println(byte2str(hmacMessage));

            pOut.println(byte2str(iv1.getIV()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 10. get "OK" or "ERROR"
        if ((fromServer = pIn.readLine()) != null) {
            if (fromServer.equals("OK")) {
                System.out.println(dlg + "Message recieved.");
            } else {
                System.out.println(dlg + "Nothing recieved.");
            }
        }

        // 11. gets encrypted response message, hmac and iv2
        // String zStr = String.valueOf(z.toString());
        // zStr = zStr + "1";
        
        if ((fromServer = pIn.readLine()) != null) {
            byte[] newMessageBytes = str2byte(fromServer);
            try {
                //K_AB1_2 = f.csk1(zStr);
                decryptedMessage = f.sdec(newMessageBytes, K_AB1, iv1);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if ((fromServer = pIn.readLine()) != null) {
            byte[] newMessageBytes = str2byte(fromServer);
            try {
                //K_AB2_2 = f.csk2(zStr);
                newHmacMessage = f.hmac(newMessageBytes, K_AB2);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if ((fromServer = pIn.readLine()) != null) {
            try {
                iv2 = str2byte(fromServer);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // // 12. verifies the decrypted message
        // Integer messageInt = Integer.parseInt(message) + 1;
        // String messagePlusOne = messageInt.toString();
        // String decryptesMessageStr = byte2str(decryptedMessage);
        // String state = "ERROR";
        // if (decryptesMessageStr.equals(messagePlusOne)) {
        //     System.out.println("Success!");
        //     state = "OK";
        // }
        // else {
        //     System.out.println("Failure!");
        // }
        
        // // 13. sends "OK" or "ERROR"
        // pOut.print(state);

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
