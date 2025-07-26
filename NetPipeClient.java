import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.SQLOutput;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    private static SessionKey sessionKey;
    private static byte[] ivbytes;
    private static HandshakeCertificate servercert;
    private static PrivateKey privateKey;
    private static HandshakeCertificate clientcert;
    private static CipherOutputStream cipherOut;
    private static CipherInputStream cipherIn;
    private static HandshakeMessage clientHello;
    private static HandshakeMessage sessionMessage;
    private static HandshakeCertificate cacert;
    private static HandshakeMessage serverHello;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<usercertificate>");
        System.err.println(indent + "--key=<privatekey>");
        System.err.println(indent + "--cacert=<CA certificate>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "usercertificate");
        arguments.setArgumentSpec("key", "privatekey");
        arguments.setArgumentSpec("cacert", "CA certificate");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }

        if(arguments.get("host") == null || arguments.get("port") == null || arguments.get("key")
                == null || arguments.get("usercert") == null || arguments.get("cacert") == null)
            usage();
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) {
        Socket socket = null;

        parseArgs(args);
        readPrivateKeyFromFile(arguments.get("key"));
        cacert = readCertificateFromFile(arguments.get("cacert"));
        clientcert = readCertificateFromFile(arguments.get("usercert"));
        try {
            clientcert.verify(cacert);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException |
                 NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }

        clientHello(socket);
        readServerHello(socket);
        sessionMessage(socket);
        clientFinished(socket);
        readServerFinished(socket);

        SessionCipher cipher = new SessionCipher(sessionKey, ivbytes);
        try {
            cipherIn = cipher.openDecryptedInputStream(socket.getInputStream());
            cipherOut = cipher.openEncryptedOutputStream(socket.getOutputStream());
            Forwarder.forwardStreams(System.in, System.out, cipherIn, cipherOut, socket);
            cipherIn.close();
            cipherOut.close();
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }

    private static void clientHello(Socket socket){
        try {
            clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
            String base64Cert = Base64.getEncoder().encodeToString(clientcert.getBytes());
            clientHello.putParameter("Certificate", base64Cert);
            clientHello.send(socket);
        } catch (CertificateEncodingException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void readServerHello(Socket socket){
        try {
            HandshakeMessage fromServer = HandshakeMessage.recv(socket);

            if(fromServer.getType().equals(HandshakeMessage.MessageType.SERVERHELLO)) {
                serverHello = fromServer;
                String base64Message = fromServer.getParameter("Certificate");
                if (base64Message == null) {
                    System.out.println("Missing Certificate");
                    System.exit(1);
                }
                base64Message = base64Message.replace("Certificate ", "");

                byte[] decodedBytes = Base64.getDecoder().decode(base64Message);
                servercert = new HandshakeCertificate(decodedBytes);
                servercert.verify(cacert);
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | SignatureException |
                 InvalidKeyException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private static void sessionMessage(Socket socket){
        try {
            sessionMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
            sessionKey = new SessionKey(128);
            ivbytes = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(ivbytes);
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto(servercert);
            byte[] encryptedIV = handshakeCrypto.encrypt(ivbytes);
            byte[] encryptedKey = handshakeCrypto.encrypt(sessionKey.getKeyBytes());
            String base64Key = Base64.getEncoder().encodeToString(encryptedKey);
            String base64IV = Base64.getEncoder().encodeToString(encryptedIV);
            sessionMessage.putParameter("SessionKey", base64Key);
            sessionMessage.putParameter("SessionIV", base64IV);
            sessionMessage.send(socket);
        } catch (IOException e) {
            System.out.println("Error sending session message");
            System.exit(1);
        }
    }

    private static void clientFinished(Socket socket){
        try {
            HandshakeMessage message = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);

            HandshakeDigest digest = new HandshakeDigest();
            digest.update(clientHello.getBytes());
            digest.update(sessionMessage.getBytes());
            byte[] messageDigest = digest.digest();
            HandshakeCrypto crypto = new HandshakeCrypto(privateKey.getEncoded());
            String base64SignedMessage = Base64.getEncoder().encodeToString(
                    crypto.encrypt(messageDigest));
            message.putParameter("Signature", base64SignedMessage);
            byte[] timestamp = getUTF8TimeStamp();
            String base64SignedTimeStamp = Base64.getEncoder().encodeToString(
                    crypto.encrypt(timestamp));
            message.putParameter("TimeStamp", base64SignedTimeStamp);
            message.send(socket);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static void readServerFinished(Socket socket){
        try {
            HandshakeMessage fromServer = HandshakeMessage.recv(socket);
            if(fromServer.getType().equals(HandshakeMessage.MessageType.SERVERFINISHED)) {
                HandshakeCrypto crypto = new HandshakeCrypto(servercert);

                String signature = fromServer.getParameter("Signature");
                if (signature == null) {
                    System.out.println("Signature missing");
                    System.exit(1);
                }
                HandshakeDigest digest = new HandshakeDigest();
                digest.update(serverHello.getBytes());
                if(!Arrays.equals(digest.digest(), crypto.decrypt(Base64.getDecoder().decode(signature)))){
                    System.out.println("Invalid Signature");
                    System.exit(1);
                }

                String timestamp = fromServer.getParameter("TimeStamp");
                if (timestamp == null) {
                    System.out.println("Timestamp missing");
                    System.exit(1);
                }
                byte[] serverTimeStamp = crypto.decrypt(Base64.getDecoder().decode(timestamp));
                long serverTime = parseTimeStamp(serverTimeStamp);
                long clientTime = parseTimeStamp(getUTF8TimeStamp());
                if (Math.abs(clientTime - serverTime) > 5000) {
                    System.out.println("Invalid Client Timestamp");
                    System.exit(1);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private static HandshakeCertificate readCertificateFromFile(String filepath) {
        try (InputStream inStream = new FileInputStream(filepath
        )) {
            return new HandshakeCertificate(inStream);
        } catch (FileNotFoundException e) {
            System.out.println("Certificate file not found");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("Error reading certificate from file");
            System.exit(1);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    private static void readPrivateKeyFromFile(String arg){
        try(InputStream inStream = new FileInputStream(arg)){
            byte[] keyBytes = inStream.readAllBytes();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] getUTF8TimeStamp(){
        LocalDateTime now = LocalDateTime.now();

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = now.format(formatter);

        return formattedDateTime.getBytes(StandardCharsets.UTF_8);
    }

    private static long parseTimeStamp(byte[] utf8Timestamp){
        String timestamp = new String(utf8Timestamp, StandardCharsets.UTF_8);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime time = LocalDateTime.parse(timestamp, formatter);
        return time.toEpochSecond(ZoneOffset.UTC);
    }
}
